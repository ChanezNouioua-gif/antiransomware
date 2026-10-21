"""Surveillance du système de fichiers (watchdog : inotify sous Linux,
ReadDirectoryChangesW sous Windows) -> événements -> agrégation -> Alert.

Le watcher tourne dans des threads. Pour le brancher à asyncio/FastAPI, passe un
`on_alert` qui fait `loop.call_soon_threadsafe(queue.put_nowait, alert)`.
"""

import fnmatch
import logging
import threading
from collections.abc import Callable
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from app.config import Settings
from app.monitor.aggregator import WindowAggregator
from app.monitor.canary import CanaryManager
from app.monitor.detectors import ObservedEvent, analyze_file
from app.schemas import Alert, FileEventRecord
from app.schemas.alert import utcnow

log = logging.getLogger(__name__)

EVAL_INTERVAL = 0.5  # secondes entre deux évaluations de fenêtre


class _Handler(FileSystemEventHandler):
    def __init__(self, watcher: "FileWatcher", root: Path):
        self.w = watcher
        self.root = root

    def _handle(self, event: FileSystemEvent, kind: str) -> None:
        if event.is_directory:
            return
        src = str(event.src_path)
        dest = str(event.dest_path) if kind == "moved" and event.dest_path else None
        self.w.ingest(self.root, kind, src, dest)

    def on_created(self, event): self._handle(event, "created")
    def on_modified(self, event): self._handle(event, "modified")
    def on_deleted(self, event): self._handle(event, "deleted")
    def on_moved(self, event): self._handle(event, "moved")


class FileWatcher:
    def __init__(
        self,
        settings: Settings,
        on_alert: Callable[[Alert], None],
        canary: CanaryManager | None = None,
    ):
        self.settings = settings
        self.on_alert = on_alert
        self.canary = canary
        self._lock = threading.Lock()
        self._aggs: dict[Path, WindowAggregator] = {}
        self._observer = Observer()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        for root in settings.watched_paths:
            root = Path(root).resolve()
            self._aggs[root] = WindowAggregator(settings, str(root))
            self._observer.schedule(_Handler(self, root), str(root), recursive=True)

    # -- ingestion (appelée depuis les threads watchdog)
    def _ignored(self, path: str) -> bool:
        name = Path(path).name
        return any(fnmatch.fnmatch(name, pat) for pat in self.settings.ignored_patterns)

    def ingest(self, root: Path, kind: str, src: str, dest: str | None = None) -> None:
        if self._ignored(src) or (dest and self._ignored(dest)):
            return
        target = dest or src
        entropy, mismatch = (None, False)
        if kind in ("created", "modified", "moved"):
            entropy, mismatch = analyze_file(target, self.settings.entropy_sample_bytes)
        record = FileEventRecord(
            timestamp=utcnow(), event_type=kind, path=src, dest_path=dest, entropy=entropy
        )
        is_canary = bool(self.canary and (self.canary.is_canary(src) or (dest and self.canary.is_canary(dest))))
        with self._lock:
            self._aggs[root].add(ObservedEvent(record, ext_mismatch=mismatch, is_canary=is_canary))

    # -- boucle d'évaluation
    def _loop(self) -> None:
        while not self._stop.wait(EVAL_INTERVAL):
            with self._lock:
                alerts = [a for agg in self._aggs.values() if (a := agg.evaluate())]
            for alert in alerts:
                try:
                    self.on_alert(alert)
                except Exception:  # un consommateur défaillant ne doit pas tuer la surveillance
                    log.exception("on_alert a échoué")

    def start(self) -> None:
        self._observer.start()
        self._thread = threading.Thread(target=self._loop, name="monitor-eval", daemon=True)
        self._thread.start()
        log.info("Surveillance démarrée : %s", ", ".join(map(str, self._aggs)))

    def stop(self) -> None:
        self._stop.set()
        self._observer.stop()
        self._observer.join(timeout=5)
        if self._thread:
            self._thread.join(timeout=5)
