"""Agrégation par fenêtre glissante + déduplication.

Une attaque produit des milliers d'événements : on n'émet qu'UNE Alert par burst
(délai de « cooldown » ensuite), sinon on lancerait des centaines de graphes d'agents.
"""

import time
from collections import deque

from app.config import Settings
from app.monitor.detectors import ObservedEvent, evaluate_window, severity_for, should_alert
from app.schemas import Alert


class WindowAggregator:
    def __init__(self, settings: Settings, watched_path: str):
        self.settings = settings
        self.watched_path = watched_path
        self._events: deque[tuple[float, ObservedEvent]] = deque()
        self._cooldown_until = 0.0

    def add(self, ev: ObservedEvent, now: float | None = None) -> None:
        self._events.append((now if now is not None else time.monotonic(), ev))

    def _prune(self, now: float) -> None:
        limit = now - self.settings.window_seconds
        while self._events and self._events[0][0] < limit:
            self._events.popleft()

    def evaluate(self, now: float | None = None) -> Alert | None:
        now = now if now is not None else time.monotonic()
        self._prune(now)
        if not self._events or now < self._cooldown_until:
            return None
        window = [ev for _, ev in self._events]
        signals, rules = evaluate_window(window, self.settings)
        if not should_alert(rules):
            return None
        # Un burst = une alerte : on vide la fenêtre et on observe un délai de calme.
        self._events.clear()
        self._cooldown_until = now + self.settings.dedup_cooldown_seconds
        records = [ev.record for ev in window]
        return Alert(
            window_start=min(r.timestamp for r in records),
            window_end=max(r.timestamp for r in records),
            watched_path=self.watched_path,
            signals=signals,
            severity_hint=severity_for(rules),
            triggered_rules=rules,
            sample_events=records[-50:],
        )
