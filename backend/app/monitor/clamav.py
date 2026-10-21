"""Client ClamAV (daemon clamd) : analyse par signatures des ransomwares connus.

Parle directement le protocole clamd (commande INSTREAM) : aucune dépendance externe,
et clamd n'a pas besoin de pouvoir lire le fichier (utile avec les droits/containers).

Connexion : socket Unix (`CLAMAV_SOCKET`, Linux/macOS) ou TCP (`CLAMAV_HOST` + `CLAMAV_PORT`,
seule option sous Windows). Si les deux sont définis, le TCP est utilisé sous Windows et
le socket Unix ailleurs.

Principe de robustesse : ClamAV est un renfort, jamais un point de défaillance. Aucune
méthode ne lève d'exception réseau ; une panne est renvoyée comme ScanResult.error.
"""

import logging
import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings, get_settings
from app.schemas import Alert

log = logging.getLogger(__name__)

CHUNK = 64 * 1024
TIMEOUT = 5.0
MAX_STREAM = 25 * 1024 * 1024  # limite par défaut de clamd (StreamMaxLength)
MAX_FILES_PER_ALERT = 25


@dataclass
class ScanResult:
    path: str
    infected: bool = False
    signature: str | None = None
    error: str | None = None  # "unavailable", "too_large", "unreadable", ou message clamd

    @property
    def scanned(self) -> bool:
        return self.error is None


class ClamAVClient:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    # ------------------------------------------------------------------ connexion
    @property
    def enabled(self) -> bool:
        return bool(self.settings.clamav_enabled)

    def _connect(self) -> socket.socket:
        s = self.settings
        use_unix = bool(s.clamav_socket) and hasattr(socket, "AF_UNIX") and not (
            sys.platform == "win32" and s.clamav_host
        )
        if use_unix:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect(s.clamav_socket)
            return sock
        if s.clamav_host:
            return socket.create_connection((s.clamav_host, s.clamav_port), timeout=TIMEOUT)
        raise OSError("ClamAV non configuré (CLAMAV_SOCKET ou CLAMAV_HOST)")

    @staticmethod
    def _read_reply(sock: socket.socket) -> str:
        buf = b""
        while not buf.endswith(b"\0") and not buf.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf.rstrip(b"\0\n").decode(errors="replace")

    def ping(self) -> bool:
        """True si clamd répond PONG."""
        if not self.enabled:
            return False
        try:
            with self._connect() as sock:
                sock.sendall(b"zPING\0")
                return self._read_reply(sock) == "PONG"
        except OSError:
            return False

    # ------------------------------------------------------------------ analyse
    @staticmethod
    def _parse(path: str, reply: str) -> ScanResult:
        # "stream: OK" | "stream: Win.Ransomware.X FOUND" | "... ERROR"
        body = reply.split(":", 1)[-1].strip()
        if body.endswith("FOUND"):
            return ScanResult(path, infected=True, signature=body[: -len("FOUND")].strip())
        if body == "OK":
            return ScanResult(path)
        return ScanResult(path, error=body or "empty reply")

    def scan_bytes(self, data: bytes, label: str = "stream") -> ScanResult:
        if not self.enabled:
            return ScanResult(label, error="unavailable")
        if len(data) > MAX_STREAM:
            return ScanResult(label, error="too_large")
        try:
            with self._connect() as sock:
                sock.sendall(b"zINSTREAM\0")
                for i in range(0, len(data), CHUNK):
                    part = data[i : i + CHUNK]
                    sock.sendall(struct.pack("!I", len(part)) + part)
                sock.sendall(struct.pack("!I", 0))  # fin du flux
                return self._parse(label, self._read_reply(sock))
        except OSError as e:
            log.debug("clamd injoignable : %s", e)
            return ScanResult(label, error="unavailable")

    def scan_file(self, path: str | Path) -> ScanResult:
        p = Path(path)
        try:
            size = p.stat().st_size
            if size > MAX_STREAM:
                return ScanResult(str(p), error="too_large")
            data = p.read_bytes()
        except OSError:
            return ScanResult(str(p), error="unreadable")
        res = self.scan_bytes(data, label=str(p))
        res.path = str(p)
        return res

    def scan_many(self, paths: list[str | Path]) -> list[ScanResult]:
        results: list[ScanResult] = []
        for p in paths:
            r = self.scan_file(p)
            results.append(r)
            if r.error == "unavailable":  # inutile d'insister fichier par fichier
                break
        return results

    def scan_alert(self, alert: Alert, limit: int = MAX_FILES_PER_ALERT) -> list[str]:
        """Scanne les fichiers créés pendant l'alerte (binaires déposés, notes de rançon).

        Retourne les détections au format "chemin: signature", à placer dans
        `alert.signals.clamav_detections`. Les fichiers chiffrés eux-mêmes ne sont pas
        scannés : ils n'ont plus de signature reconnaissable.
        """
        created = []
        for ev in alert.sample_events:
            if ev.event_type == "created" and ev.path not in created:
                created.append(ev.path)
        found = []
        for r in self.scan_many(created[:limit]):
            if r.infected:
                found.append(f"{r.path}: {r.signature}")
        return found