"""Baseline d'intégrité : empreinte SHA-256 de chaque fichier surveillé, protégée par HMAC.

Chaque ligne de la base (chemin, empreinte, taille) est signée avec une clé secrète
(`BASELINE_HMAC_KEY`). Un attaquant qui réécrit la base sans connaître la clé produit
des lignes dont la signature ne correspond pas : elles sont détectées (TAMPERED).

Limites assumées :
  * la clé est lue dans l'environnement du processus : si l'attaquant la lit, la
    protection tombe (en production, la placer dans un coffre/HSM, hors de l'hôte) ;
  * supprimer toute la base n'est pas détectable ici : le monitor doit alerter si la
    base disparaît (voir `exists()`).

Usage :
    baseline = Baseline(settings)
    baseline.build()                       # photographie initiale des dossiers surveillés
    baseline.check("/data/a.txt")          # OK | MODIFIED | MISSING | UNKNOWN | TAMPERED
    baseline.check_many(paths)             # compteurs par statut -> signals.baseline_mismatches
    before, after = baseline.entropy_change("/data/a.txt")
"""

import fnmatch
import hashlib
import hmac
import logging
import sqlite3
import threading
from collections import Counter
from collections.abc import Iterable
from enum import Enum
from pathlib import Path

from app.config import Settings, get_settings
from app.monitor.detectors import shannon_entropy

log = logging.getLogger(__name__)

DEFAULT_KEY = "change-me"
CHUNK = 1 << 20


class BaselineStatus(str, Enum):
    OK = "ok"                # identique à la baseline
    MODIFIED = "modified"    # le contenu a changé depuis la baseline
    MISSING = "missing"      # présent dans la baseline mais plus sur le disque
    UNKNOWN = "unknown"      # fichier absent de la baseline (nouveau)
    TAMPERED = "tampered"    # la ligne de baseline elle-même a été falsifiée


# Statuts qui comptent comme « écart d'intégrité » dans DetectionSignals.baseline_mismatches
MISMATCH_STATUSES = frozenset({BaselineStatus.MODIFIED, BaselineStatus.MISSING, BaselineStatus.TAMPERED})


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


class Baseline:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        key = self.settings.baseline_hmac_key.get_secret_value()
        if key == DEFAULT_KEY:
            if self.settings.is_prod:
                raise RuntimeError("BASELINE_HMAC_KEY par défaut interdite en production.")
            log.warning("BASELINE_HMAC_KEY a la valeur par défaut : la baseline n'est pas réellement protégée.")
        self._key = key.encode()
        self._path = Path(self.settings.baseline_db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self._path, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS files ("
            "path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL, "
            "entropy REAL, mac TEXT NOT NULL)"
        )
        self._db.commit()

    # ------------------------------------------------------------------ signature
    def _mac(self, path: str, digest: str, size: int) -> str:
        msg = f"{path}\x00{digest}\x00{size}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    @staticmethod
    def _norm(path: str | Path) -> str:
        return str(Path(path).resolve())

    def exists(self) -> bool:
        """False si le fichier de base a été supprimé : à traiter comme une alerte."""
        return self._path.is_file()

    # ------------------------------------------------------------------ construction
    def _ignored(self, p: Path) -> bool:
        if any(fnmatch.fnmatch(p.name, pat) for pat in self.settings.ignored_patterns):
            return True
        try:
            return p.resolve().is_relative_to(Path(self.settings.canary_dir).resolve())
        except OSError:
            return False

    def _record(self, p: Path) -> tuple[str, str, int, float | None] | None:
        try:
            with p.open("rb") as f:
                sample = f.read(self.settings.entropy_sample_bytes)
            digest, size = sha256_file(p), p.stat().st_size
        except OSError:  # verrouillé, supprimé pendant le scan...
            return None
        entropy = shannon_entropy(sample) if len(sample) >= 512 else None
        return self._norm(p), digest, size, entropy

    def update_file(self, path: str | Path) -> bool:
        """Enregistre (ou accepte) l'état actuel d'un fichier : à appeler après une modification légitime."""
        p = Path(path)
        rec = self._record(p)
        if rec is None:
            return False
        norm, digest, size, entropy = rec
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO files(path, sha256, size, entropy, mac) VALUES (?,?,?,?,?)",
                (norm, digest, size, entropy, self._mac(norm, digest, size)),
            )
            self._db.commit()
        return True

    def build(self, roots: Iterable[Path] | None = None) -> int:
        """Photographie initiale : hash de tous les fichiers sous les dossiers surveillés."""
        count = 0
        for root in roots or self.settings.watched_paths:
            for p in Path(root).resolve().rglob("*"):
                if p.is_file() and not p.is_symlink() and not self._ignored(p) and self.update_file(p):
                    count += 1
        log.info("Baseline construite : %d fichiers", count)
        return count

    # ------------------------------------------------------------------ vérification
    def _row(self, norm: str):
        with self._lock:
            return self._db.execute(
                "SELECT sha256, size, entropy, mac FROM files WHERE path = ?", (norm,)
            ).fetchone()

    def check(self, path: str | Path) -> BaselineStatus:
        norm = self._norm(path)
        row = self._row(norm)
        if row is None:
            return BaselineStatus.UNKNOWN
        digest, size, _entropy, mac = row
        if not hmac.compare_digest(mac, self._mac(norm, digest, size)):
            return BaselineStatus.TAMPERED
        p = Path(norm)
        if not p.is_file():
            return BaselineStatus.MISSING
        try:
            if p.stat().st_size == size and sha256_file(p) == digest:
                return BaselineStatus.OK
        except OSError:
            return BaselineStatus.MISSING
        return BaselineStatus.MODIFIED

    def check_many(self, paths: Iterable[str | Path]) -> Counter:
        """Compte les statuts ; `sum(c[s] for s in MISMATCH_STATUSES)` = baseline_mismatches."""
        return Counter(self.check(p) for p in paths)

    @staticmethod
    def mismatch_count(counts: Counter) -> int:
        return sum(counts[s] for s in MISMATCH_STATUSES)

    def entropy_change(self, path: str | Path) -> tuple[float | None, float | None]:
        """(entropie enregistrée, entropie actuelle) : un bond vers ~8 = fichier chiffré."""
        norm = self._norm(path)
        row = self._row(norm)
        before = row[2] if row else None
        try:
            with open(norm, "rb") as f:
                sample = f.read(self.settings.entropy_sample_bytes)
            after = shannon_entropy(sample) if len(sample) >= 512 else None
        except OSError:
            after = None
        return before, after

    def close(self) -> None:
        with self._lock:
            self._db.close()