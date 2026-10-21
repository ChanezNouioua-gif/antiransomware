"""Détecteurs déterministes (niveau 1) : fonctions pures, testables sans LLM.

Principe : on ne juge pas un fichier isolé mais une *fenêtre* d'événements.
Les règles sont volontairement sensibles : l'agent de triage (niveau 2) est là
pour écarter les faux positifs restants (renommage en masse légitime, etc.).
"""

import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings
from app.schemas import DetectionSignals, FileEventRecord, Severity

# Formats dont une entropie élevée est NORMALE (déjà compressés/chiffrés par nature).
HIGH_ENTROPY_EXT = {
    ".zip", ".gz", ".7z", ".rar", ".bz2", ".xz", ".zst", ".tgz",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".mp4", ".mkv", ".avi", ".mov",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".apk", ".jar", ".whl",
}
TEXT_EXT = {".txt", ".csv", ".md", ".json", ".xml", ".html", ".py", ".js", ".log", ".ini", ".yml", ".yaml"}
MAGIC = {
    ".pdf": b"%PDF", ".png": b"\x89PNG", ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff",
    ".gif": b"GIF8", ".zip": b"PK", ".docx": b"PK", ".xlsx": b"PK", ".pptx": b"PK",
}
MIN_ENTROPY_BYTES = 512  # en dessous, l'entropie mesurée n'est pas significative
MIN_ENTROPY_SAMPLES = 5  # nombre minimal de fichiers échantillonnés pour juger l'entropie

VOLUME_RULES = {"mass_modification", "write_rate", "mass_rename"}
CONTENT_RULES = {"high_entropy", "extension_change", "extension_mismatch"}


@dataclass
class ObservedEvent:
    record: FileEventRecord
    ext_mismatch: bool = False
    is_canary: bool = False


# --------------------------------------------------------------------------- fichiers
def shannon_entropy(data: bytes) -> float:
    """Entropie de Shannon en bits/octet (0 = uniforme constant, 8 = aléatoire parfait)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def read_sample(path: str | Path, n: int) -> bytes | None:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:  # fichier supprimé entre l'événement et la lecture, verrouillé...
        return None


def analyze_file(path: str | Path, sample_bytes: int) -> tuple[float | None, bool]:
    """Retourne (entropie, incohérence extension/contenu). (None, False) si non mesurable."""
    data = read_sample(path, sample_bytes)
    if data is None or len(data) < MIN_ENTROPY_BYTES:
        return None, False
    entropy = shannon_entropy(data)
    ext = Path(path).suffix.lower()
    if ext in MAGIC:
        mismatch = not data.startswith(MAGIC[ext])
    elif ext in TEXT_EXT:
        mismatch = entropy > 7.0  # un « .txt » qui ressemble à du bruit aléatoire
    else:
        mismatch = False
    return entropy, mismatch


# --------------------------------------------------------------------------- fenêtre
def _strip_suffix(p: str) -> str:
    return str(Path(p).with_suffix(""))


def evaluate_window(
    events: list[ObservedEvent], settings: Settings
) -> tuple[DetectionSignals, list[str]]:
    """Calcule les indicateurs d'une fenêtre d'événements et les règles déclenchées."""
    modified: set[str] = set()
    deleted: set[str] = set()
    created: set[str] = set()
    moves: list[tuple[str, str]] = []
    entropies: list[float] = []
    mismatches = 0
    canary_hit = False

    for ev in events:
        r = ev.record
        if ev.is_canary and r.event_type != "created":
            canary_hit = True
        if r.event_type in ("created", "modified"):
            modified.add(r.path)
            if r.event_type == "created":
                created.add(r.path)
        elif r.event_type == "deleted":
            deleted.add(r.path)
        elif r.event_type == "moved" and r.dest_path:
            moves.append((r.path, r.dest_path))
            modified.add(r.dest_path)
        target = r.dest_path or r.path
        if r.entropy is not None and Path(target).suffix.lower() not in HIGH_ENTROPY_EXT:
            entropies.append(r.entropy)
        mismatches += int(ev.ext_mismatch)

    # « Remplacements » : fichier original supprimé + fichier créé portant une extension en plus
    # (ex. a.txt supprimé, a.txt.locked créé) ou renommage a.txt -> a.txt.locked.
    appended = Counter()
    pairs = 0
    for c in created:
        if _strip_suffix(c) in deleted:
            pairs += 1
            appended[Path(c).suffix.lower()] += 1
    for src, dst in moves:
        if dst != src and dst.startswith(src):
            appended[Path(dst).suffix.lower()] += 1
    new_exts = sorted(e for e, n in appended.items() if n >= 3 and e)

    times = [ev.record.timestamp for ev in events]
    span = max((max(times) - min(times)).total_seconds(), 1.0) if times else 1.0
    all_exts = {Path(p).suffix.lower() for p in modified}

    signals = DetectionSignals(
        files_modified=len(modified),
        files_renamed=len(moves) + pairs,
        files_deleted=len(deleted),
        distinct_extensions=len(all_exts),
        new_extensions=new_exts,
        mean_entropy=(sum(entropies) / len(entropies)) if entropies else None,
        write_rate_per_sec=len(modified) / span,
        canary_triggered=canary_hit,
        extension_mismatch_count=mismatches,
    )

    rules: list[str] = []
    if signals.files_modified >= settings.min_files_modified:
        rules.append("mass_modification")
    if signals.files_modified >= 5 and signals.write_rate_per_sec >= settings.write_rate_threshold:
        rules.append("write_rate")
    if (
        len(entropies) >= MIN_ENTROPY_SAMPLES
        and signals.mean_entropy is not None
        and signals.mean_entropy >= settings.entropy_threshold
    ):
        rules.append("high_entropy")
    if signals.files_renamed >= settings.min_rename_count:
        rules.append("mass_rename")
    if new_exts:
        rules.append("extension_change")
    if mismatches >= 5:
        rules.append("extension_mismatch")
    if canary_hit:
        rules.append("canary_touched")
    return signals, rules


def should_alert(rules: list[str]) -> bool:
    """Un canari touché suffit. Sinon il faut du VOLUME *et* un indice de CONTENU suspect."""
    r = set(rules)
    return "canary_touched" in r or (bool(r & VOLUME_RULES) and bool(r & CONTENT_RULES))


def severity_for(rules: list[str]) -> Severity:
    r = set(rules)
    strong = {"high_entropy", "extension_change"} <= r
    if "canary_touched" in r and "high_entropy" in r:
        return Severity.CRITICAL
    if strong and (r & VOLUME_RULES):
        return Severity.CRITICAL
    if "canary_touched" in r or (r & VOLUME_RULES and r & CONTENT_RULES):
        return Severity.HIGH
    return Severity.MEDIUM
