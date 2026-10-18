"""Alerte produite par le monitor (niveau 1) et consommée par les agents (niveau 2).

Une attaque génère des milliers d'événements fichiers : le monitor les agrège
par processus et par fenêtre de temps pour produire UNE seule Alert.
"""

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field

from app.schemas.enums import ActionType, Severity


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProcessInfo(BaseModel):
    pid: int
    name: str | None = None
    exe: str | None = None
    cmdline: list[str] = Field(default_factory=list)
    username: str | None = None
    parent_pid: int | None = None


class FileEventRecord(BaseModel):
    """Un événement fichier brut (échantillon conservé dans l'alerte)."""

    timestamp: datetime
    event_type: str  # created | modified | moved | deleted
    path: str
    dest_path: str | None = None  # pour les renommages
    entropy: float | None = None


class DetectionSignals(BaseModel):
    """Indicateurs calculés par les détecteurs déterministes."""

    files_modified: int = 0
    files_renamed: int = 0
    files_deleted: int = 0
    distinct_extensions: int = 0
    new_extensions: list[str] = Field(default_factory=list)
    mean_entropy: float | None = Field(default=None, ge=0, le=8)
    entropy_delta: float | None = None  # entropie après - avant
    write_rate_per_sec: float = 0.0
    canary_triggered: bool = False
    baseline_mismatches: int = 0
    clamav_detections: list[str] = Field(default_factory=list)
    extension_mismatch_count: int = 0  # extension incohérente avec les magic bytes


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    created_at: datetime = Field(default_factory=utcnow)
    window_start: datetime
    window_end: datetime
    watched_path: str
    process: ProcessInfo | None = None  # None si le PID n'a pas pu être attribué
    signals: DetectionSignals
    severity_hint: Severity = Severity.MEDIUM
    triggered_rules: list[str] = Field(default_factory=list)
    sample_events: list[FileEventRecord] = Field(default_factory=list, max_length=50)
    reflex_action: ActionType | None = None  # ex. SUSPEND_PROCESS déjà appliqué
