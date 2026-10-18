"""Entrées d'audit et vue résumée d'un incident (utilisée par l'API)."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.alert import utcnow
from app.schemas.enums import IncidentStatus, Severity, Verdict


class AuditEntry(BaseModel):
    """Journal d'audit : qui a fait quoi, quand (agent, monitor, humain)."""

    timestamp: datetime = Field(default_factory=utcnow)
    actor: str  # "monitor" | "triage" | "investigator" | "responder" | "reporter" | "human:<nom>"
    event: str
    detail: dict = Field(default_factory=dict)


class IncidentSummary(BaseModel):
    incident_id: str
    created_at: datetime
    status: IncidentStatus
    severity: Severity | None = None
    verdict: Verdict | None = None
    process_name: str | None = None
    watched_path: str
