"""Rapport d'incident final produit par l'agent de rapport."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.alert import utcnow
from app.schemas.enums import Severity, Verdict
from app.schemas.response import ActionResult


class TimelineEntry(BaseModel):
    timestamp: datetime
    description: str


class IncidentReport(BaseModel):
    incident_id: str
    generated_at: datetime = Field(default_factory=utcnow)
    title: str
    severity: Severity
    verdict: Verdict
    summary: str
    timeline: list[TimelineEntry] = Field(default_factory=list)
    affected_files_count: int = 0
    actions_taken: list[ActionResult] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
