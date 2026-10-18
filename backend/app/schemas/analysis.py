"""Sorties structurées des agents de triage et d'investigation."""

from pydantic import BaseModel, Field

from app.schemas.enums import Severity, Verdict


class TriageResult(BaseModel):
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    severity: Severity
    reasoning: str
    needs_investigation: bool = True


class Finding(BaseModel):
    """Une observation issue d'un outil d'investigation."""

    tool: str
    summary: str
    evidence: dict = Field(default_factory=dict)


class InvestigationResult(BaseModel):
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    findings: list[Finding] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)  # ex. T1486, T1490
    summary: str
