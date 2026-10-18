"""État partagé du graphe LangGraph : un seul IncidentState traverse
triage -> investigation -> réponse -> rapport.

Chaque nœud lit ce dont il a besoin et ne renvoie QUE les clés qu'il modifie
(LangGraph fusionne le dictionnaire retourné dans l'état).
"""

import operator
from typing import Annotated, TypedDict

from app.schemas import (
    ActionResult,
    Alert,
    ApprovalDecision,
    AuditEntry,
    IncidentReport,
    IncidentStatus,
    InvestigationResult,
    ProposedAction,
    TriageResult,
)


class IncidentState(TypedDict, total=False):
    # --- Entrée (fournie au lancement du graphe) ---
    incident_id: str
    alert: Alert

    # --- Progression ---
    status: IncidentStatus

    # --- Sorties des nœuds ---
    triage: TriageResult
    investigation: InvestigationResult
    proposed_actions: list[ProposedAction]
    approval: ApprovalDecision  # renseigné après l'interrupt() (validation humaine)
    action_results: Annotated[list[ActionResult], operator.add]
    report: IncidentReport

    # --- Traçabilité (les nœuds ajoutent, ne remplacent jamais) ---
    audit_log: Annotated[list[AuditEntry], operator.add]
    error: str | None


def new_state(alert: Alert) -> IncidentState:
    """État initial d'un incident créé à partir d'une alerte du monitor."""
    return IncidentState(
        incident_id=alert.id,
        alert=alert,
        status=IncidentStatus.NEW,
        proposed_actions=[],
        action_results=[],
        audit_log=[AuditEntry(actor="monitor", event="alert_received", detail={"rules": alert.triggered_rules})],
        error=None,
    )
