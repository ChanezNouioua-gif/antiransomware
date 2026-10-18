"""Actions de réponse, validation humaine et résultats d'exécution."""

from datetime import datetime

from pydantic import BaseModel, Field, model_validator

from app.schemas.alert import utcnow
from app.schemas.enums import DESTRUCTIVE_ACTIONS, ActionType


class ProposedAction(BaseModel):
    action: ActionType
    target: str | None = None  # PID, chemin du binaire, identifiant de snapshot...
    rationale: str
    destructive: bool = False
    requires_approval: bool = False

    @model_validator(mode="after")
    def enforce_policy(self) -> "ProposedAction":
        # La politique de sécurité ne dépend pas du LLM : toute action
        # destructrice exige une validation, quoi que l'agent ait écrit.
        if self.action in DESTRUCTIVE_ACTIONS:
            self.destructive = True
            self.requires_approval = True
        return self


class ApprovalDecision(BaseModel):
    approved: bool
    reviewer: str
    comment: str | None = None
    decided_at: datetime = Field(default_factory=utcnow)


class ActionResult(BaseModel):
    action: ActionType
    target: str | None = None
    success: bool
    dry_run: bool = True
    detail: str = ""
    executed_at: datetime = Field(default_factory=utcnow)
