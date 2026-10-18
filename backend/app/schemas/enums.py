"""Énumérations partagées par le monitor, les agents et l'API."""

from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    """Conclusion d'un agent sur la nature de l'activité observée."""

    RANSOMWARE = "ransomware"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class IncidentStatus(str, Enum):
    NEW = "new"
    TRIAGE = "triage"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    RESPONDING = "responding"
    REPORTING = "reporting"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    FAILED = "failed"


class ActionType(str, Enum):
    SUSPEND_PROCESS = "suspend_process"
    RESUME_PROCESS = "resume_process"
    KILL_PROCESS = "kill_process"
    QUARANTINE_BINARY = "quarantine_binary"
    ISOLATE_HOST = "isolate_host"
    RESTORE_FROM_SNAPSHOT = "restore_from_snapshot"
    NO_ACTION = "no_action"


# Actions irréversibles ou à fort impact : jamais exécutées sans validation.
DESTRUCTIVE_ACTIONS: frozenset[ActionType] = frozenset(
    {
        ActionType.KILL_PROCESS,
        ActionType.QUARANTINE_BINARY,
        ActionType.ISOLATE_HOST,
        ActionType.RESTORE_FROM_SNAPSHOT,
    }
)
