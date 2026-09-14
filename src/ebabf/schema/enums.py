"""Enumerations used by the Event contract.

Every value here is fixed by the specification. Adding a value is a schema
change and requires bumping SCHEMA_VERSION in `ebabf.schema.event`.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "EventSource",
    "VerdictType",
    "RiskLevel",
    "Decision",
    "EnforcementBlockedReason",
]


class EventSource(StrEnum):
    """Which collector produced the observation (spec 14.1)."""

    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    USER = "user"
    INVENTORY = "inventory"


class VerdictType(StrEnum):
    """Strength of the evidence behind a judgement (spec 9).

    This is never stored. It is derived from `confidence` so the two can
    never disagree - see `Event.verdict_type`.
    """

    VERDICT = "verdict"  # confidence >= 0.85
    SUSPICION = "suspicion"  # 0.5 <= confidence < 0.85
    UNVERIFIED = "unverified"  # confidence < 0.5


class RiskLevel(StrEnum):
    """Risk band derived from the final score (spec 8)."""

    NORMAL = "normal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(StrEnum):
    """The twelve cells of the decision matrix (spec 8.1), de-duplicated.

    Matrix 8.1 is authoritative wherever it disagrees with the table in
    spec 8 - see docs/decisions.md, decision D-003.
    """

    # Pure logging outcomes. Nothing is enforced and nobody is paged.
    LOG = "log"
    WATCHLIST = "watchlist"
    LOG_FOR_REVIEW = "log_for_review"

    # Notification outcomes. Handled by the presentation layer, not by
    # the enforcement engine - an alert does not change how the host behaves.
    ALERT = "alert"
    ALERT_UNVERIFIED = "alert_unverified"
    ALERT_AND_CONFIRM = "alert_and_confirm"
    URGENT_ALERT_AND_CONFIRM = "urgent_alert_and_confirm"

    # Outcomes that act on the host. These are the enforcement engine's job.
    ALERT_AND_RATE_LIMIT = "alert_and_rate_limit"
    SUSPEND = "suspend"
    SUSPEND_AND_CONFIRM = "suspend_and_confirm"
    BLOCK_AND_ISOLATE = "block_and_isolate"

    @property
    def requires_enforcement(self) -> bool:
        """Whether this decision asks the enforcement engine to act.

        WATCHLIST is deliberately False: it is a marker attached to a logged
        event, not an action (docs/decisions.md, D-002).
        """
        return self in _ENFORCEABLE_DECISIONS


_ENFORCEABLE_DECISIONS: frozenset[Decision] = frozenset(
    {
        Decision.ALERT_AND_RATE_LIMIT,
        Decision.SUSPEND,
        Decision.SUSPEND_AND_CONFIRM,
        Decision.BLOCK_AND_ISOLATE,
    }
)


class EnforcementBlockedReason(StrEnum):
    """Why enforcement did not happen for an event that asked for it.

    `enforced` alone cannot distinguish "nothing to do" from "we were
    switched off", and Training Mode reporting (spec 17.1) needs that
    distinction to be honest about what it would have blocked.
    """

    KILL_SWITCH_ACTIVE = "kill_switch_active"
    # Spec 4: "Training Mode = enforcement OFF". Training Mode is not a
    # separate reason, it is this one.
    ENFORCEMENT_DISABLED = "enforcement_disabled"
    NO_ACTION_REQUIRED = "no_action_required"
    FAIL_OPEN = "fail_open"  # internal fault, spec 11.3
    NOT_SUPPORTED = "not_supported"  # no enforcer implements this action yet
