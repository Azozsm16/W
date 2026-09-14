"""The Event contract. This package depends on no other layer, by design."""

from ebabf.schema.enums import (
    Decision,
    EnforcementBlockedReason,
    EventSource,
    RiskLevel,
    VerdictType,
)
from ebabf.schema.event import (
    CONFIDENCE_SUSPICION_THRESHOLD,
    CONFIDENCE_VERDICT_THRESHOLD,
    CONTEXT_MODIFIER_MAX,
    PSEUDONYM_PATTERN,
    SCHEMA_VERSION,
    Event,
    derive_verdict_type,
)

__all__ = [
    "Decision",
    "EnforcementBlockedReason",
    "EventSource",
    "RiskLevel",
    "VerdictType",
    "Event",
    "SCHEMA_VERSION",
    "PSEUDONYM_PATTERN",
    "CONFIDENCE_VERDICT_THRESHOLD",
    "CONFIDENCE_SUSPICION_THRESHOLD",
    "CONTEXT_MODIFIER_MAX",
    "derive_verdict_type",
]
