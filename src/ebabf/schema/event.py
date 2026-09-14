"""The Event contract - spec 14.1.

Every layer reads and writes this object. Changing it breaks everything
downstream, which is why it is defined before any layer that uses it.

Three properties of this type are load-bearing:

1. It is frozen. An event is an audit record; a record that can be edited
   after the fact is not evidence. Layers enrich an event with
   `dataclasses.replace`, which yields a new object and leaves the original
   intact - that is what makes `raw_score` vs `final_score` auditable.
2. Unevaluated scoring fields are None, never 0.0. Zero means "safe", and
   saying "safe" about something nobody scored is a lie. This is spec 6.3's
   missing-layer rule applied to the schema itself.
3. `subject_pseudonym` is format-checked, so the schema is structurally
   incapable of carrying a real identity - not merely discouraged from it.
"""

from __future__ import annotations

import re
from dataclasses import FrozenInstanceError, dataclass, field, replace
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping

from ebabf.schema.enums import (
    Decision,
    EnforcementBlockedReason,
    EventSource,
    RiskLevel,
    VerdictType,
)

__all__ = [
    "SCHEMA_VERSION",
    "Event",
    "PSEUDONYM_PATTERN",
    "CONFIDENCE_VERDICT_THRESHOLD",
    "CONFIDENCE_SUSPICION_THRESHOLD",
    "CONTEXT_MODIFIER_MAX",
    "derive_verdict_type",
]

SCHEMA_VERSION = "1.0.0"

# USR- plus a uuid4 hex. The pseudonym carries no information about the
# subject: it is minted at random and stored in identity.db (D-001).
PSEUDONYM_PATTERN = re.compile(r"^USR-[0-9a-f]{32}$")

# Spec 9 / 6.1. An automated action needs confidence >= 0.85.
CONFIDENCE_VERDICT_THRESHOLD = 0.85
CONFIDENCE_SUSPICION_THRESHOLD = 0.5

# The schema bounds what is impossible; config bounds what is sensible.
# Spec 6.4's 0.3-1.4 are calibration values, not laws of nature, so pinning
# them here would force a migration at the first re-calibration (13.2).
# A modifier of 0 would erase the score entirely, so the range is open at 0.
CONTEXT_MODIFIER_MAX = 2.0


def derive_verdict_type(confidence: float | None) -> VerdictType | None:
    """Map a confidence value onto the bands in spec 9.

    Returns None when confidence is None: no judgement was made at all,
    which is not the same claim as `unverified` ("we judged, and the
    evidence was weak").
    """
    if confidence is None:
        return None
    if confidence >= CONFIDENCE_VERDICT_THRESHOLD:
        return VerdictType.VERDICT
    if confidence >= CONFIDENCE_SUSPICION_THRESHOLD:
        return VerdictType.SUSPICION
    return VerdictType.UNVERIFIED


def _require_unit_interval(name: str, value: float | None) -> None:
    if value is None:
        return
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"{name} must be a number, got {type(value).__name__}")
    if not 0.0 <= float(value) <= 1.0:
        raise ValueError(f"{name} must be within [0, 1], got {value}")


def _require_aware(name: str, value: datetime | None) -> None:
    if value is None:
        return
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(
            f"{name} must be timezone-aware; a naive timestamp breaks retention "
            "(spec 11.2) and temporal splitting (spec 10.4)"
        )


def _freeze_mapping(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, Mapping):
        raise TypeError(f"expected a mapping, got {type(value).__name__}")
    return MappingProxyType(dict(value))


def _freeze_str_tuple(name: str, value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        raise TypeError(f"{name} must be a sequence of strings, not a single string")
    items = tuple(value)
    for item in items:
        if not isinstance(item, str):
            raise TypeError(f"{name} must contain only strings, found {type(item).__name__}")
    return items


@dataclass(frozen=True, slots=True)
class Event:
    """A single observation and whatever has been concluded about it so far."""

    # --- Provenance -------------------------------------------------------
    event_id: str
    timestamp: datetime
    """When the observed thing happened, according to the host.

    Host-supplied and therefore not trustworthy: a root-level adversary can
    move the clock, and ordinary clock drift is enough to reorder events.
    Use `ingested_at` for anything that must not be forgeable.
    """

    host_id: str
    tenant_id: str
    """Present from day one (spec decision 19). Adding it later would mean
    migrating every stored event."""

    subject_pseudonym: str
    source: EventSource

    # --- Payload ----------------------------------------------------------
    raw_attributes: Mapping[str, Any] = field(default_factory=dict)
    extracted_features: Mapping[str, Any] = field(default_factory=dict)

    # --- Scoring. None means "not evaluated", and never 0.0. ---------------
    raw_score: float | None = None
    context_modifier: float | None = None
    final_score: float | None = None
    confidence: float | None = None
    level: RiskLevel | None = None
    degraded_layers: tuple[str, ...] = ()
    triggered_rule_ids: tuple[str, ...] = ()

    # --- Decision, kept separate from enforcement (spec 4) -----------------
    decision: Decision | None = None
    enforced: bool = False
    enforcement_blocked_reason: EnforcementBlockedReason | None = None

    # --- Explainability (spec 9) ------------------------------------------
    explanation: Mapping[str, Any] = field(default_factory=dict)

    # --- Ingestion --------------------------------------------------------
    ingested_at: datetime | None = None
    """When the receiving side accepted the event. Stamped by the store, which
    overwrites whatever arrived, so upstream cannot forge it. Retention (11.2)
    and temporal splits (10.4) key off this, not `timestamp`."""

    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("event_id", "host_id", "tenant_id", "schema_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")

        if not PSEUDONYM_PATTERN.match(self.subject_pseudonym):
            raise ValueError(
                "subject_pseudonym must match USR-<uuid4 hex>; the event schema "
                "cannot carry a real identity"
            )

        if not isinstance(self.source, EventSource):
            raise TypeError("source must be an EventSource")

        _require_aware("timestamp", self.timestamp)
        _require_aware("ingested_at", self.ingested_at)

        _require_unit_interval("raw_score", self.raw_score)
        _require_unit_interval("final_score", self.final_score)
        _require_unit_interval("confidence", self.confidence)

        if self.context_modifier is not None:
            cm = self.context_modifier
            if not isinstance(cm, (int, float)) or isinstance(cm, bool):
                raise TypeError("context_modifier must be a number")
            if not 0.0 < float(cm) <= CONTEXT_MODIFIER_MAX:
                raise ValueError(
                    f"context_modifier must be within (0, {CONTEXT_MODIFIER_MAX}], got {cm}"
                )

        if self.level is not None and not isinstance(self.level, RiskLevel):
            raise TypeError("level must be a RiskLevel")
        if self.decision is not None and not isinstance(self.decision, Decision):
            raise TypeError("decision must be a Decision")
        if self.enforcement_blocked_reason is not None and not isinstance(
            self.enforcement_blocked_reason, EnforcementBlockedReason
        ):
            raise TypeError("enforcement_blocked_reason must be an EnforcementBlockedReason")
        if not isinstance(self.enforced, bool):
            raise TypeError("enforced must be a bool")

        # An event cannot be both enforced and blocked from enforcement.
        if self.enforced:
            if self.decision is None:
                raise ValueError("enforced=True requires a decision")
            if not self.decision.requires_enforcement:
                raise ValueError(
                    f"enforced=True is impossible for decision {self.decision.value!r}, "
                    "which asks for no enforcement action"
                )
            if self.enforcement_blocked_reason is not None:
                raise ValueError(
                    "enforced=True and enforcement_blocked_reason are mutually exclusive"
                )

        object.__setattr__(self, "raw_attributes", _freeze_mapping(self.raw_attributes))
        object.__setattr__(self, "extracted_features", _freeze_mapping(self.extracted_features))
        object.__setattr__(self, "explanation", _freeze_mapping(self.explanation))
        object.__setattr__(
            self, "degraded_layers", _freeze_str_tuple("degraded_layers", self.degraded_layers)
        )
        object.__setattr__(
            self,
            "triggered_rule_ids",
            _freeze_str_tuple("triggered_rule_ids", self.triggered_rule_ids),
        )

    @property
    def verdict_type(self) -> VerdictType | None:
        """Derived from `confidence`, never stored.

        Storing it beside `confidence` would allow a row where the two
        disagree; spec 9 defines the mapping, so the mapping is the only
        place it can live.
        """
        return derive_verdict_type(self.confidence)

    @property
    def is_evaluated(self) -> bool:
        """Whether any scoring layer has run on this event."""
        return self.confidence is not None or self.final_score is not None

    def to_dict(self) -> dict[str, Any]:
        """Plain-Python projection for storage and JSON.

        Includes the derived `verdict_type` for consumers; `from_dict`
        discards it, so it can never be read back as stored state.
        """
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "host_id": self.host_id,
            "tenant_id": self.tenant_id,
            "subject_pseudonym": self.subject_pseudonym,
            "source": self.source.value,
            "raw_attributes": dict(self.raw_attributes),
            "extracted_features": dict(self.extracted_features),
            "raw_score": self.raw_score,
            "context_modifier": self.context_modifier,
            "final_score": self.final_score,
            "confidence": self.confidence,
            "verdict_type": self.verdict_type.value if self.verdict_type else None,
            "level": self.level.value if self.level else None,
            "degraded_layers": list(self.degraded_layers),
            "triggered_rule_ids": list(self.triggered_rule_ids),
            "decision": self.decision.value if self.decision else None,
            "enforced": self.enforced,
            "enforcement_blocked_reason": (
                self.enforcement_blocked_reason.value
                if self.enforcement_blocked_reason
                else None
            ),
            "explanation": dict(self.explanation),
            "ingested_at": self.ingested_at.isoformat() if self.ingested_at else None,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Event":
        """Rebuild an Event. Any `verdict_type` key present is ignored."""

        def _dt(value: Any) -> datetime | None:
            if value is None:
                return None
            parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
            return parsed.astimezone(timezone.utc)

        return cls(
            event_id=data["event_id"],
            timestamp=_dt(data["timestamp"]),
            host_id=data["host_id"],
            tenant_id=data["tenant_id"],
            subject_pseudonym=data["subject_pseudonym"],
            source=EventSource(data["source"]),
            raw_attributes=data.get("raw_attributes") or {},
            extracted_features=data.get("extracted_features") or {},
            raw_score=data.get("raw_score"),
            context_modifier=data.get("context_modifier"),
            final_score=data.get("final_score"),
            confidence=data.get("confidence"),
            level=RiskLevel(data["level"]) if data.get("level") else None,
            degraded_layers=tuple(data.get("degraded_layers") or ()),
            triggered_rule_ids=tuple(data.get("triggered_rule_ids") or ()),
            decision=Decision(data["decision"]) if data.get("decision") else None,
            enforced=bool(data.get("enforced", False)),
            enforcement_blocked_reason=(
                EnforcementBlockedReason(data["enforcement_blocked_reason"])
                if data.get("enforcement_blocked_reason")
                else None
            ),
            explanation=data.get("explanation") or {},
            ingested_at=_dt(data.get("ingested_at")),
            schema_version=data.get("schema_version", SCHEMA_VERSION),
        )

    def enriched(self, **changes: Any) -> "Event":
        """Return a new Event with `changes` applied. The original is untouched."""
        return replace(self, **changes)


def _immutable_setattr(self: Event, name: str, value: Any) -> None:
    raise FrozenInstanceError(f"Event is immutable; cannot assign to {name!r}")


def _immutable_delattr(self: Event, name: str) -> None:
    raise FrozenInstanceError(f"Event is immutable; cannot delete {name!r}")


# Installed after class creation, because @dataclass(frozen=True) refuses to
# let the class body define these.
#
# Why they are needed at all: with slots=True the decorator rebuilds the class,
# while the generated __setattr__ still closes over the original. Its guard
# `type(self) is cls` is therefore False for every instance, so assigning to
# anything that is not a field falls through to a zero-argument super() with a
# broken __class__ cell - an opaque TypeError instead of a clean refusal. That
# matters here because `verdict_type` is a property: without this, assigning to
# it fails for the wrong reason and with an unreadable message.
#
# Neither the generated __init__ nor __post_init__ is affected: both write
# through object.__setattr__ directly, never through this one.
Event.__setattr__ = _immutable_setattr  # type: ignore[method-assign]
Event.__delattr__ = _immutable_delattr  # type: ignore[method-assign]
