"""The Event contract (spec 14.1)."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from ebabf.schema import (
    CONTEXT_MODIFIER_MAX,
    Decision,
    EnforcementBlockedReason,
    Event,
    EventSource,
    RiskLevel,
    SCHEMA_VERSION,
    VerdictType,
    derive_verdict_type,
)
from tests.conftest import FIXED_TIME, make_event


class TestRequiredFields:
    def test_all_spec_14_1_fields_exist(self) -> None:
        event = make_event()
        for name in (
            "event_id",
            "timestamp",
            "host_id",
            "tenant_id",
            "subject_pseudonym",
            "source",
            "raw_attributes",
            "extracted_features",
            "raw_score",
            "context_modifier",
            "final_score",
            "confidence",
            "verdict_type",
            "level",
            "degraded_layers",
            "triggered_rule_ids",
            "decision",
            "enforced",
            "enforcement_blocked_reason",
            "explanation",
            "ingested_at",
            "schema_version",
        ):
            assert hasattr(event, name), f"spec 14.1 field missing: {name}"

    def test_schema_version_is_stamped(self) -> None:
        assert make_event().schema_version == SCHEMA_VERSION

    @pytest.mark.parametrize("field", ["event_id", "host_id", "tenant_id"])
    def test_blank_identifiers_rejected(self, field: str) -> None:
        with pytest.raises(ValueError):
            make_event(**{field: "  "})


class TestUnevaluatedIsNotZero:
    """Spec 6.3: an absent layer is not a score of zero."""

    def test_scoring_fields_default_to_none(self) -> None:
        event = make_event()
        assert event.raw_score is None
        assert event.final_score is None
        assert event.confidence is None
        assert event.context_modifier is None
        assert event.level is None
        assert event.is_evaluated is False

    def test_zero_is_a_distinct_value_from_unevaluated(self) -> None:
        scored = make_event(raw_score=0.0, confidence=0.0)
        assert scored.raw_score == 0.0
        assert scored.is_evaluated is True
        assert make_event().is_evaluated is False


class TestVerdictTypeIsDerived:
    def test_not_a_stored_field(self) -> None:
        assert "verdict_type" not in {f.name for f in Event.__dataclass_fields__.values()}

    def test_cannot_be_assigned(self) -> None:
        with pytest.raises(FrozenInstanceError):
            make_event().verdict_type = VerdictType.VERDICT  # type: ignore[misc]

    def test_from_dict_ignores_any_supplied_verdict_type(self) -> None:
        payload = make_event(confidence=0.2).to_dict()
        payload["verdict_type"] = "verdict"  # a stale or forged value
        assert Event.from_dict(payload).verdict_type is VerdictType.UNVERIFIED

    @pytest.mark.parametrize(
        ("confidence", "expected"),
        [
            (None, None),
            (0.0, VerdictType.UNVERIFIED),
            (0.49, VerdictType.UNVERIFIED),
            (0.5, VerdictType.SUSPICION),
            (0.84, VerdictType.SUSPICION),
            (0.85, VerdictType.VERDICT),
            (1.0, VerdictType.VERDICT),
        ],
    )
    def test_bands_match_spec_9(self, confidence: float | None, expected: VerdictType | None) -> None:
        assert derive_verdict_type(confidence) is expected
        assert make_event(confidence=confidence).verdict_type is expected

    def test_none_confidence_is_not_unverified(self) -> None:
        """No judgement made is a different claim from a weak one."""
        assert make_event().verdict_type is None


class TestIngestedAt:
    def test_separate_from_timestamp_and_optional(self) -> None:
        event = make_event()
        assert event.timestamp == FIXED_TIME
        assert event.ingested_at is None

    def test_must_be_timezone_aware(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            make_event(ingested_at=datetime(2026, 3, 1, 12, 0, 0))

    def test_survives_roundtrip(self) -> None:
        moment = datetime(2026, 3, 1, 12, 0, 5, tzinfo=timezone.utc)
        event = make_event(ingested_at=moment)
        assert Event.from_dict(event.to_dict()).ingested_at == moment


class TestPseudonymGuard:
    @pytest.mark.parametrize(
        "value",
        [
            "alice",
            "USR-8842",
            "USR-" + "0" * 31,
            "USR-" + "0" * 33,
            "USR-" + "G" * 32,
            "usr-" + "0" * 32,
            "",
        ],
    )
    def test_rejects_anything_that_is_not_a_uuid4_pseudonym(self, value: str) -> None:
        with pytest.raises(ValueError, match="subject_pseudonym"):
            make_event(subject_pseudonym=value)

    def test_accepts_the_agreed_format(self) -> None:
        import uuid

        make_event(subject_pseudonym=f"USR-{uuid.uuid4().hex}")


class TestBounds:
    @pytest.mark.parametrize("field", ["raw_score", "final_score", "confidence"])
    @pytest.mark.parametrize("value", [-0.01, 1.01])
    def test_scores_confined_to_unit_interval(self, field: str, value: float) -> None:
        with pytest.raises(ValueError, match=field):
            make_event(**{field: value})

    @pytest.mark.parametrize("value", [0.0, -0.5, 2.01, 10.0])
    def test_context_modifier_outside_open_zero_to_two_rejected(self, value: float) -> None:
        with pytest.raises(ValueError, match="context_modifier"):
            make_event(context_modifier=value)

    @pytest.mark.parametrize("value", [0.01, 0.3, 1.0, 1.4, CONTEXT_MODIFIER_MAX])
    def test_calibration_range_is_config_not_schema(self, value: float) -> None:
        """Spec 6.4's 0.3-1.4 are examples; the schema must not freeze them."""
        assert make_event(context_modifier=value).context_modifier == value

    def test_naive_timestamp_rejected(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            make_event(timestamp=datetime(2026, 3, 1, 12, 0, 0))


class TestEnforcementInvariants:
    def test_enforced_requires_a_decision(self) -> None:
        with pytest.raises(ValueError, match="requires a decision"):
            make_event(enforced=True)

    def test_enforced_and_blocked_are_mutually_exclusive(self) -> None:
        with pytest.raises(ValueError, match="mutually exclusive"):
            make_event(
                enforced=True,
                decision=Decision.BLOCK_AND_ISOLATE,
                enforcement_blocked_reason=EnforcementBlockedReason.KILL_SWITCH_ACTIVE,
            )

    def test_cannot_enforce_a_logging_only_decision(self) -> None:
        with pytest.raises(ValueError, match="asks for no enforcement"):
            make_event(enforced=True, decision=Decision.LOG)

    def test_enforced_is_independent_of_decision(self) -> None:
        """Spec 17.1 needs a decision that was made but not carried out."""
        event = make_event(
            decision=Decision.BLOCK_AND_ISOLATE,
            enforced=False,
            enforcement_blocked_reason=EnforcementBlockedReason.ENFORCEMENT_DISABLED,
        )
        assert event.decision is Decision.BLOCK_AND_ISOLATE
        assert event.enforced is False


class TestImmutability:
    def test_fields_cannot_be_reassigned(self) -> None:
        with pytest.raises(FrozenInstanceError):
            make_event().event_id = "EVT-other"  # type: ignore[misc]

    def test_mappings_cannot_be_mutated_through_the_event(self) -> None:
        event = make_event(raw_attributes={"exec_path": "/usr/bin/curl"})
        with pytest.raises(TypeError):
            event.raw_attributes["exec_path"] = "/bin/sh"  # type: ignore[index]

    def test_mutating_the_source_dict_does_not_change_the_event(self) -> None:
        attrs = {"exec_path": "/usr/bin/curl"}
        event = make_event(raw_attributes=attrs)
        attrs["exec_path"] = "/bin/sh"
        assert event.raw_attributes["exec_path"] == "/usr/bin/curl"

    def test_enrichment_leaves_the_original_intact(self) -> None:
        original = make_event()
        enriched = original.enriched(raw_score=0.4, context_modifier=1.4, final_score=0.56)
        assert original.raw_score is None
        assert enriched.raw_score == 0.4
        assert enriched.final_score == 0.56
        assert enriched.event_id == original.event_id


class TestSerialisation:
    def test_roundtrip_preserves_everything(self) -> None:
        event = make_event(
            raw_attributes={"exec_path": "/usr/bin/curl", "child_process_count": 3},
            extracted_features={"x": 1.0},
            raw_score=0.4,
            context_modifier=1.3,
            final_score=0.52,
            confidence=0.9,
            level=RiskLevel.MEDIUM,
            degraded_layers=("reputation",),
            triggered_rule_ids=("R-014",),
            decision=Decision.ALERT_AND_RATE_LIMIT,
            explanation={"mitre_technique": "T1071.001"},
            ingested_at=datetime(2026, 3, 1, 12, 0, 5, tzinfo=timezone.utc),
        )
        assert Event.from_dict(event.to_dict()) == event

    def test_to_dict_exposes_the_derived_verdict(self) -> None:
        assert make_event(confidence=0.9).to_dict()["verdict_type"] == "verdict"

    def test_arabic_text_survives(self) -> None:
        event = make_event(explanation={"note": "نمط اتصال منتظم يشبه beaconing"})
        assert Event.from_dict(event.to_dict()).explanation["note"].startswith("نمط")


class TestDecisionClassification:
    def test_watchlist_is_a_logging_marker_not_an_action(self) -> None:
        """docs/decisions.md D-002."""
        assert Decision.WATCHLIST.requires_enforcement is False

    def test_only_host_acting_decisions_require_enforcement(self) -> None:
        enforceable = {d for d in Decision if d.requires_enforcement}
        assert enforceable == {
            Decision.ALERT_AND_RATE_LIMIT,
            Decision.SUSPEND,
            Decision.SUSPEND_AND_CONFIRM,
            Decision.BLOCK_AND_ISOLATE,
        }

    def test_alerts_are_not_enforcement(self) -> None:
        for decision in (
            Decision.ALERT,
            Decision.ALERT_UNVERIFIED,
            Decision.ALERT_AND_CONFIRM,
            Decision.URGENT_ALERT_AND_CONFIRM,
        ):
            assert decision.requires_enforcement is False


def test_event_source_covers_spec_14_1() -> None:
    assert {s.value for s in EventSource} == {
        "process",
        "network",
        "file",
        "user",
        "inventory",
    }


class TestTypeGuards:
    """The contract rejects wrong types outright, rather than storing them."""

    def test_source_must_be_an_enum(self) -> None:
        with pytest.raises(TypeError, match="source"):
            make_event(source="process")

    def test_level_must_be_an_enum(self) -> None:
        with pytest.raises(TypeError, match="level"):
            make_event(level="high")

    def test_decision_must_be_an_enum(self) -> None:
        with pytest.raises(TypeError, match="decision"):
            make_event(decision="log")

    def test_blocked_reason_must_be_an_enum(self) -> None:
        with pytest.raises(TypeError, match="EnforcementBlockedReason"):
            make_event(enforcement_blocked_reason="fail_open")

    def test_enforced_must_be_a_bool(self) -> None:
        with pytest.raises(TypeError, match="enforced"):
            make_event(enforced=1)

    def test_timestamp_must_be_a_datetime(self) -> None:
        with pytest.raises(TypeError, match="timestamp"):
            make_event(timestamp="2026-03-01T12:00:00Z")

    @pytest.mark.parametrize("field", ["raw_score", "confidence", "final_score"])
    def test_scores_must_be_numbers(self, field: str) -> None:
        with pytest.raises(TypeError, match=field):
            make_event(**{field: "0.5"})

    def test_bool_is_not_a_score(self) -> None:
        """True would silently become 1.0 and read as maximum risk."""
        with pytest.raises(TypeError, match="raw_score"):
            make_event(raw_score=True)

    def test_context_modifier_must_be_a_number(self) -> None:
        with pytest.raises(TypeError, match="context_modifier"):
            make_event(context_modifier="1.4")

    def test_mappings_must_be_mappings(self) -> None:
        with pytest.raises(TypeError, match="mapping"):
            make_event(raw_attributes=[("a", 1)])

    def test_a_string_is_not_a_list_of_layers(self) -> None:
        """("reputation") is a string, not a tuple - a mistake worth catching."""
        with pytest.raises(TypeError, match="not a single string"):
            make_event(degraded_layers="reputation")

    def test_layer_names_must_be_strings(self) -> None:
        with pytest.raises(TypeError, match="degraded_layers"):
            make_event(degraded_layers=(1, 2))

    def test_rule_ids_must_be_strings(self) -> None:
        with pytest.raises(TypeError, match="triggered_rule_ids"):
            make_event(triggered_rule_ids=(404,))

    def test_deletion_is_blocked_too(self) -> None:
        with pytest.raises(FrozenInstanceError):
            del make_event().event_id
