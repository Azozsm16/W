"""Decision engine: always runs, never enforces, never raises (spec 4, 11.3)."""

from __future__ import annotations

import pytest

from ebabf.engine.decision import DecisionEngine, DecisionOutcome, PassThroughDecisionEngine
from ebabf.schema import Decision, Event, RiskLevel
from tests.conftest import make_event


class ExplodingEngine(DecisionEngine):
    name = "exploding_layer"

    def _decide(self, event: Event) -> DecisionOutcome:
        raise RuntimeError("scoring layer unavailable")


class ScoringEngine(DecisionEngine):
    name = "stub_scoring"

    def _decide(self, event: Event) -> DecisionOutcome:
        return DecisionOutcome(
            event=event.enriched(
                raw_score=0.6,
                context_modifier=1.3,
                final_score=0.78,
                confidence=0.9,
                level=RiskLevel.HIGH,
                decision=Decision.SUSPEND,
            )
        )


class TestAlwaysRuns:
    def test_no_configuration_can_disable_it(self) -> None:
        """Spec 4: the decision engine has no off switch, by omission."""
        from ebabf.config import AgentConfig

        fields = set(AgentConfig.__dataclass_fields__)
        assert not any("decision" in name for name in fields)
        assert "enforcement_enabled" in fields

    def test_produces_a_decision_for_every_event(self) -> None:
        outcome = PassThroughDecisionEngine().decide(make_event())
        assert outcome.event.decision is Decision.LOG


class TestNeverEnforces:
    def test_decide_leaves_enforced_false(self) -> None:
        outcome = ScoringEngine().decide(make_event())
        assert outcome.event.enforced is False
        assert outcome.event.enforcement_blocked_reason is None

    def test_action_required_is_derived_not_stored(self) -> None:
        assert "action_required" not in DecisionOutcome.__dataclass_fields__
        assert ScoringEngine().decide(make_event()).action_required is True
        assert PassThroughDecisionEngine().decide(make_event()).action_required is False

    def test_watchlist_requires_no_enforcement(self) -> None:
        outcome = DecisionOutcome(event=make_event(decision=Decision.WATCHLIST))
        assert outcome.action_required is False


class TestFailureBehaviour:
    """A broken evaluator must degrade loudly, not swallow the event."""

    def test_decide_does_not_raise(self) -> None:
        outcome = ExplodingEngine().decide(make_event())
        assert isinstance(outcome, DecisionOutcome)

    def test_failure_decides_log(self) -> None:
        assert ExplodingEngine().decide(make_event()).event.decision is Decision.LOG

    def test_failure_names_the_degraded_layer(self) -> None:
        event = ExplodingEngine().decide(make_event()).event
        assert "exploding_layer" in event.degraded_layers

    def test_failure_clears_confidence(self) -> None:
        """Spec 6.3: an absent layer must not leave a confidence standing."""
        event = ExplodingEngine().decide(make_event(confidence=0.95)).event
        assert event.confidence is None
        assert event.verdict_type is None

    def test_failure_never_enforces(self) -> None:
        outcome = ExplodingEngine().decide(make_event())
        assert outcome.event.enforced is False
        assert outcome.action_required is False

    def test_existing_degraded_layers_are_preserved(self) -> None:
        event = ExplodingEngine().decide(make_event(degraded_layers=("reputation",))).event
        assert set(event.degraded_layers) == {"reputation", "exploding_layer"}

    def test_layer_is_not_recorded_twice(self) -> None:
        event = ExplodingEngine().decide(make_event(degraded_layers=("exploding_layer",))).event
        assert list(event.degraded_layers).count("exploding_layer") == 1

    def test_the_event_is_still_usable_downstream(self) -> None:
        event = ExplodingEngine().decide(make_event()).event
        assert event.event_id == "EVT-test-0001"
        assert event.subject_pseudonym == "USR-" + "0" * 32


class TestPassThroughIsNotAScore:
    def test_leaves_every_score_unset(self) -> None:
        event = PassThroughDecisionEngine().decide(make_event()).event
        assert event.raw_score is None
        assert event.final_score is None
        assert event.confidence is None
        assert event.level is None
        assert event.is_evaluated is False

    def test_records_no_degradation_when_nothing_failed(self) -> None:
        assert PassThroughDecisionEngine().decide(make_event()).event.degraded_layers == ()


def test_decision_engine_cannot_be_instantiated_directly() -> None:
    with pytest.raises(TypeError):
        DecisionEngine()  # type: ignore[abstract]
