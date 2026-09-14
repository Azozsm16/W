"""Enforcement engine: one off switch, kill-switch first, fail-open (spec 4, 11.3)."""

from __future__ import annotations

import pytest

from ebabf.engine.decision import DecisionOutcome
from ebabf.engine.enforcement import EnforcementEngine, EnforcementResult, NoOpEnforcementEngine
from ebabf.engine.killswitch import KillSwitch
from ebabf.schema import Decision, EnforcementBlockedReason
from tests.conftest import AlwaysBlockEngine, blocking_outcome, make_event


class ExplodingEnforcer(EnforcementEngine):
    name = "exploding"

    def _enforce(self, outcome: DecisionOutcome) -> EnforcementResult:
        raise OSError("iptables binary missing")


class TestSingleOffSwitch:
    def test_one_setting_disables_everything(self, kill_switch: KillSwitch) -> None:
        engine = AlwaysBlockEngine(enabled=False, kill_switch=kill_switch)
        result = engine.enforce(blocking_outcome())
        assert engine.is_enabled() is False
        assert result.enforced is False
        assert result.blocked_reason is EnforcementBlockedReason.ENFORCEMENT_DISABLED
        assert engine.calls == 0

    def test_training_mode_is_that_setting_off(self, kill_switch: KillSwitch) -> None:
        """Spec 4/17.1: Training Mode is enforcement off, not a second mechanism."""
        reasons = {r.value for r in EnforcementBlockedReason}
        assert "training_mode" not in reasons

        engine = AlwaysBlockEngine(enabled=False, kill_switch=kill_switch)
        outcome = blocking_outcome()
        event = engine.enforce(outcome).apply_to(outcome.event)
        # The decision is preserved even though nothing happened - which is
        # exactly what a "what would have happened" report reads.
        assert event.decision is Decision.BLOCK_AND_ISOLATE
        assert event.enforced is False

    def test_enabled_engine_acts(self, kill_switch: KillSwitch) -> None:
        engine = AlwaysBlockEngine(enabled=True, kill_switch=kill_switch)
        assert engine.enforce(blocking_outcome()).enforced is True
        assert engine.calls == 1


class TestKillSwitchPrecedence:
    def test_kill_switch_blocks_an_enabled_engine(self, kill_switch: KillSwitch) -> None:
        kill_switch.engage(reason="halt", actor="ops")
        engine = AlwaysBlockEngine(enabled=True, kill_switch=kill_switch)
        result = engine.enforce(blocking_outcome())
        assert result.blocked_reason is EnforcementBlockedReason.KILL_SWITCH_ACTIVE
        assert engine.calls == 0

    def test_is_enabled_reflects_the_kill_switch(self, kill_switch: KillSwitch) -> None:
        engine = AlwaysBlockEngine(enabled=True, kill_switch=kill_switch)
        assert engine.is_enabled() is True
        kill_switch.engage(reason="halt", actor="ops")
        assert engine.is_enabled() is False
        kill_switch.release(actor="ops")
        assert engine.is_enabled() is True

    def test_config_off_is_reported_ahead_of_the_kill_switch(
        self, kill_switch: KillSwitch
    ) -> None:
        kill_switch.engage(reason="halt", actor="ops")
        engine = AlwaysBlockEngine(enabled=False, kill_switch=kill_switch)
        assert (
            engine.enforce(blocking_outcome()).blocked_reason
            is EnforcementBlockedReason.ENFORCEMENT_DISABLED
        )


class TestNoActionRequired:
    def test_logging_decisions_are_not_enforcement_failures(
        self, kill_switch: KillSwitch
    ) -> None:
        engine = AlwaysBlockEngine(enabled=True, kill_switch=kill_switch)
        outcome = DecisionOutcome(event=make_event(decision=Decision.LOG))
        result = engine.enforce(outcome)
        assert result.blocked_reason is EnforcementBlockedReason.NO_ACTION_REQUIRED
        assert engine.calls == 0

    def test_watchlist_asks_for_nothing(self, kill_switch: KillSwitch) -> None:
        engine = AlwaysBlockEngine(enabled=True, kill_switch=kill_switch)
        outcome = DecisionOutcome(event=make_event(decision=Decision.WATCHLIST))
        assert (
            engine.enforce(outcome).blocked_reason
            is EnforcementBlockedReason.NO_ACTION_REQUIRED
        )
        assert engine.calls == 0

    def test_an_undecided_event_is_not_enforced(self, kill_switch: KillSwitch) -> None:
        engine = AlwaysBlockEngine(enabled=True, kill_switch=kill_switch)
        outcome = DecisionOutcome(event=make_event())
        assert engine.enforce(outcome).enforced is False


class TestFailOpen:
    def test_internal_fault_does_not_raise(self, kill_switch: KillSwitch) -> None:
        result = ExplodingEnforcer(enabled=True, kill_switch=kill_switch).enforce(
            blocking_outcome()
        )
        assert result.enforced is False
        assert result.blocked_reason is EnforcementBlockedReason.FAIL_OPEN
        assert "OSError" in (result.detail or "")

    def test_fault_is_recorded_on_the_event(self, kill_switch: KillSwitch) -> None:
        outcome = blocking_outcome()
        event = ExplodingEnforcer(enabled=True, kill_switch=kill_switch).enforce(
            outcome
        ).apply_to(outcome.event)
        assert event.enforced is False
        assert event.enforcement_blocked_reason is EnforcementBlockedReason.FAIL_OPEN
        assert event.decision is Decision.BLOCK_AND_ISOLATE


class TestResultInvariants:
    def test_enforced_with_a_reason_is_impossible(self) -> None:
        with pytest.raises(ValueError, match="both enforced and blocked"):
            EnforcementResult(
                enforced=True, blocked_reason=EnforcementBlockedReason.FAIL_OPEN
            )

    def test_not_enforcing_needs_a_reason(self) -> None:
        with pytest.raises(ValueError, match="requires a reason"):
            EnforcementResult(enforced=False, blocked_reason=None)

    def test_apply_to_keeps_the_event_consistent(self, kill_switch: KillSwitch) -> None:
        outcome = blocking_outcome()
        event = AlwaysBlockEngine(enabled=True, kill_switch=kill_switch).enforce(
            outcome
        ).apply_to(outcome.event)
        assert event.enforced is True
        assert event.enforcement_blocked_reason is None


class TestNoOpEngine:
    def test_reports_not_supported_rather_than_pretending(
        self, kill_switch: KillSwitch
    ) -> None:
        result = NoOpEnforcementEngine(enabled=True, kill_switch=kill_switch).enforce(
            blocking_outcome()
        )
        assert result.enforced is False
        assert result.blocked_reason is EnforcementBlockedReason.NOT_SUPPORTED

    def test_cannot_instantiate_the_abstract_base(self, kill_switch: KillSwitch) -> None:
        with pytest.raises(TypeError):
            EnforcementEngine(enabled=True, kill_switch=kill_switch)  # type: ignore[abstract]
