"""The single auditable join, and the Break-Glass conditions on it (spec 18.4)."""

from __future__ import annotations

import pytest

from ebabf.schema import RiskLevel
from ebabf.storage import EventStore, IdentityStore, TenantPseudonymizer
from ebabf.storage.bridge import BreakGlassDenied, resolve_subject_for_event
from tests.conftest import make_event


@pytest.fixture()
def wired(event_store: EventStore, identity_store: IdentityStore, pseudonymizer: TenantPseudonymizer):
    pseudonym = pseudonymizer.pseudonymize("alice")
    event = event_store.append(make_event(subject_pseudonym=pseudonym))
    return event_store, identity_store, event


def _resolve(wired, **overrides):
    event_store, identity_store, event = wired
    kwargs = {
        "event_store": event_store,
        "identity_store": identity_store,
        "event_id": event.event_id,
        "actor": "amal",
        "second_approver": "sami",
        "reason": "incident 42: suspected exfiltration",
    }
    kwargs.update(overrides)
    return resolve_subject_for_event(**kwargs)


class TestHappyPath:
    def test_discloses_the_real_subject(self, wired) -> None:
        assert _resolve(wired) == "alice"

    def test_writes_the_audit_row_before_returning(self, wired) -> None:
        _, identity_store, event = wired
        assert identity_store.access_log() == []
        _resolve(wired)
        log = identity_store.access_log()
        assert len(log) == 1
        assert log[0]["event_id"] == event.event_id
        assert log[0]["actor"] == "amal"
        assert log[0]["reason"].startswith("incident 42")


class TestWrittenReason:
    @pytest.mark.parametrize("reason", ["", "   ", None])
    def test_required(self, wired, reason) -> None:
        with pytest.raises(BreakGlassDenied, match="written reason"):
            _resolve(wired, reason=reason)

    def test_no_audit_row_on_refusal(self, wired) -> None:
        _, identity_store, _ = wired
        with pytest.raises(BreakGlassDenied):
            _resolve(wired, reason="")
        assert identity_store.access_log() == []


class TestTwoPersonRule:
    def test_approver_cannot_be_the_requester(self, wired) -> None:
        with pytest.raises(BreakGlassDenied, match="two-person rule"):
            _resolve(wired, actor="amal", second_approver="amal")

    def test_whitespace_does_not_defeat_it(self, wired) -> None:
        with pytest.raises(BreakGlassDenied, match="two-person rule"):
            _resolve(wired, actor="amal", second_approver="  amal  ")

    @pytest.mark.parametrize("field", ["actor", "second_approver"])
    def test_both_parties_must_be_named(self, wired, field: str) -> None:
        with pytest.raises(BreakGlassDenied):
            _resolve(wired, **{field: "  "})


class TestSelfArmingSeverityGate:
    """Written so it starts enforcing on its own once scoring lands (Sprint 4)."""

    def test_passes_while_nothing_has_a_level(self, wired) -> None:
        _, _, event = wired
        assert event.level is None
        assert _resolve(wired) == "alice"

    @pytest.mark.parametrize(
        "level", [RiskLevel.NORMAL, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]
    )
    def test_refuses_below_critical_the_moment_a_level_exists(
        self, event_store: EventStore, identity_store: IdentityStore,
        pseudonymizer: TenantPseudonymizer, level: RiskLevel,
    ) -> None:
        pseudonym = pseudonymizer.pseudonymize("alice")
        event = event_store.append(
            make_event(subject_pseudonym=pseudonym, level=level, confidence=0.9)
        )
        with pytest.raises(BreakGlassDenied, match="below critical threshold"):
            resolve_subject_for_event(
                event_store=event_store,
                identity_store=identity_store,
                event_id=event.event_id,
                actor="amal",
                second_approver="sami",
                reason="incident 42",
            )

    def test_permits_critical(
        self, event_store: EventStore, identity_store: IdentityStore,
        pseudonymizer: TenantPseudonymizer,
    ) -> None:
        pseudonym = pseudonymizer.pseudonymize("alice")
        event = event_store.append(
            make_event(subject_pseudonym=pseudonym, level=RiskLevel.CRITICAL, confidence=0.95)
        )
        assert resolve_subject_for_event(
            event_store=event_store,
            identity_store=identity_store,
            event_id=event.event_id,
            actor="amal",
            second_approver="sami",
            reason="incident 42",
        ) == "alice"

    def test_no_configuration_can_switch_the_gate_off(self) -> None:
        """A gate with an off switch is a back door. There is no setting."""
        from ebabf.config import AgentConfig

        assert not any(
            "break_glass" in name or "severity" in name
            for name in AgentConfig.__dataclass_fields__
        )


class TestUnknownEvent:
    def test_refuses_and_records_nothing(self, wired) -> None:
        _, identity_store, _ = wired
        with pytest.raises(BreakGlassDenied, match="no such event"):
            _resolve(wired, event_id="EVT-does-not-exist")
        assert identity_store.access_log() == []
