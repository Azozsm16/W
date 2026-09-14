"""Kill-switch (spec 14.2) and its tamper checks."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from ebabf.config import AgentConfig
from ebabf.engine.decision import PassThroughDecisionEngine
from ebabf.engine.killswitch import InsecureSentinelLocation, KillSwitch, TamperKind, TamperReport
from ebabf.schema import EnforcementBlockedReason
from ebabf.storage import EventStore
from tests.conftest import AlwaysBlockEngine, blocking_outcome


class TestEngageRelease:
    def test_starts_disengaged(self, kill_switch: KillSwitch) -> None:
        assert kill_switch.is_engaged() is False

    def test_engage_then_release(self, kill_switch: KillSwitch) -> None:
        kill_switch.engage(reason="false positive on the build agent", actor="ops")
        assert kill_switch.is_engaged() is True
        kill_switch.release(actor="ops")
        assert kill_switch.is_engaged() is False

    def test_engage_records_who_and_why(self, kill_switch: KillSwitch) -> None:
        kill_switch.engage(reason="blocking our CI runner", actor="amal")
        state = kill_switch.read_state()
        assert state.engaged is True
        assert state.reason == "blocking our CI runner"
        assert state.actor == "amal"
        assert state.engaged_at is not None

    @pytest.mark.parametrize(("reason", "actor"), [("", "ops"), ("   ", "ops"), ("why", "")])
    def test_refuses_an_unattributed_engage(
        self, kill_switch: KillSwitch, reason: str, actor: str
    ) -> None:
        with pytest.raises(ValueError):
            kill_switch.engage(reason=reason, actor=actor)

    def test_sentinel_is_not_world_readable(
        self, kill_switch: KillSwitch, config: AgentConfig
    ) -> None:
        kill_switch.engage(reason="r", actor="a")
        assert stat.S_IMODE(config.kill_switch_path.stat().st_mode) == 0o600

    def test_release_is_idempotent(self, kill_switch: KillSwitch) -> None:
        kill_switch.release(actor="ops")
        kill_switch.release(actor="ops")
        assert kill_switch.is_engaged() is False


class TestNoRestartRequired:
    """Spec 14.2: takes effect immediately, without restarting the agent."""

    def test_same_instance_sees_a_switch_thrown_after_construction(
        self, kill_switch: KillSwitch, config: AgentConfig
    ) -> None:
        engine = AlwaysBlockEngine(enabled=True, kill_switch=kill_switch)
        assert engine.enforce(blocking_outcome()).enforced is True

        kill_switch.engage(reason="stop now", actor="ops")

        result = engine.enforce(blocking_outcome())
        assert result.enforced is False
        assert result.blocked_reason is EnforcementBlockedReason.KILL_SWITCH_ACTIVE

    def test_a_switch_thrown_by_another_process_is_honoured(
        self, kill_switch: KillSwitch, config: AgentConfig
    ) -> None:
        """The running agent never sees this write; it only sees the file."""
        engine = AlwaysBlockEngine(enabled=True, kill_switch=kill_switch)
        assert engine.is_enabled() is True

        external = KillSwitch(config.kill_switch_path, trusted_owner_uid=os.getuid())
        external.engage(reason="thrown from the CLI", actor="root")

        assert engine.is_enabled() is False
        assert engine.enforce(blocking_outcome()).enforced is False

    def test_state_is_never_cached(self, kill_switch: KillSwitch) -> None:
        for expected in (True, False, True, False):
            if expected:
                kill_switch.engage(reason="toggle", actor="ops")
            else:
                kill_switch.release(actor="ops")
            assert kill_switch.is_engaged() is expected


class TestLoggingSurvivesTheKillSwitch:
    """The requirement: enforcement stops, recording does not (spec 11.3)."""

    def test_events_are_still_decided_and_stored_while_engaged(
        self, kill_switch: KillSwitch, event_store: EventStore
    ) -> None:
        kill_switch.engage(reason="enforcement misbehaving", actor="ops")
        engine = AlwaysBlockEngine(enabled=True, kill_switch=kill_switch)
        decision_engine = PassThroughDecisionEngine()

        outcome = blocking_outcome()
        result = engine.enforce(outcome)
        stored = event_store.append(result.apply_to(outcome.event))

        assert kill_switch.is_engaged() is True
        assert result.enforced is False
        assert result.blocked_reason is EnforcementBlockedReason.KILL_SWITCH_ACTIVE
        assert engine.calls == 0, "the enforcer itself must never be reached"

        # The record exists, carries the decision, and says why nothing happened.
        assert event_store.count() == 1
        read_back = event_store.get(stored.event_id)
        assert read_back is not None
        assert read_back.decision is outcome.event.decision
        assert read_back.enforced is False
        assert (
            read_back.enforcement_blocked_reason
            is EnforcementBlockedReason.KILL_SWITCH_ACTIVE
        )
        assert read_back.ingested_at is not None

        # And decisions keep being computed while it is engaged.
        assert decision_engine.decide(outcome.event).event.decision is not None

    def test_many_events_recorded_while_enforcement_is_halted(
        self, kill_switch: KillSwitch, event_store: EventStore
    ) -> None:
        kill_switch.engage(reason="halt", actor="ops")
        engine = AlwaysBlockEngine(enabled=True, kill_switch=kill_switch)
        for index in range(10):
            outcome = blocking_outcome()
            event = outcome.event.enriched(event_id=f"EVT-{index:04d}")
            result = engine.enforce(outcome)
            event_store.append(result.apply_to(event))

        assert event_store.count() == 10
        assert all(not e.enforced for e in event_store.query(limit=20))


class TestSentinelTampering:
    """A sentinel any local user can plant must not stop enforcement."""

    @pytest.mark.skipif(os.getuid() != 0, reason="needs root to chown the sentinel")
    def test_sentinel_owned_by_someone_else_is_rejected(
        self, kill_switch: KillSwitch, config: AgentConfig, tamper_reports: list[TamperReport]
    ) -> None:
        """A trusted directory holding a sentinel owned by somebody else.

        The directory check alone would not catch this: the file is what the
        switch acts on, so the file's owner is checked too.
        """
        kill_switch.engage(reason="legitimate", actor="ops")
        assert kill_switch.is_engaged() is True

        os.chown(config.kill_switch_path, 4242, 4242)

        assert kill_switch.is_engaged() is False
        assert tamper_reports[-1].kind == TamperKind.WRONG_OWNER
        assert tamper_reports[-1].observed_uid == 4242

    def test_world_writable_sentinel_is_rejected(
        self, kill_switch: KillSwitch, config: AgentConfig, tamper_reports: list[TamperReport]
    ) -> None:
        kill_switch.engage(reason="legitimate", actor="ops")
        config.kill_switch_path.chmod(0o666)
        assert kill_switch.is_engaged() is False
        assert tamper_reports[-1].kind == TamperKind.WORLD_WRITABLE

    def test_symlinked_sentinel_is_rejected(
        self, kill_switch: KillSwitch, config: AgentConfig, tmp_path: Path,
        tamper_reports: list[TamperReport],
    ) -> None:
        """A symlink to a trusted file would pass an ownership check made after
        following it, so the check is made on the link itself."""
        decoy = tmp_path / "decoy"
        decoy.write_text("{}")
        decoy.chmod(0o600)
        config.kill_switch_path.symlink_to(decoy)

        assert kill_switch.is_engaged() is False
        assert tamper_reports[-1].kind == TamperKind.SYMLINK

    def test_insecure_directory_discovered_at_runtime_is_rejected(
        self, kill_switch: KillSwitch, config: AgentConfig, tamper_reports: list[TamperReport]
    ) -> None:
        kill_switch.engage(reason="legitimate", actor="ops")
        config.kill_switch_path.parent.chmod(0o777)
        assert kill_switch.is_engaged() is False
        assert tamper_reports[-1].kind == TamperKind.DIRECTORY_INSECURE

    def test_rejection_is_reported_never_silent(
        self, kill_switch: KillSwitch, config: AgentConfig, tamper_reports: list[TamperReport]
    ) -> None:
        kill_switch.engage(reason="legitimate", actor="ops")
        config.kill_switch_path.chmod(0o666)
        kill_switch.is_engaged()

        assert len(tamper_reports) == 1
        report = tamper_reports[0]
        assert report.path == config.kill_switch_path
        assert report.observed_uid == os.getuid()
        assert report.observed_mode == 0o666
        assert "detected_at" in report.as_dict()

    def test_a_broken_tamper_handler_does_not_open_the_bypass(
        self, config: AgentConfig
    ) -> None:
        def explode(_: TamperReport) -> None:
            raise RuntimeError("reporting pipeline down")

        switch = KillSwitch(
            config.kill_switch_path, trusted_owner_uid=os.getuid(), on_tamper=explode
        )
        switch.engage(reason="legitimate", actor="ops")
        config.kill_switch_path.chmod(0o666)
        assert switch.is_engaged() is False


class TestInsecureLocationAtStartup:
    def test_agent_refuses_to_start_on_a_world_writable_directory(
        self, config: AgentConfig
    ) -> None:
        directory = config.kill_switch_path.parent
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o777)
        with pytest.raises(InsecureSentinelLocation):
            KillSwitch(config.kill_switch_path, trusted_owner_uid=os.getuid())

    def test_agent_refuses_a_directory_owned_by_another_user(
        self, config: AgentConfig
    ) -> None:
        with pytest.raises(InsecureSentinelLocation):
            KillSwitch(config.kill_switch_path, trusted_owner_uid=os.getuid() + 4242)

    def test_directory_is_created_locked_down(self, kill_switch: KillSwitch, config: AgentConfig) -> None:
        assert stat.S_IMODE(config.kill_switch_path.parent.stat().st_mode) == 0o700


class TestCorruptSentinel:
    def test_unparseable_contents_still_count_as_engaged(
        self, kill_switch: KillSwitch, config: AgentConfig
    ) -> None:
        """Failing to halt because the reason field is corrupt would be the
        worst possible reading of spec 14.2."""
        kill_switch.engage(reason="legitimate", actor="ops")
        config.kill_switch_path.write_text("not json at all")
        config.kill_switch_path.chmod(0o600)

        state = kill_switch.read_state()
        assert state.engaged is True
        assert state.reason is None

    def test_engage_is_atomic(self, kill_switch: KillSwitch, config: AgentConfig) -> None:
        kill_switch.engage(reason="r", actor="a")
        payload = json.loads(config.kill_switch_path.read_text())
        assert set(payload) == {"reason", "actor", "engaged_at"}
        leftovers = list(config.kill_switch_path.parent.glob(".killswitch-*"))
        assert leftovers == []


class TestCli:
    def test_status_engage_release_roundtrip(self, config: AgentConfig, capsys) -> None:
        from ebabf.engine.killswitch import main

        path = str(config.kill_switch_path)
        assert main(["--path", path, "status"]) == 0
        assert "engaged: False" in capsys.readouterr().out

        assert main(["--path", path, "engage", "--reason", "ops call", "--actor", "amal"]) == 0
        assert main(["--path", path, "status"]) == 0
        out = capsys.readouterr().out
        assert "engaged: True" in out and "ops call" in out

        assert main(["--path", path, "release", "--actor", "amal"]) == 0
        assert main(["--path", path, "status"]) == 0
        assert "engaged: False" in capsys.readouterr().out


class TestDefensivePaths:
    def test_release_requires_a_named_actor(self, kill_switch: KillSwitch) -> None:
        with pytest.raises(ValueError, match="named actor"):
            kill_switch.release(actor="  ")

    def test_a_directory_where_the_sentinel_should_be(
        self, kill_switch: KillSwitch, config: AgentConfig, tamper_reports: list[TamperReport]
    ) -> None:
        config.kill_switch_path.mkdir()
        assert kill_switch.is_engaged() is False

    def test_sentinel_path_pointing_at_a_file_not_a_directory(
        self, config: AgentConfig, tmp_path: Path
    ) -> None:
        not_a_dir = tmp_path / "plain-file"
        not_a_dir.write_text("x")
        with pytest.raises(Exception):
            KillSwitch(not_a_dir / "KILL_SWITCH", trusted_owner_uid=os.getuid())

    def test_tamper_report_serialises(self, kill_switch: KillSwitch, config: AgentConfig,
                                      tamper_reports: list[TamperReport]) -> None:
        kill_switch.engage(reason="r", actor="a")
        config.kill_switch_path.chmod(0o666)
        kill_switch.is_engaged()
        payload = tamper_reports[-1].as_dict()
        assert payload["observed_mode"] == "0o666"
        assert payload["kind"] == TamperKind.WORLD_WRITABLE


class TestDefaultTamperHandler:
    def test_logs_at_critical(self, config: AgentConfig, caplog) -> None:
        """Spec 11.3 classifies agent tampering as a Critical event."""
        import logging

        switch = KillSwitch(config.kill_switch_path, trusted_owner_uid=os.getuid())
        switch.engage(reason="legitimate", actor="ops")
        config.kill_switch_path.chmod(0o666)

        with caplog.at_level(logging.CRITICAL, logger="ebabf.engine.killswitch"):
            assert switch.is_engaged() is False

        records = [r for r in caplog.records if "tampering detected" in r.message]
        assert records and records[0].levelno == logging.CRITICAL
