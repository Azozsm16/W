"""systemd unit generation - spec 11.3, decision 11.

The unit is checked by systemd's own parser, not by reading it. systemd
*ignores* a directive it does not recognise rather than rejecting it, so a
misspelled `Restart=` yields a service that starts happily with no restart
policy - precisely the silent failure this module exists to prevent.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ebabf.packaging import (
    EXIT_STORAGE_HALTED,
    UnitSpec,
    default_executable,
    render_unit,
    validate_unit,
)

needs_systemd = pytest.mark.skipif(
    shutil.which("systemd-analyze") is None, reason="systemd-analyze not installed"
)


class TestRendering:
    def test_contains_the_restart_policy(self) -> None:
        text = render_unit(UnitSpec())
        assert "Restart=always" in text
        assert "RestartSec=" in text

    def test_disables_the_start_rate_limit(self) -> None:
        """Restart=always alone is not enough.

        systemd's default is five starts in ten seconds; past that the unit
        enters failed state and is never restarted. A fortnight of recording
        must not end on one burst of fast restarts.
        """
        text = render_unit(UnitSpec())
        assert "StartLimitIntervalSec=0" in text
        unit_section = text.split("[Service]")[0]
        assert "StartLimitIntervalSec=0" in unit_section, "must sit in [Unit]"

    def test_prevents_restarting_into_a_full_disk(self) -> None:
        text = render_unit(UnitSpec())
        assert f"RestartPreventExitStatus={EXIT_STORAGE_HALTED}" in text

    def test_enabled_at_boot(self) -> None:
        text = render_unit(UnitSpec())
        assert "[Install]" in text
        assert "WantedBy=multi-user.target" in text

    def test_ships_no_unverifiable_sandboxing(self) -> None:
        """The agent reads /home and /var/log; a directive whose effect we
        cannot verify here would blind a collector silently."""
        text = render_unit(UnitSpec())
        for directive in ("ProtectHome=", "ProtectSystem=", "PrivateDevices="):
            assert directive not in text

    def test_command_and_arguments_are_rendered(self) -> None:
        spec = UnitSpec(
            command="baseline", interval=15.0, extra_args=("--db", "/var/lib/ebabf/b.db")
        )
        text = render_unit(spec)
        assert "baseline --interval 15.0 --db /var/lib/ebabf/b.db" in text

    def test_user_and_working_directory(self) -> None:
        text = render_unit(UnitSpec(user="ebabf", working_directory=Path("/srv/ebabf")))
        assert "User=ebabf" in text
        assert "WorkingDirectory=/srv/ebabf" in text

    def test_filename_follows_the_name(self) -> None:
        assert UnitSpec(name="ebabf-baseline").filename == "ebabf-baseline.service"

    def test_executable_is_discoverable(self) -> None:
        assert default_executable().name == "ebabf-agent"


@needs_systemd
class TestValidationAgainstSystemd:
    def test_the_generated_unit_is_accepted(self) -> None:
        assert validate_unit(render_unit(UnitSpec())) == []

    def test_the_baseline_unit_is_accepted(self) -> None:
        spec = UnitSpec(name="ebabf-baseline", command="baseline", extra_args=("--db", "/tmp/b.db"))
        assert validate_unit(render_unit(spec), name=spec.filename) == []

    def test_a_misspelled_directive_is_caught(self) -> None:
        """systemd would ignore this at runtime, leaving no restart policy."""
        broken = render_unit(UnitSpec()).replace("Restart=always", "Restrt=always")
        problems = validate_unit(broken)
        assert problems
        assert any("Unknown key name" in p for p in problems)

    def test_a_bad_value_is_caught(self) -> None:
        broken = render_unit(UnitSpec()).replace("Type=simple", "Type=banana")
        assert validate_unit(broken)

    def test_missing_analyzer_is_reported_not_assumed_clean(self, monkeypatch) -> None:
        monkeypatch.setattr("ebabf.packaging.shutil.which", lambda _: None)
        problems = validate_unit(render_unit(UnitSpec()))
        assert problems == ["systemd-analyze not available; unit was not validated"]


class TestCli:
    def test_unit_command_prints_a_validated_unit(self, capsys) -> None:
        from ebabf.bootstrap import main

        assert main(["unit", "--mode", "baseline"]) == 0
        printed = capsys.readouterr().out
        assert "[Unit]" in printed and "Restart=always" in printed
        assert "baseline" in printed

    def test_unit_command_offers_run_mode(self, capsys) -> None:
        from ebabf.bootstrap import main

        assert main(["unit", "--mode", "run"]) == 0
        assert "ebabf-agent run" in capsys.readouterr().out

    def test_status_command_on_a_real_recording(self, tmp_path: Path, capsys) -> None:
        from datetime import datetime, timezone

        from ebabf.bootstrap import main
        from ebabf.schema import Event, EventSource
        from ebabf.storage import EventStore

        database = tmp_path / "b.db"
        store = EventStore(database)
        store.append(
            Event(
                event_id="EVT-1",
                timestamp=datetime(2026, 3, 1, tzinfo=timezone.utc),
                host_id="h",
                tenant_id="t",
                subject_pseudonym="USR-" + "0" * 32,
                source=EventSource.PROCESS,
            )
        )
        store.close()

        assert main(["status", "--db", str(database)]) == 0
        printed = capsys.readouterr().out
        assert "events          1" in printed
        assert "free disk" in printed

    def test_status_on_a_missing_database_fails_clearly(self, tmp_path: Path, capsys) -> None:
        from ebabf.bootstrap import main

        assert main(["status", "--db", str(tmp_path / "absent.db")]) == 1
        assert "nothing has been recorded" in capsys.readouterr().out

    def test_status_json_is_machine_readable(self, tmp_path: Path, capsys) -> None:
        import json

        from ebabf.bootstrap import main
        from ebabf.storage import EventStore

        database = tmp_path / "b.db"
        EventStore(database).close()
        assert main(["status", "--db", str(database), "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert "gaps" in payload and "free_bytes" in payload
