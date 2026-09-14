"""User activity collector - spec 5.4, and what it refuses to record."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from ebabf.collectors.base import CollectorContext
from ebabf.collectors.user_activity import (
    AuthEvent,
    AuthEventSource,
    AuthLogFileSource,
    NullAuthSource,
    UserActivityCollector,
    parse_auth_line,
    select_auth_source,
)
from ebabf.schema import EventSource

SPEC_5_4_FIELDS = {
    "activity_hour",
    "failed_auth_count",
    "sudo_usage_pattern",
    "session_duration",
}


class StubAuthSource(AuthEventSource):
    name = "stub"

    def __init__(self, events: list[AuthEvent] | None = None) -> None:
        self._events = events or []
        self.reads = 0

    @classmethod
    def is_available(cls) -> bool:
        return True

    def read_since(self, since: float) -> list[AuthEvent]:
        self.reads += 1
        return list(self._events)


class StubSession:
    def __init__(self, name: str, terminal: str | None = "pts/0", host: str = "", started: float = 0.0):
        self.name = name
        self.terminal = terminal
        self.host = host
        self.started = started


class TestLogParsingKeepsOnlyFacts:
    def test_failed_password(self) -> None:
        events = parse_auth_line(
            "Mar  1 12:00:00 h sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
            100.0,
        )
        assert [(e.kind, e.username) for e in events] == [("failed_auth", "admin")]

    def test_pam_authentication_failure(self) -> None:
        events = parse_auth_line(
            "Mar  1 12:00:00 h sshd[1]: pam_unix(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4 user=alice",
            100.0,
        )
        assert [(e.kind, e.username) for e in events] == [("failed_auth", "alice")]

    def test_sudo_use_is_counted(self) -> None:
        events = parse_auth_line(
            "Mar  1 12:00:01 h sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; "
            "USER=root ; COMMAND=/usr/bin/apt update",
            100.0,
        )
        assert [(e.kind, e.username) for e in events] == [("sudo", "alice")]

    def test_the_sudo_command_is_discarded(self) -> None:
        """Principle 5 applies to log text: `sudo mysql -pHUNTER2` is a secret."""
        line = (
            "Mar  1 12:00:01 h sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; "
            "USER=root ; COMMAND=/usr/bin/mysql -pHUNTER2 --host=internal.db"
        )
        events = parse_auth_line(line, 100.0)
        rendered = repr(events)
        assert "HUNTER2" not in rendered
        assert "mysql" not in rendered
        assert "internal.db" not in rendered

    def test_successful_logins_are_not_failures(self) -> None:
        assert parse_auth_line(
            "Mar  1 12:00:02 h sshd[2]: Accepted password for bob from 10.0.0.5 port 22 ssh2", 100.0
        ) == []

    def test_unrelated_lines_are_ignored(self) -> None:
        assert parse_auth_line("Mar  1 12:00:03 h CRON[9]: session opened", 100.0) == []

    def test_a_failure_is_counted_once(self) -> None:
        events = parse_auth_line(
            "Mar  1 12:00:00 h sshd[1]: Failed password for invalid user root from 1.2.3.4", 100.0
        )
        assert len(events) == 1


class TestUnknownIsNotZero:
    """Principle 1: an unreadable log yields None, never a reassuring zero."""

    def test_null_source_reports_none_not_zero(
        self, collector_context: CollectorContext, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            "ebabf.collectors.user_activity.psutil.users", lambda: [StubSession("alice")]
        )
        collector = UserActivityCollector(collector_context, auth_source=NullAuthSource())
        event = next(iter(collector.collect()))
        assert event.raw_attributes["failed_auth_count"] is None
        assert event.raw_attributes["sudo_usage_pattern"] is None
        assert event.raw_attributes["auth_log_readable"] is False

    def test_a_readable_log_with_no_failures_reports_zero(
        self, collector_context: CollectorContext, monkeypatch
    ) -> None:
        """Zero is a real measurement here, and must be distinguishable."""
        monkeypatch.setattr(
            "ebabf.collectors.user_activity.psutil.users", lambda: [StubSession("alice")]
        )
        collector = UserActivityCollector(collector_context, auth_source=StubAuthSource([]))
        event = next(iter(collector.collect()))
        assert event.raw_attributes["failed_auth_count"] == 0
        assert event.raw_attributes["auth_log_readable"] is True

    def test_source_selection_falls_back_to_null(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "ebabf.collectors.user_activity.JournaldAuthSource.is_available", lambda: False
        )
        monkeypatch.setattr(
            "ebabf.collectors.user_activity.AuthLogFileSource.is_available", lambda: False
        )
        assert isinstance(select_auth_source(), NullAuthSource)

    def test_a_broken_probe_is_just_unavailability(self, monkeypatch) -> None:
        def explode() -> bool:
            raise OSError("journalctl segfaulted")

        monkeypatch.setattr(
            "ebabf.collectors.user_activity.JournaldAuthSource.is_available", explode
        )
        monkeypatch.setattr(
            "ebabf.collectors.user_activity.AuthLogFileSource.is_available", lambda: False
        )
        assert isinstance(select_auth_source(), NullAuthSource)


class TestCollectorOutput:
    def test_declares_its_source(self) -> None:
        assert UserActivityCollector.source is EventSource.USER
        assert UserActivityCollector.name == "user_activity"

    def test_spec_5_4_fields_present(
        self, collector_context: CollectorContext, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            "ebabf.collectors.user_activity.psutil.users",
            lambda: [StubSession("alice", started=1_700_000_000.0)],
        )
        collector = UserActivityCollector(collector_context, auth_source=StubAuthSource([]))
        event = next(iter(collector.collect()))
        assert SPEC_5_4_FIELDS <= set(event.raw_attributes)

    def test_counts_are_per_user(
        self, collector_context: CollectorContext, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            "ebabf.collectors.user_activity.psutil.users",
            lambda: [StubSession("alice"), StubSession("bob")],
        )
        source = StubAuthSource(
            [
                AuthEvent("failed_auth", "alice", 100.0),
                AuthEvent("failed_auth", "alice", 101.0),
                AuthEvent("sudo", "bob", 102.0),
            ]
        )
        collector = UserActivityCollector(collector_context, auth_source=source)
        by_pseudonym = {e.subject_pseudonym: e.raw_attributes for e in collector.collect()}
        alice = collector_context.pseudonymizer.pseudonymize("alice")
        bob = collector_context.pseudonymizer.pseudonymize("bob")
        assert by_pseudonym[alice]["failed_auth_count"] == 2
        assert by_pseudonym[alice]["sudo_usage_pattern"] == 0
        assert by_pseudonym[bob]["sudo_usage_pattern"] == 1

    def test_brute_force_against_a_user_with_no_session_is_still_reported(
        self, collector_context: CollectorContext, monkeypatch
    ) -> None:
        """The brute-force case has no live session by definition."""
        monkeypatch.setattr("ebabf.collectors.user_activity.psutil.users", lambda: [])
        source = StubAuthSource(
            [AuthEvent("failed_auth", "root", 100.0 + n) for n in range(40)]
        )
        collector = UserActivityCollector(collector_context, auth_source=source)
        events = list(collector.collect())
        assert len(events) == 1
        assert events[0].raw_attributes["failed_auth_count"] == 40
        assert events[0].raw_attributes["session_duration"] is None

    def test_activity_hour_comes_from_the_clock(
        self, collector_context: CollectorContext, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            "ebabf.collectors.user_activity.psutil.users", lambda: [StubSession("alice")]
        )
        context = CollectorContext(
            host_id=collector_context.host_id,
            tenant_id=collector_context.tenant_id,
            pseudonymizer=collector_context.pseudonymizer,
            clock=lambda: datetime(2026, 3, 1, 3, 30, tzinfo=timezone.utc),
        )
        collector = UserActivityCollector(context, auth_source=StubAuthSource([]))
        assert next(iter(collector.collect())).raw_attributes["activity_hour"] == 3

    def test_remote_sessions_are_flagged(
        self, collector_context: CollectorContext, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            "ebabf.collectors.user_activity.psutil.users",
            lambda: [StubSession("alice", host="10.0.0.5"), StubSession("bob", host=":0")],
        )
        collector = UserActivityCollector(collector_context, auth_source=StubAuthSource([]))
        flags = {
            e.subject_pseudonym: e.raw_attributes["session_is_remote"]
            for e in collector.collect()
        }
        assert flags[collector_context.pseudonymizer.pseudonymize("alice")] is True
        assert flags[collector_context.pseudonymizer.pseudonymize("bob")] is False

    def test_an_unreadable_session_table_degrades_without_raising(
        self, collector_context: CollectorContext, monkeypatch
    ) -> None:
        def explode():
            raise OSError("utmp unreadable")

        monkeypatch.setattr("ebabf.collectors.user_activity.psutil.users", explode)
        collector = UserActivityCollector(collector_context, auth_source=StubAuthSource([]))
        assert list(collector.collect()) == []

    def test_events_are_unscored(
        self, collector_context: CollectorContext, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            "ebabf.collectors.user_activity.psutil.users", lambda: [StubSession("alice")]
        )
        collector = UserActivityCollector(collector_context, auth_source=StubAuthSource([]))
        event = next(iter(collector.collect()))
        assert event.raw_score is None and event.confidence is None


class TestAuthLogFileSource:
    def test_parses_a_log_file(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        log.write_text(
            "Mar  1 12:00:00 h sshd[1]: Failed password for admin from 1.2.3.4 port 22 ssh2\n"
            "Mar  1 12:00:01 h sudo:    alice : TTY=pts/0 ; COMMAND=/bin/ls\n"
            "Mar  1 12:00:02 h sshd[2]: Accepted password for bob from 10.0.0.5\n"
        )
        events = AuthLogFileSource(path=log).read_since(0.0)
        assert {(e.kind, e.username) for e in events} == {
            ("failed_auth", "admin"),
            ("sudo", "alice"),
        }

    def test_missing_file_yields_nothing(self, tmp_path: Path) -> None:
        assert AuthLogFileSource(path=tmp_path / "absent.log").read_since(0.0) == []
