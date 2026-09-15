"""File monitor - spec 5.3, minus the field the privacy principle forbids."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ebabf.collectors.base import CollectorContext
from ebabf.collectors.filesystem import (
    SENSITIVE_CATEGORIES,
    FileActivity,
    FileMonitorCollector,
    WatchRoot,
    _BufferingHandler,
    _KNOWN_NON_MUTATION_EVENTS,
    classify_sensitive,
    default_watch_roots,
    read_inotify_limit,
)
from ebabf.schema import EventSource


def _roots(tmp_path: Path) -> tuple[WatchRoot, ...]:
    documents = tmp_path / "home" / "alice" / "Documents"
    documents.mkdir(parents=True)
    return (
        WatchRoot(path=documents, label="alice:Documents", subject="alice"),
    )


@pytest.fixture()
def collector(collector_context: CollectorContext, tmp_path: Path) -> FileMonitorCollector:
    return FileMonitorCollector(collector_context, roots=_roots(tmp_path))


class TestEntropyIsNotImplemented:
    """D-010: principle 5 wins over the feature in spec 5.3."""

    def test_no_entropy_field_is_produced(
        self, collector: FileMonitorCollector, collector_context: CollectorContext
    ) -> None:
        handler = collector._handlers["alice:Documents"]
        for index in range(5):
            handler.record("modified", f"/home/alice/Documents/f{index}.docx", now=1000.0 + index)
        collector._last_sweep = 999.0
        event = next(iter(collector.collect()))
        assert "file_entropy_change" not in event.raw_attributes

    def test_no_file_is_ever_opened(self) -> None:
        """The collector reads directory events, never file contents."""
        import ebabf.collectors.filesystem as module

        source = Path(module.__file__).read_text()
        for forbidden in (".read_bytes()", ".read_text()", "open(", "mmap"):
            if forbidden == ".read_text()":
                # read_inotify_limit reads one kernel tunable, not a user file.
                assert source.count(forbidden) == 1, forbidden
            else:
                assert forbidden not in source.replace("path.open(", ""), forbidden


class TestSensitivePathClassification:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/etc/passwd", "system_config"),
            ("/etc/systemd/system/x.service", "system_config"),
            ("/home/alice/.ssh/authorized_keys", "ssh_keys"),
            ("/home/alice/.config/autostart/evil.desktop", "autostart"),
            ("/home/bob/.bashrc", "shell_init"),
            ("/home/alice/Documents/report.docx", None),
            ("/tmp/scratch", None),
        ],
    )
    def test_categories(self, path: str, expected: str | None) -> None:
        assert classify_sensitive(path) == expected

    def test_every_spec_5_3_location_is_covered(self) -> None:
        """Spec 5.3 names /etc, ~/.ssh and autostart explicitly."""
        assert {"system_config", "ssh_keys", "autostart"} <= set(SENSITIVE_CATEGORIES)


class TestActivityCounting:
    def test_counts_by_operation(self, tmp_path: Path) -> None:
        handler = _BufferingHandler(WatchRoot(tmp_path, "x", "alice"))
        handler.record("created", "/a/1", now=1000.0)
        handler.record("modified", "/a/2", now=1000.1)
        handler.record("modified", "/a/2", now=1000.2)
        handler.record("deleted", "/a/3", now=1000.3)
        handler.record("moved", "/a/4", now=1000.4)

        activity = handler.drain()
        assert (activity.created, activity.modified, activity.deleted, activity.moved) == (1, 2, 1, 1)
        assert activity.total == 5
        assert len(activity.distinct_paths) == 4

    def test_drain_resets(self, tmp_path: Path) -> None:
        handler = _BufferingHandler(WatchRoot(tmp_path, "x", "alice"))
        handler.record("modified", "/a/1")
        assert handler.drain().total == 1
        assert handler.drain().total == 0

    def test_sensitive_categories_accumulate(self, tmp_path: Path) -> None:
        handler = _BufferingHandler(WatchRoot(tmp_path, "x", "alice"))
        handler.record("modified", "/home/alice/.ssh/id_rsa")
        handler.record("created", "/home/alice/.config/autostart/x.desktop")
        handler.record("modified", "/home/alice/Documents/a.txt")
        assert handler.drain().sensitive_categories == {"ssh_keys", "autostart"}


class TestPathsAreNotStored:
    """Spec 11.2 tier 3 treats paths as identifying; so does this collector."""

    def test_filenames_do_not_reach_the_activity_record(self, tmp_path: Path) -> None:
        handler = _BufferingHandler(WatchRoot(tmp_path, "x", "alice"))
        handler.record("modified", "/home/alice/Documents/divorce-settlement.pdf")
        activity = handler.drain()
        assert "divorce-settlement" not in repr(activity)
        assert activity.total == 1
        assert len(activity.distinct_paths) == 1

    def test_filenames_do_not_reach_the_event(
        self, collector: FileMonitorCollector
    ) -> None:
        handler = collector._handlers["alice:Documents"]
        handler.record("modified", "/home/alice/Documents/salary-negotiation.xlsx", now=1000.0)
        collector._last_sweep = 999.0
        event = next(iter(collector.collect()))
        rendered = repr(dict(event.raw_attributes))
        assert "salary-negotiation" not in rendered
        assert event.raw_attributes["watch_root_label"] == "alice:Documents"


class TestCollectorOutput:
    def test_declares_its_source(self) -> None:
        assert FileMonitorCollector.source is EventSource.FILE
        assert FileMonitorCollector.name == "file"

    def test_spec_5_3_fields_present(self, collector: FileMonitorCollector) -> None:
        collector._handlers["alice:Documents"].record("modified", "/home/alice/Documents/a", now=1000.0)
        collector._last_sweep = 999.0
        event = next(iter(collector.collect()))
        assert "sensitive_path_write" in event.raw_attributes
        assert "file_modification_rate" in event.raw_attributes

    def test_quiet_roots_emit_nothing(self, collector: FileMonitorCollector) -> None:
        collector._last_sweep = 999.0
        assert list(collector.collect()) == []

    def test_one_event_per_root_not_per_file(self, collector: FileMonitorCollector) -> None:
        """A mass-encryption run must not bury its own signal in 5,000 events."""
        handler = collector._handlers["alice:Documents"]
        for index in range(5000):
            handler.record("modified", f"/home/alice/Documents/f{index}.docx", now=1000.0)
        collector._last_sweep = 999.0

        events = list(collector.collect())
        assert len(events) == 1
        assert events[0].raw_attributes["events_total"] == 5000
        assert events[0].raw_attributes["distinct_file_count"] == 5000

    def test_modification_rate_reflects_the_window(
        self, collector_context: CollectorContext, tmp_path: Path
    ) -> None:
        from datetime import datetime, timedelta, timezone

        base = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        offset = {"seconds": 0}
        context = CollectorContext(
            host_id=collector_context.host_id,
            tenant_id=collector_context.tenant_id,
            pseudonymizer=collector_context.pseudonymizer,
            clock=lambda: base + timedelta(seconds=offset["seconds"]),
        )
        collector = FileMonitorCollector(context, roots=_roots(tmp_path))
        list(collector.collect())  # establishes the window start
        offset["seconds"] = 10

        for index in range(100):
            collector._handlers["alice:Documents"].record("modified", f"/a/{index}")
        event = next(iter(collector.collect()))
        assert event.raw_attributes["file_modification_rate"] == pytest.approx(10.0)
        assert event.raw_attributes["window_seconds"] == pytest.approx(10.0)

    def test_sensitive_write_is_flagged(self, collector: FileMonitorCollector) -> None:
        collector._handlers["alice:Documents"].record(
            "created", "/home/alice/.config/autostart/persist.desktop", now=1000.0
        )
        collector._last_sweep = 999.0
        event = next(iter(collector.collect()))
        assert event.raw_attributes["sensitive_path_write"] is True
        assert event.raw_attributes["sensitive_categories"] == ["autostart"]

    def test_events_are_unscored(self, collector: FileMonitorCollector) -> None:
        collector._handlers["alice:Documents"].record("modified", "/a/1", now=1000.0)
        collector._last_sweep = 999.0
        event = next(iter(collector.collect()))
        assert event.raw_score is None and event.decision is None

    def test_attributed_to_the_root_owner(self, collector: FileMonitorCollector) -> None:
        """inotify cannot say who acted, so attribution is by path ownership."""
        collector._handlers["alice:Documents"].record("modified", "/a/1", now=1000.0)
        collector._last_sweep = 999.0
        event = next(iter(collector.collect()))
        expected = collector._context.pseudonymizer.pseudonymize("alice")
        assert event.subject_pseudonym == expected


class TestWatchBudget:
    def test_limit_is_readable_on_linux(self) -> None:
        limit = read_inotify_limit()
        assert limit is None or limit > 0

    def test_warns_when_near_the_limit(self, collector: FileMonitorCollector, caplog) -> None:
        import logging

        collector._watch_count = 10**9
        with caplog.at_level(logging.WARNING, logger="ebabf.collectors.filesystem"):
            collector._warn_if_near_watch_limit()
        if read_inotify_limit() is not None:
            assert any("inotify" in r.message for r in caplog.records)


class TestDefaultRoots:
    def test_system_paths_are_host_attributed(self) -> None:
        roots = default_watch_roots()
        system = [r for r in roots if r.label == "system_config"]
        if system:
            assert system[0].subject == "__host__"

    def test_home_roots_are_user_attributed(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        (home / "alice" / "Documents").mkdir(parents=True)
        (home / "alice" / ".ssh").mkdir(parents=True)
        roots = default_watch_roots(home_parent=home)
        labels = {r.label: r.subject for r in roots}
        assert labels.get("alice:Documents") == "alice"
        assert labels.get("alice:.ssh") == "alice"

    def test_documents_are_watched_because_ransomware_encrypts_there(
        self, tmp_path: Path
    ) -> None:
        home = tmp_path / "home"
        (home / "bob" / "Documents").mkdir(parents=True)
        assert any(r.label == "bob:Documents" for r in default_watch_roots(home_parent=home))


class TestOnlyMutationsAreCounted:
    """Regression: reads were being counted as modifications.

    watchdog emits `opened`, `closed` and `closed_no_write` alongside the four
    mutation types. The handler used to fold every unrecognised type into
    `modified`, so reading 20 files registered as 40 modifications - a backup
    job or a recursive grep looked exactly like mass encryption.
    """

    def test_reads_are_not_modifications(self, tmp_path: Path) -> None:
        handler = _BufferingHandler(WatchRoot(tmp_path, "docs", "alice"))
        for index in range(20):
            handler.record("opened", f"/home/alice/Documents/f{index}.txt")
            handler.record("closed_no_write", f"/home/alice/Documents/f{index}.txt")

        activity = handler.drain()
        assert activity.total == 0, "reading files must not register as modification"
        assert activity.modified == 0
        assert activity.distinct_paths == set()
        assert activity.ignored == 40

    def test_closing_after_a_write_is_not_a_second_modification(
        self, tmp_path: Path
    ) -> None:
        handler = _BufferingHandler(WatchRoot(tmp_path, "docs", "alice"))
        for event_type in ("created", "opened", "modified", "closed"):
            handler.record(event_type, "/home/alice/Documents/a.txt")

        activity = handler.drain()
        assert (activity.created, activity.modified) == (1, 1)
        assert activity.total == 2
        assert activity.ignored == 2

    def test_mutation_types_come_from_watchdog_not_from_memory(self) -> None:
        from watchdog.events import (
            EVENT_TYPE_CREATED,
            EVENT_TYPE_DELETED,
            EVENT_TYPE_MODIFIED,
            EVENT_TYPE_MOVED,
        )

        from ebabf.collectors.filesystem import MUTATION_EVENTS

        assert set(MUTATION_EVENTS) == {
            EVENT_TYPE_CREATED,
            EVENT_TYPE_DELETED,
            EVENT_TYPE_MODIFIED,
            EVENT_TYPE_MOVED,
        }

    def test_no_current_watchdog_event_type_is_unhandled(self) -> None:
        """Every type this watchdog can emit is either a mutation or known."""
        import watchdog.events as events

        from ebabf.collectors.filesystem import (
            _KNOWN_NON_MUTATION_EVENTS,
            MUTATION_EVENTS,
        )

        emitted = {
            getattr(events, name)
            for name in dir(events)
            if name.startswith("EVENT_TYPE_")
        }
        unaccounted = emitted - set(MUTATION_EVENTS) - _KNOWN_NON_MUTATION_EVENTS
        assert unaccounted == set(), (
            f"watchdog can emit {sorted(unaccounted)}, which this collector "
            "classifies neither as a mutation nor as a known non-mutation"
        )

    def test_an_unknown_type_is_warned_about_not_absorbed(
        self, tmp_path: Path, caplog
    ) -> None:
        """A future watchdog type must be loud, not quietly counted."""
        import logging

        handler = _BufferingHandler(WatchRoot(tmp_path, "docs", "alice"))
        with caplog.at_level(logging.WARNING, logger="ebabf.collectors.filesystem"):
            handler.record("teleported", "/home/alice/Documents/a.txt")

        activity = handler.drain()
        assert activity.total == 0
        assert activity.ignored == 1
        assert any("unrecognised event type" in r.message for r in caplog.records)

    def test_the_warning_fires_once_per_type(self, tmp_path: Path, caplog) -> None:
        import logging

        handler = _BufferingHandler(WatchRoot(tmp_path, "docs", "alice"))
        with caplog.at_level(logging.WARNING, logger="ebabf.collectors.filesystem"):
            for _ in range(50):
                handler.record("teleported", "/a/b")
        assert len([r for r in caplog.records if "unrecognised" in r.message]) == 1

    def test_known_non_mutations_do_not_warn(self, tmp_path: Path, caplog) -> None:
        import logging

        handler = _BufferingHandler(WatchRoot(tmp_path, "docs", "alice"))
        with caplog.at_level(logging.WARNING, logger="ebabf.collectors.filesystem"):
            handler.record("opened", "/a/b")
            handler.record("closed", "/a/b")
        assert [r for r in caplog.records if "unrecognised" in r.message] == []

    def test_the_rate_measures_mutations_only(
        self, collector_context: CollectorContext, tmp_path: Path
    ) -> None:
        from datetime import timedelta

        base = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        offset = {"seconds": 0}
        context = CollectorContext(
            host_id=collector_context.host_id,
            tenant_id=collector_context.tenant_id,
            pseudonymizer=collector_context.pseudonymizer,
            clock=lambda: base + timedelta(seconds=offset["seconds"]),
        )
        collector = FileMonitorCollector(context, roots=_roots(tmp_path))
        list(collector.collect())
        offset["seconds"] = 10

        handler = collector._handlers["alice:Documents"]
        for index in range(10):
            handler.record("modified", f"/a/{index}")
        for index in range(500):  # a scan reading a lot of files
            handler.record("opened", f"/a/{index}")

        event = next(iter(collector.collect()))
        assert event.raw_attributes["file_modification_rate"] == pytest.approx(1.0)
        assert event.raw_attributes["ignored_events"] == 500


class TestBlindRootsAreDeclared:
    """A root that cannot be watched produces the same silence as a quiet one.

    Without this list, a sandbox or a permission change that hid /home would
    read as an uneventful fortnight.
    """

    def test_a_missing_root_is_declared(
        self, collector_context: CollectorContext, tmp_path: Path
    ) -> None:
        collector = FileMonitorCollector(
            collector_context,
            roots=(WatchRoot(tmp_path / "absent", "gone", "alice"),),
        )
        collector.start()
        try:
            assert collector.watched_root_count == 0
            assert collector.unwatchable_roots[0][0] == "gone"
            assert "does not exist" in collector.unwatchable_roots[0][1]
        finally:
            collector.close()

    def test_a_file_where_a_directory_was_expected(
        self, collector_context: CollectorContext, tmp_path: Path
    ) -> None:
        target = tmp_path / "not-a-dir"
        target.write_text("x")
        collector = FileMonitorCollector(
            collector_context, roots=(WatchRoot(target, "wrong", "alice"),)
        )
        collector.start()
        try:
            assert "not a directory" in collector.unwatchable_roots[0][1]
        finally:
            collector.close()

    def test_watchable_roots_are_not_listed(
        self, collector_context: CollectorContext, tmp_path: Path
    ) -> None:
        good = tmp_path / "Documents"
        good.mkdir()
        collector = FileMonitorCollector(
            collector_context, roots=(WatchRoot(good, "docs", "alice"),)
        )
        collector.start()
        try:
            assert collector.unwatchable_roots == ()
            assert collector.watched_root_count == 1
        finally:
            collector.close()

    def test_a_mix_is_reported_precisely(
        self, collector_context: CollectorContext, tmp_path: Path
    ) -> None:
        good = tmp_path / "ok"
        good.mkdir()
        collector = FileMonitorCollector(
            collector_context,
            roots=(
                WatchRoot(good, "ok", "alice"),
                WatchRoot(tmp_path / "absent", "gone", "alice"),
            ),
        )
        collector.start()
        try:
            assert collector.watched_root_count == 1
            assert [label for label, _ in collector.unwatchable_roots] == ["gone"]
        finally:
            collector.close()

    def test_the_gap_is_logged(
        self, collector_context: CollectorContext, tmp_path: Path, caplog
    ) -> None:
        import logging

        collector = FileMonitorCollector(
            collector_context, roots=(WatchRoot(tmp_path / "absent", "gone", "alice"),)
        )
        with caplog.at_level(logging.WARNING, logger="ebabf.collectors.filesystem"):
            collector.start()
        collector.close()
        assert any("file coverage gap" in r.message for r in caplog.records)
