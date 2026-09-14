"""Paths that touch the real operating system.

Everything else in the suite runs on stubs so it stays deterministic. These
tests exercise the parts that are only meaningful against the real thing: a
live inotify watch, the real socket table, an actual subprocess, and the
running loop.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

from ebabf.collectors.base import CollectorContext
from ebabf.collectors.filesystem import (
    FileMonitorCollector,
    WatchRoot,
    _count_directories,
    default_watch_roots,
)
from ebabf.collectors.network import (
    ScapyPacketSource,
    SocketOwnerResolver,
    _local_addresses,
)
from ebabf.collectors.registry import CollectorRegistry
from ebabf.collectors.user_activity import (
    AUTH_LOG_CANDIDATES,
    AuthLogFileSource,
    JournaldAuthSource,
)
from ebabf.config import AgentConfig
from ebabf.engine.decision import PassThroughDecisionEngine
from ebabf.engine.enforcement import NoOpEnforcementEngine
from ebabf.engine.killswitch import KillSwitch
from ebabf.runner import AgentRunner
from ebabf.storage import EventStore


def _wait_for(predicate, timeout: float = 5.0, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


class TestLiveFileWatching:
    """The file monitor against a real inotify watch."""

    @pytest.fixture()
    def watched(self, tmp_path: Path) -> Path:
        directory = tmp_path / "Documents"
        directory.mkdir()
        return directory

    def test_real_file_changes_are_observed(
        self, collector_context: CollectorContext, watched: Path
    ) -> None:
        collector = FileMonitorCollector(
            collector_context,
            roots=(WatchRoot(path=watched, label="alice:Documents", subject="alice"),),
        )
        collector.start()
        try:
            handler = collector._handlers["alice:Documents"]
            for index in range(12):
                (watched / f"file{index}.txt").write_text("content")
            assert _wait_for(lambda: handler._activity.total >= 12), "inotify saw nothing"

            events = list(collector.collect())
            assert len(events) == 1
            attributes = events[0].raw_attributes
            assert attributes["events_total"] >= 12
            assert attributes["file_modification_rate"] is not None
            assert attributes["watch_root_label"] == "alice:Documents"
        finally:
            collector.close()

    def test_a_burst_looks_like_a_burst(
        self, collector_context: CollectorContext, watched: Path
    ) -> None:
        """The ransomware signal: many files rewritten very fast."""
        collector = FileMonitorCollector(
            collector_context,
            roots=(WatchRoot(path=watched, label="docs", subject="alice"),),
        )
        collector.start()
        try:
            handler = collector._handlers["docs"]
            for index in range(200):
                (watched / f"doc{index}.dat").write_text("x" * 64)
            # Wait on distinct files, not on the event total: one write raises
            # several inotify events, so the total passes 200 first.
            assert _wait_for(
                lambda: len(handler._activity.distinct_paths) >= 200, timeout=10
            )

            event = next(iter(collector.collect()))
            assert event.raw_attributes["distinct_file_count"] >= 200
            assert event.raw_attributes["events_total"] >= 200
            assert event.raw_attributes["file_modification_rate"] > 10
        finally:
            collector.close()

    def test_no_file_content_appears_in_the_event(
        self, collector_context: CollectorContext, watched: Path
    ) -> None:
        collector = FileMonitorCollector(
            collector_context,
            roots=(WatchRoot(path=watched, label="docs", subject="alice"),),
        )
        collector.start()
        try:
            (watched / "secret.txt").write_text("BANK-ACCOUNT-9988776655")
            handler = collector._handlers["docs"]
            assert _wait_for(lambda: handler._activity.total >= 1)
            event = next(iter(collector.collect()))
            rendered = repr(dict(event.raw_attributes))
            assert "BANK-ACCOUNT" not in rendered
            assert "secret.txt" not in rendered
        finally:
            collector.close()

    def test_missing_roots_are_skipped_not_fatal(
        self, collector_context: CollectorContext, tmp_path: Path
    ) -> None:
        collector = FileMonitorCollector(
            collector_context,
            roots=(WatchRoot(path=tmp_path / "nope", label="absent", subject="alice"),),
        )
        collector.start()
        collector.close()

    def test_close_is_safe_without_start(
        self, collector_context: CollectorContext, watched: Path
    ) -> None:
        collector = FileMonitorCollector(
            collector_context, roots=(WatchRoot(watched, "docs", "alice"),)
        )
        collector.close()

    def test_watch_counting(self, tmp_path: Path) -> None:
        (tmp_path / "a" / "b" / "c").mkdir(parents=True)
        assert _count_directories(tmp_path) == 4
        assert _count_directories(tmp_path, cap=2) == 2

    def test_supported_when_inotify_present(self) -> None:
        assert FileMonitorCollector.is_supported() is os.path.exists(
            "/proc/sys/fs/inotify/max_user_watches"
        )

    def test_default_roots_do_not_raise_on_this_host(self) -> None:
        assert isinstance(default_watch_roots(), tuple)


class TestRealSocketTable:
    def test_local_addresses_include_loopback(self) -> None:
        addresses = _local_addresses()
        assert isinstance(addresses, frozenset)
        assert "127.0.0.1" in addresses

    def test_resolver_reads_the_socket_table(self) -> None:
        resolver = SocketOwnerResolver()
        resolver.refresh()
        assert isinstance(resolver._owners, dict)

    def test_resolver_attributes_a_socket_this_process_owns(self) -> None:
        import getpass
        import socket

        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            resolver = SocketOwnerResolver()
            resolver.refresh()
            if not resolver._owners:
                pytest.skip("socket table not readable in this environment")
            from ebabf.collectors.network import FlowKey

            key = FlowKey("tcp", "127.0.0.1", port, "127.0.0.1", 1)
            owner = resolver.owner_of(key)
            if owner is not None:
                assert owner == getpass.getuser()
        finally:
            server.close()

    def test_unknown_endpoints_resolve_to_none(self) -> None:
        from ebabf.collectors.network import FlowKey

        resolver = SocketOwnerResolver()
        resolver.refresh()
        assert resolver.owner_of(FlowKey("tcp", "203.0.113.9", 9, "203.0.113.10", 9)) is None

    def test_capture_availability_is_answered_without_raising(self) -> None:
        available, reason = ScapyPacketSource.is_available()
        assert isinstance(available, bool) and isinstance(reason, str)


class TestAuthSources:
    def test_journald_probe_answers(self) -> None:
        assert isinstance(JournaldAuthSource.is_available(), bool)

    def test_journald_read_survives_a_failing_subprocess(self, monkeypatch) -> None:
        def explode(*args, **kwargs):
            raise OSError("journalctl missing")

        monkeypatch.setattr(subprocess, "run", explode)
        assert JournaldAuthSource().read_since(0.0) == []

    def test_journald_parses_json_lines(self, monkeypatch) -> None:
        payload = "\n".join(
            json.dumps(
                {
                    "MESSAGE": "Failed password for invalid user admin from 1.2.3.4",
                    "__REALTIME_TIMESTAMP": "1700000000000000",
                }
            )
            for _ in range(3)
        )

        class Result:
            returncode = 0
            stdout = payload

        monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
        events = JournaldAuthSource().read_since(0.0)
        assert len(events) == 3
        assert all(e.kind == "failed_auth" and e.username == "admin" for e in events)

    def test_journald_ignores_unparseable_lines(self, monkeypatch) -> None:
        class Result:
            returncode = 0
            stdout = "not json\n{}\n"

        monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
        assert JournaldAuthSource().read_since(0.0) == []

    def test_journald_non_zero_exit_yields_nothing(self, monkeypatch) -> None:
        class Result:
            returncode = 1
            stdout = ""

        monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
        assert JournaldAuthSource().read_since(0.0) == []

    def test_auth_log_discovery_picks_a_readable_candidate(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        log = tmp_path / "auth.log"
        log.write_text("Mar  1 12:00:00 h sudo:    alice : COMMAND=/bin/ls\n")
        monkeypatch.setattr(
            "ebabf.collectors.user_activity.AUTH_LOG_CANDIDATES",
            (str(tmp_path / "absent.log"), str(log)),
        )
        assert AuthLogFileSource.is_available() is True
        assert AuthLogFileSource()._path == log

    def test_auth_log_discovery_returns_none_when_unreadable(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            "ebabf.collectors.user_activity.AUTH_LOG_CANDIDATES",
            (str(tmp_path / "absent.log"),),
        )
        assert AuthLogFileSource.is_available() is False
        assert AuthLogFileSource().read_since(0.0) == []

    def test_candidates_cover_debian_and_rhel(self) -> None:
        assert "/var/log/auth.log" in AUTH_LOG_CANDIDATES  # Debian, Ubuntu
        assert "/var/log/secure" in AUTH_LOG_CANDIDATES  # RHEL, Fedora


class TestRunLoop:
    def test_run_forever_sweeps_until_stopped(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        from tests.test_runner import StubCollector

        runner = AgentRunner(
            collectors=[StubCollector(collector_context, count=2)],
            decision_engine=PassThroughDecisionEngine(),
            enforcement_engine=NoOpEnforcementEngine(enabled=True, kill_switch=kill_switch),
            event_store=event_store,
        )
        thread = threading.Thread(
            target=runner.run_forever, kwargs={"interval_seconds": 0.05}, daemon=True
        )
        thread.start()
        assert _wait_for(lambda: event_store.count() >= 4), "loop produced nothing"
        runner.stop()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert event_store.count() >= 4

    def test_stopping_closes_the_collectors(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        from tests.test_runner import StubCollector

        collector = StubCollector(collector_context, count=1)
        runner = AgentRunner(
            collectors=[collector],
            decision_engine=PassThroughDecisionEngine(),
            enforcement_engine=NoOpEnforcementEngine(enabled=True, kill_switch=kill_switch),
            event_store=event_store,
        )
        thread = threading.Thread(
            target=runner.run_forever, kwargs={"interval_seconds": 0.05}, daemon=True
        )
        thread.start()
        assert _wait_for(lambda: collector.sweeps >= 1)
        runner.stop()
        thread.join(timeout=5)
        assert collector.closed is True

    def test_signal_handlers_are_skipped_off_the_main_thread(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        """Installing them off-main raises ValueError; the loop must not die."""
        from tests.test_runner import StubCollector

        runner = AgentRunner(
            collectors=[StubCollector(collector_context, count=1)],
            decision_engine=PassThroughDecisionEngine(),
            enforcement_engine=NoOpEnforcementEngine(enabled=True, kill_switch=kill_switch),
            event_store=event_store,
        )
        error: list[BaseException] = []

        def run() -> None:
            try:
                runner.run_forever(interval_seconds=0.05)
            except BaseException as exc:  # noqa: BLE001
                error.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        assert _wait_for(lambda: event_store.count() >= 1)
        runner.stop()
        thread.join(timeout=5)
        assert error == []


class TestCli:
    def test_coverage_subcommand(self, config: AgentConfig, monkeypatch, capsys) -> None:
        from ebabf import bootstrap
        from tests.test_runner import StubCollector

        registry = CollectorRegistry()
        registry.register(StubCollector)
        monkeypatch.setattr(bootstrap, "AgentConfig", lambda: config)
        monkeypatch.setattr(bootstrap, "default_registry", registry)

        assert bootstrap.main(["coverage"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["active"] == ["stub"]
        assert payload["is_complete"] is True

    def test_baseline_disables_enforcement(
        self, config: AgentConfig, tmp_path: Path, monkeypatch
    ) -> None:
        """A baseline is recorded on a machine known to be clean; blocking
        anything there would poison the very data being gathered."""
        from ebabf import bootstrap

        captured: dict[str, object] = {}
        real_build = bootstrap.build_agent

        def spy(cfg, **kwargs):
            captured["enforcement_enabled"] = cfg.enforcement_enabled
            captured["event_db_path"] = kwargs.get("event_db_path")
            runner, identity_store, event_store = real_build(cfg, **kwargs)
            runner.stop()
            return runner, identity_store, event_store

        registry = CollectorRegistry()
        from tests.test_runner import StubCollector

        registry.register(StubCollector)
        monkeypatch.setattr(bootstrap, "AgentConfig", lambda: config)
        monkeypatch.setattr(bootstrap, "default_registry", registry)
        monkeypatch.setattr(bootstrap, "build_agent", spy)

        baseline_db = tmp_path / "baseline.db"
        assert bootstrap.main(["--interval", "0.05", "baseline", "--db", str(baseline_db)]) == 0
        assert captured["enforcement_enabled"] is False
        assert captured["event_db_path"] == baseline_db


class TestStoresAreThreadSafe:
    """The agent sweeps from a worker thread; the stores are opened elsewhere.

    A connection pinned to its creating thread crashes there, which is how
    this was found - `run_forever` in a background thread hit
    sqlite3.ProgrammingError before these tests existed.
    """

    def test_events_can_be_written_from_another_thread(
        self, event_store: EventStore
    ) -> None:
        from tests.conftest import make_event

        errors: list[BaseException] = []

        def write(index: int) -> None:
            try:
                event_store.append(make_event(event_id=f"EVT-{index:05d}"))
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=write, args=(i,)) for i in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert errors == [], f"cross-thread write failed: {errors[:1]}"
        assert event_store.count() == 20

    def test_pseudonyms_can_be_minted_from_another_thread(self, pseudonymizer) -> None:
        errors: list[BaseException] = []
        minted: list[str] = []

        def mint(name: str) -> None:
            try:
                minted.append(pseudonymizer.pseudonymize(name))
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=mint, args=(f"user{i}",)) for i in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert errors == [], f"cross-thread mint failed: {errors[:1]}"
        assert len(set(minted)) == 20

    def test_concurrent_mints_for_one_subject_stay_stable(self, pseudonymizer) -> None:
        """The lock must not let two threads mint two pseudonyms for one person."""
        results: list[str] = []
        barrier = threading.Barrier(16)

        def mint() -> None:
            barrier.wait()
            results.append(pseudonymizer.pseudonymize("alice"))

        threads = [threading.Thread(target=mint) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert len(set(results)) == 1, "the same subject got more than one pseudonym"
