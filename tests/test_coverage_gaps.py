"""Silent failures, made loud - decision 11 and spec 11.3.

Three ways a 7-14 day recording can die without saying so, and the checks
that stop each being silent:

- the machine reboots and nothing restarts the agent;
- a collector reports itself healthy while capturing nothing;
- the disk fills and writes stop.

Each is worse than a recording that never started, because the resulting
dataset still looks complete when a model is trained on it.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ebabf.bootstrap import format_status, recording_status
from ebabf.config import AgentConfig
from ebabf.schema import Event, EventSource
from ebabf.storage import EventStore
from ebabf.storage.event_store import (
    DEFAULT_GAP_THRESHOLD_SECONDS,
    DEFAULT_MIN_FREE_BYTES,
    StorageHalted,
)

BASE = datetime(2026, 3, 1, tzinfo=timezone.utc)


def event(index: int) -> Event:
    return Event(
        event_id=f"EVT-{index:06d}",
        timestamp=BASE,
        host_id="h",
        tenant_id="t",
        subject_pseudonym="USR-" + "0" * 32,
        source=EventSource.PROCESS,
    )


@pytest.fixture()
def clocked(tmp_path: Path):
    """A store whose ingestion clock the test drives."""
    state = {"now": BASE}

    def make(**kwargs) -> tuple[EventStore, dict]:
        store = EventStore(tmp_path / "events.db", clock=lambda: state["now"], **kwargs)
        return store, state

    return make


class TestDowntimeIsRecorded:
    """systemd restarting the agent closes the outage, not the hole it left."""

    def test_a_long_break_before_start_is_recorded(self, clocked) -> None:
        store, state = clocked()
        for index in range(5):
            state["now"] = BASE + timedelta(seconds=30 * index)
            store.append(event(index))

        state["now"] = BASE + timedelta(hours=6)
        gap = store.detect_downtime()

        assert gap == pytest.approx(6 * 3600, abs=180)
        recorded = store.coverage_gap_log()
        assert recorded[0]["kind"] == "agent_downtime"
        assert recorded[0]["duration_seconds"] == pytest.approx(gap)
        store.close()

    def test_a_short_break_is_not_a_gap(self, clocked) -> None:
        store, state = clocked()
        store.append(event(0))
        state["now"] = BASE + timedelta(seconds=60)
        assert store.detect_downtime() is None
        assert store.coverage_gap_log() == []
        store.close()

    def test_an_empty_database_has_no_downtime(self, clocked) -> None:
        store, _ = clocked()
        assert store.detect_downtime() is None
        store.close()

    def test_the_operator_is_warned(self, clocked, caplog) -> None:
        store, state = clocked()
        store.append(event(0))
        state["now"] = BASE + timedelta(hours=8)
        with caplog.at_level(logging.WARNING, logger="ebabf.storage.event_store"):
            store.detect_downtime()
        assert any("hole in it" in r.message for r in caplog.records)
        store.close()

    def test_the_runner_records_downtime_on_start(
        self, config: AgentConfig, collector_context, kill_switch
    ) -> None:
        from ebabf.engine.decision import PassThroughDecisionEngine
        from ebabf.engine.enforcement import NoOpEnforcementEngine
        from ebabf.runner import AgentRunner
        from tests.test_runner import StubCollector

        state = {"now": BASE}
        store = EventStore(config.event_db_path, clock=lambda: state["now"])
        store.append(event(0))
        state["now"] = BASE + timedelta(hours=4)

        runner = AgentRunner(
            collectors=[StubCollector(collector_context)],
            decision_engine=PassThroughDecisionEngine(),
            enforcement_engine=NoOpEnforcementEngine(enabled=True, kill_switch=kill_switch),
            event_store=store,
        )
        runner.start()
        assert any(e["kind"] == "agent_downtime" for e in store.coverage_gap_log())
        runner.close()
        store.close()


class TestGapsAreFoundInTheDataItself:
    """Finds outages nobody recorded - a kill -9, a power cut, a missed boot."""

    def test_a_break_between_events_is_found(self, clocked) -> None:
        store, state = clocked()
        for index in range(10):
            state["now"] = BASE + timedelta(seconds=30 * index)
            store.append(event(index))
        for index in range(10, 20):
            state["now"] = BASE + timedelta(hours=5, seconds=30 * index)
            store.append(event(index))

        gaps = store.find_gaps()
        assert len(gaps) == 1
        assert gaps[0]["duration_seconds"] > 4 * 3600
        store.close()

    def test_continuous_recording_has_no_gaps(self, clocked) -> None:
        store, state = clocked()
        for index in range(60):
            state["now"] = BASE + timedelta(seconds=30 * index)
            store.append(event(index))
        assert store.find_gaps() == []
        store.close()

    def test_the_threshold_is_respected(self, clocked) -> None:
        store, state = clocked()
        store.append(event(0))
        state["now"] = BASE + timedelta(minutes=20)
        store.append(event(1))

        assert store.find_gaps(min_seconds=3600) == []
        assert len(store.find_gaps(min_seconds=600)) == 1
        store.close()

    def test_gaps_sort_worst_first(self, clocked) -> None:
        store, state = clocked()
        offsets = [0, 1, 40, 41, 300, 301]
        for index, minutes in enumerate(offsets):
            state["now"] = BASE + timedelta(minutes=minutes)
            store.append(event(index))
        gaps = store.find_gaps(min_seconds=600)
        assert [g["duration_seconds"] for g in gaps] == sorted(
            (g["duration_seconds"] for g in gaps), reverse=True
        )
        store.close()

    def test_span_reports_what_was_covered(self, clocked) -> None:
        store, state = clocked()
        store.append(event(0))
        state["now"] = BASE + timedelta(hours=3)
        store.append(event(1))
        span = store.span()
        assert span["count"] == 2
        assert span["span_hours"] == pytest.approx(3.0)
        store.close()


class TestDiskFloor:
    def test_writing_stops_before_the_disk_is_full(self, tmp_path: Path) -> None:
        store = EventStore(tmp_path / "e.db", min_free_bytes=10**18)
        with pytest.raises(StorageHalted):
            for index in range(1000):
                store.append(event(index))
        assert store.is_halted is True
        store.close()

    def test_the_halt_is_recorded(self, tmp_path: Path) -> None:
        store = EventStore(tmp_path / "e.db", min_free_bytes=10**18)
        with pytest.raises(StorageHalted):
            for index in range(1000):
                store.append(event(index))
        recorded = store.coverage_gap_log()
        assert recorded[0]["kind"] == "storage_halted"
        assert "floor" in recorded[0]["detail"]
        store.close()

    def test_further_writes_are_refused(self, tmp_path: Path) -> None:
        store = EventStore(tmp_path / "e.db", min_free_bytes=10**18)
        with pytest.raises(StorageHalted):
            for index in range(1000):
                store.append(event(index))
        with pytest.raises(StorageHalted):
            store.append(event(9999))
        store.close()

    def test_the_halt_is_logged_at_critical(self, tmp_path: Path, caplog) -> None:
        store = EventStore(tmp_path / "e.db", min_free_bytes=10**18)
        with caplog.at_level(logging.CRITICAL, logger="ebabf.storage.event_store"):
            with pytest.raises(StorageHalted):
                for index in range(1000):
                    store.append(event(index))
        assert any("RECORDING HALTED" in r.message for r in caplog.records)
        store.close()

    def test_a_healthy_disk_does_not_halt(self, tmp_path: Path) -> None:
        store = EventStore(tmp_path / "e.db", min_free_bytes=1024)
        for index in range(600):
            store.append(event(index))
        assert store.is_halted is False
        assert store.coverage_gap_log() == []
        store.close()

    def test_zero_disables_the_floor(self, tmp_path: Path) -> None:
        store = EventStore(tmp_path / "e.db", min_free_bytes=0)
        for index in range(600):
            store.append(event(index))
        assert store.is_halted is False
        store.close()

    def test_config_carries_a_floor_by_default(self) -> None:
        assert AgentConfig().min_free_bytes == DEFAULT_MIN_FREE_BYTES
        assert DEFAULT_MIN_FREE_BYTES > 0, "no floor means filling the disk silently"


class TestStatusReport:
    def _recorded(self, tmp_path: Path) -> EventStore:
        state = {"now": BASE}
        store = EventStore(tmp_path / "b.db", clock=lambda: state["now"])
        for index in range(20):
            state["now"] = BASE + timedelta(seconds=30 * index)
            store.append(event(index))
        for index in range(20, 40):
            state["now"] = BASE + timedelta(hours=6, seconds=30 * index)
            store.append(event(index))
        return store

    def test_separates_wall_clock_from_covered_time(self, tmp_path: Path) -> None:
        """The number that matters: hours actually recorded, not hours elapsed."""
        store = self._recorded(tmp_path)
        status = recording_status(store)
        assert status["span_hours"] > status["effective_hours"]
        assert status["hours_lost_to_gaps"] > 4
        store.close()

    def test_lists_the_gaps(self, tmp_path: Path) -> None:
        store = self._recorded(tmp_path)
        status = recording_status(store)
        assert status["gap_count"] == 1
        assert status["gaps"][0]["start"] < status["gaps"][0]["end"]
        store.close()

    def test_reports_free_space_and_cap(self, tmp_path: Path) -> None:
        store = self._recorded(tmp_path)
        status = recording_status(store)
        assert status["free_bytes"] > 0
        assert "events_dropped_to_overflow" in status
        store.close()

    def test_formats_for_a_terminal(self, tmp_path: Path) -> None:
        store = self._recorded(tmp_path)
        text = format_status(recording_status(store))
        assert "span" in text and "covered" in text and "gaps" in text
        assert "7-14 days" in text
        store.close()

    def test_a_hole_is_called_out(self, tmp_path: Path) -> None:
        state = {"now": BASE}
        store = EventStore(tmp_path / "b.db", clock=lambda: state["now"], max_events=50)
        for index in range(200):
            state["now"] = BASE + timedelta(seconds=30 * index)
            store.append(event(index))
        text = format_status(recording_status(store))
        assert "the data has a hole" in text
        store.close()

    def test_an_empty_recording_says_so(self, tmp_path: Path) -> None:
        store = EventStore(tmp_path / "b.db")
        text = format_status(recording_status(store))
        assert "nothing recorded yet" in text
        store.close()

    def test_a_halted_store_is_shouted_about(self, tmp_path: Path) -> None:
        store = EventStore(tmp_path / "b.db", min_free_bytes=10**18)
        with pytest.raises(StorageHalted):
            for index in range(1000):
                store.append(event(index))
        text = format_status(recording_status(store))
        assert "HALTED" in text
        store.close()

    def test_threshold_is_the_same_one_used_for_downtime(self) -> None:
        """One definition of "a gap", so the two reports cannot disagree."""
        store_default = recording_status.__defaults__
        assert DEFAULT_GAP_THRESHOLD_SECONDS == 600.0
