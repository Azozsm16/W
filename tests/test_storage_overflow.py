"""Bounded growth and recorded drops - spec 11.3.

"Local storage full -> drop the oldest low-severity events first, and record
the drop." The recording half is the part that matters: a store that silently
discarded a week of a baseline still looks complete when you come to train on
it.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ebabf.config import AgentConfig
from ebabf.schema import Event, EventSource, RiskLevel
from ebabf.storage import EventStore
from ebabf.storage.event_store import DEFAULT_MAX_EVENTS

BASE = datetime(2026, 3, 1, tzinfo=timezone.utc)


def event(index: int, level: RiskLevel | None = None) -> Event:
    return Event(
        event_id=f"EVT-{index:06d}",
        timestamp=BASE,
        host_id="h",
        tenant_id="t",
        subject_pseudonym="USR-" + "0" * 32,
        source=EventSource.PROCESS,
        level=level,
        confidence=0.9 if level is not None else None,
    )


@pytest.fixture()
def ticking_store(tmp_path: Path):
    """A store whose ingestion clock advances one second per append."""

    def make(max_events: int | None) -> EventStore:
        counter = {"n": 0}

        def clock() -> datetime:
            counter["n"] += 1
            return BASE + timedelta(seconds=counter["n"])

        return EventStore(tmp_path / "events.db", clock=clock, max_events=max_events)

    return make


class TestCapIsEnforced:
    def test_row_count_stays_under_the_cap(self, ticking_store) -> None:
        store = ticking_store(100)
        for index in range(400):
            store.append(event(index))
        assert store.count() <= 100
        store.close()

    def test_unbounded_when_cap_is_zero(self, ticking_store) -> None:
        """An explicit choice for a machine with disk to spare."""
        store = ticking_store(0)
        for index in range(300):
            store.append(event(index))
        assert store.count() == 300
        assert store.drop_log() == []
        assert store.max_events is None
        store.close()

    def test_unbounded_when_unset(self, tmp_path: Path) -> None:
        store = EventStore(tmp_path / "events.db")
        for index in range(200):
            store.append(event(index))
        assert store.count() == 200
        assert store.max_events is None
        store.close()

    def test_nothing_is_dropped_below_the_cap(self, ticking_store) -> None:
        store = ticking_store(100)
        for index in range(90):
            store.append(event(index))
        assert store.count() == 90
        assert store.dropped_event_count() == 0
        store.close()

    def test_the_count_survives_reopening(self, tmp_path: Path) -> None:
        """The cached counter is seeded from the table, not from zero."""
        first = EventStore(tmp_path / "events.db", max_events=100)
        for index in range(80):
            first.append(event(index))
        first.close()

        second = EventStore(tmp_path / "events.db", max_events=100)
        for index in range(80, 140):
            second.append(event(index))
        assert second.count() <= 100
        assert second.dropped_event_count() > 0
        second.close()


class TestSeverityOrdering:
    """Spec 11.3: the low-severity events go first."""

    def test_critical_survives_while_lower_exists(self, ticking_store) -> None:
        store = ticking_store(100)
        for index in range(50):
            store.append(event(index, RiskLevel.CRITICAL))
        for index in range(50, 200):
            store.append(event(index, RiskLevel.NORMAL))

        survivors = store.query(limit=500)
        assert sum(1 for e in survivors if e.level is RiskLevel.CRITICAL) == 50
        store.close()

    def test_oldest_critical_outranks_newest_normal(self, ticking_store) -> None:
        """Severity comes before age: the ordering is not simply FIFO."""
        store = ticking_store(50)
        store.append(event(0, RiskLevel.CRITICAL))  # the oldest row of all
        for index in range(1, 150):
            store.append(event(index, RiskLevel.NORMAL))

        assert store.get("EVT-000000") is not None
        store.close()

    @pytest.mark.parametrize(
        ("kept", "dropped"),
        [
            (RiskLevel.LOW, RiskLevel.NORMAL),
            (RiskLevel.MEDIUM, RiskLevel.LOW),
            (RiskLevel.HIGH, RiskLevel.MEDIUM),
            (RiskLevel.CRITICAL, RiskLevel.HIGH),
        ],
    )
    def test_each_band_outranks_the_one_below(
        self, ticking_store, kept: RiskLevel, dropped: RiskLevel
    ) -> None:
        store = ticking_store(100)
        for index in range(60):
            store.append(event(index, kept))
        for index in range(60, 200):
            store.append(event(index, dropped))

        survivors = store.query(limit=500)
        assert sum(1 for e in survivors if e.level is kept) == 60
        store.close()

    def test_unscored_ranks_between_low_and_medium(self, ticking_store) -> None:
        """Nothing judged it, so it is neither treated as boring nor as urgent."""
        store = ticking_store(100)
        for index in range(40):
            store.append(event(index, RiskLevel.MEDIUM))
        for index in range(40, 80):
            store.append(event(index, None))
        for index in range(80, 250):
            store.append(event(index, RiskLevel.LOW))

        survivors = store.query(limit=500)
        levels = [e.level for e in survivors]
        assert levels.count(RiskLevel.MEDIUM) == 40, "medium must outlive unscored"
        assert levels.count(None) == 40, "unscored must outlive low"
        store.close()

    def test_all_unscored_degrades_to_oldest_first(self, ticking_store) -> None:
        """Today every event is unscored, so this is what actually runs."""
        store = ticking_store(100)
        for index in range(200):
            store.append(event(index))

        survivors = {e.event_id for e in store.query(limit=500)}
        assert "EVT-000199" in survivors, "the newest must survive"
        assert "EVT-000000" not in survivors, "the oldest must go first"
        store.close()


class TestTheDropIsRecorded:
    def test_drop_log_captures_what_was_lost(self, ticking_store) -> None:
        store = ticking_store(100)
        for index in range(200):
            store.append(event(index, RiskLevel.NORMAL))

        entries = store.drop_log()
        assert entries, "a drop must leave a record"
        entry = entries[0]
        assert entry["event_count"] > 0
        assert entry["level_breakdown"] == {"normal": entry["event_count"]}
        assert entry["oldest_ingested_at"] <= entry["newest_ingested_at"]
        assert "max_events" in entry["reason"]
        store.close()

    def test_breakdown_names_unscored_explicitly(self, ticking_store) -> None:
        store = ticking_store(100)
        for index in range(200):
            store.append(event(index))
        assert "unscored" in store.drop_log()[0]["level_breakdown"]
        store.close()

    def test_total_dropped_is_reported(self, ticking_store) -> None:
        store = ticking_store(100)
        for index in range(300):
            store.append(event(index))
        assert store.dropped_event_count() == 300 - store.count()
        store.close()

    def test_an_intact_store_reports_zero(self, ticking_store) -> None:
        """Non-zero is the signal that the data has a hole in it."""
        store = ticking_store(1000)
        for index in range(50):
            store.append(event(index))
        assert store.dropped_event_count() == 0
        store.close()

    def test_the_drop_is_logged_loudly(self, ticking_store, caplog) -> None:
        store = ticking_store(100)
        with caplog.at_level(logging.WARNING, logger="ebabf.storage.event_store"):
            for index in range(200):
                store.append(event(index))
        messages = [r.message for r in caplog.records if "storage full" in r.message]
        assert messages
        assert "incomplete" in messages[0]
        store.close()

    def test_the_record_outlives_the_process(self, tmp_path: Path) -> None:
        first = EventStore(tmp_path / "events.db", max_events=100)
        for index in range(200):
            first.append(event(index))
        dropped = first.dropped_event_count()
        first.close()

        second = EventStore(tmp_path / "events.db", max_events=100)
        assert second.dropped_event_count() == dropped
        assert second.drop_log()
        second.close()


class TestWiring:
    def test_config_carries_a_default_cap(self) -> None:
        assert AgentConfig().max_stored_events == DEFAULT_MAX_EVENTS
        assert DEFAULT_MAX_EVENTS > 0, "an unbounded default would fill the disk"

    def test_build_agent_applies_the_cap(self, config: AgentConfig) -> None:
        from dataclasses import replace

        from ebabf.bootstrap import build_agent
        from ebabf.collectors.registry import CollectorRegistry
        from tests.test_runner import StubCollector

        registry = CollectorRegistry()
        registry.register(StubCollector)
        runner, identity_store, event_store = build_agent(
            replace(config, max_stored_events=7), registry=registry
        )
        try:
            for _ in range(10):
                runner.sweep_once()
            assert event_store.count() <= 7
            assert event_store.dropped_event_count() > 0
        finally:
            event_store.close()
            identity_store.close()

    def test_cli_exposes_the_cap(self) -> None:
        import argparse
        import contextlib
        import io

        from ebabf.bootstrap import main

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), pytest.raises(SystemExit):
            main(["--help"])
        assert "--max-events" in buffer.getvalue()


class TestSeverityExpressionCannotDrift:
    def test_every_risk_level_is_ranked(self) -> None:
        from ebabf.storage.event_store import _SEVERITY_RANK

        assert set(_SEVERITY_RANK) == set(RiskLevel)

    def test_unscored_sits_between_low_and_medium(self) -> None:
        from ebabf.storage.event_store import _SEVERITY_RANK, _UNSCORED_RANK

        assert _SEVERITY_RANK[RiskLevel.LOW] < _UNSCORED_RANK
        assert _UNSCORED_RANK < _SEVERITY_RANK[RiskLevel.MEDIUM]

    def test_ranks_ascend_with_severity(self) -> None:
        from ebabf.storage.event_store import _SEVERITY_RANK

        order = [
            RiskLevel.NORMAL,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ]
        ranks = [_SEVERITY_RANK[level] for level in order]
        assert ranks == sorted(ranks)
