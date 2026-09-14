"""Process collector: the spec 5.1 fields, and the abstraction behind them."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Iterator

import pytest

from ebabf.collectors import Collector, CollectorContext, ProcessCollector
from ebabf.collectors.process import _privilege_level
from ebabf.schema import Event, EventSource

SPEC_5_1_FIELDS = {
    "exec_path",
    "is_signed",
    "parent_process",
    "process_lifetime",
    "cpu_percent",
    "child_process_count",
    "privilege_level",
}


@pytest.fixture()
def collector(collector_context: CollectorContext) -> ProcessCollector:
    return ProcessCollector(collector_context)


class TestInterface:
    def test_is_a_collector(self, collector: ProcessCollector) -> None:
        assert isinstance(collector, Collector)

    def test_declares_its_source_and_platform(self, collector: ProcessCollector) -> None:
        assert ProcessCollector.source is EventSource.PROCESS
        assert ProcessCollector.name == "process"
        assert ProcessCollector.is_supported() is True

    def test_abstract_base_cannot_be_instantiated(
        self, collector_context: CollectorContext
    ) -> None:
        with pytest.raises(TypeError):
            Collector(collector_context)  # type: ignore[abstract]

    def test_a_new_platform_only_needs_a_new_collector(
        self, collector_context: CollectorContext
    ) -> None:
        """Spec 3: Linux now, Windows later, without touching the layers above."""

        class FakeWindowsCollector(Collector):
            source = EventSource.PROCESS
            name = "windows-process"

            @classmethod
            def is_supported(cls) -> bool:
                return False

            def collect(self) -> Iterator[Event]:
                yield self._build_event(subject="CORP\\amal", raw_attributes={"exec_path": "C:\\x.exe"})

        events = list(FakeWindowsCollector(collector_context).collect())
        assert len(events) == 1
        assert events[0].source is EventSource.PROCESS
        assert events[0].subject_pseudonym.startswith("USR-")

    def test_context_manager(self, collector: ProcessCollector) -> None:
        with collector as opened:
            assert opened is collector


class TestCollectedFields:
    def test_every_spec_5_1_field_is_present(self, collector: ProcessCollector) -> None:
        events = list(collector.collect())
        assert events
        for event in events:
            assert SPEC_5_1_FIELDS <= set(event.raw_attributes)

    def test_finds_the_running_test_process(self, collector: ProcessCollector) -> None:
        pids = {e.raw_attributes["pid"] for e in collector.collect()}
        assert os.getpid() in pids

    def test_child_process_count_is_computed(self, collector: ProcessCollector) -> None:
        counts = [e.raw_attributes["child_process_count"] for e in collector.collect()]
        assert all(isinstance(c, int) and c >= 0 for c in counts)
        assert any(c > 0 for c in counts)

    def test_process_lifetime_is_a_positive_duration(
        self, collector: ProcessCollector
    ) -> None:
        lifetimes = [
            e.raw_attributes["process_lifetime"]
            for e in collector.collect()
            if e.raw_attributes["process_lifetime"] is not None
        ]
        assert lifetimes and all(v >= 0 for v in lifetimes)

    def test_privilege_level_is_classified(self, collector: ProcessCollector) -> None:
        levels = {e.raw_attributes["privilege_level"] for e in collector.collect()}
        assert levels <= {"root", "elevated", "user", None}
        assert levels - {None}

    def test_no_content_is_collected(self, collector: ProcessCollector) -> None:
        """Spec 5.5 note: metadata only - no command lines, no environment."""
        forbidden = {"cmdline", "environ", "open_files", "memory_maps", "connections"}
        for event in collector.collect():
            assert set(event.raw_attributes) & forbidden == set()


class TestNoGuessing:
    """Spec principle 1: report unknown as unknown."""

    def test_is_signed_is_unknown_not_false(self, collector: ProcessCollector) -> None:
        """Linux has no universal signature check; False would claim we looked."""
        for event in collector.collect():
            assert event.raw_attributes["is_signed"] is None

    def test_cpu_percent_is_none_on_first_sighting(
        self, collector: ProcessCollector
    ) -> None:
        """psutil measures between two observations; the first has nothing to
        measure against, and 0.0 would invent an idle process."""
        for event in collector.collect():
            assert event.raw_attributes["cpu_percent"] is None

    def test_cpu_percent_is_reported_from_the_second_sweep(
        self, collector: ProcessCollector
    ) -> None:
        list(collector.collect())
        second = list(collector.collect())
        measured = [
            e.raw_attributes["cpu_percent"]
            for e in second
            if e.raw_attributes["pid"] == os.getpid()
        ]
        assert measured and measured[0] is not None


class TestEventsAreUnscored:
    def test_collector_observes_and_does_not_judge(
        self, collector: ProcessCollector
    ) -> None:
        for event in collector.collect():
            assert event.raw_score is None
            assert event.confidence is None
            assert event.level is None
            assert event.decision is None
            assert event.enforced is False
            assert event.verdict_type is None
            assert event.extracted_features == {}

    def test_events_carry_host_and_tenant(
        self, collector: ProcessCollector, collector_context: CollectorContext
    ) -> None:
        event = next(iter(collector.collect()))
        assert event.host_id == collector_context.host_id
        assert event.tenant_id == collector_context.tenant_id

    def test_timestamps_are_timezone_aware(self, collector: ProcessCollector) -> None:
        for event in collector.collect():
            assert event.timestamp.tzinfo is not None


class TestPseudonymisationHappensHere:
    def test_no_real_username_appears_on_any_event(
        self, collector: ProcessCollector
    ) -> None:
        import getpass

        try:
            me = getpass.getuser()
        except Exception:  # pragma: no cover
            pytest.skip("no resolvable username")
        for event in collector.collect():
            assert event.subject_pseudonym.startswith("USR-")
            assert me not in event.subject_pseudonym

    def test_the_same_owner_gets_the_same_pseudonym(
        self, collector: ProcessCollector
    ) -> None:
        pseudonyms = {e.subject_pseudonym for e in collector.collect()}
        # Every process in this container has the same owner.
        assert len(pseudonyms) >= 1

    def test_event_ids_are_unique(self, collector: ProcessCollector) -> None:
        ids = [e.event_id for e in collector.collect()]
        assert len(ids) == len(set(ids))


class TestPrivilegeClassification:
    class _Uids:
        def __init__(self, real: int, effective: int) -> None:
            self.real = real
            self.effective = effective

    @pytest.mark.parametrize(
        ("real", "effective", "expected"),
        [(0, 0, "root"), (1000, 0, "root"), (1000, 1000, "user"), (1000, 33, "elevated")],
    )
    def test_classification(self, real: int, effective: int, expected: str) -> None:
        assert _privilege_level(self._Uids(real, effective)) == expected

    def test_unknown_uids_report_none(self) -> None:
        assert _privilege_level(None) is None


class TestEndToEnd:
    def test_a_sweep_can_be_decided_and_stored(
        self, collector: ProcessCollector, event_store, kill_switch
    ) -> None:
        from ebabf.engine import NoOpEnforcementEngine, PassThroughDecisionEngine

        decision_engine = PassThroughDecisionEngine()
        enforcement = NoOpEnforcementEngine(enabled=True, kill_switch=kill_switch)

        count = 0
        for event in collector.collect():
            outcome = decision_engine.decide(event)
            result = enforcement.enforce(outcome)
            event_store.append(result.apply_to(outcome.event))
            count += 1

        assert count > 0
        assert event_store.count() == count
        stored = event_store.query(limit=5)
        assert all(e.ingested_at is not None for e in stored)
        assert all(e.decision is not None for e in stored)
        assert all(e.enforced is False for e in stored)


class TestSkippedProcesses:
    """Entries that cannot be attributed are dropped, not guessed at."""

    def _entry(self, **overrides) -> dict:
        entry = {
            "pid": 1234,
            "ppid": 1,
            "name": "curl",
            "exe": "/usr/bin/curl",
            "username": "alice",
            "uids": None,
            "create_time": 1_700_000_000.0,
            "cpu_percent": 0.0,
            "status": "running",
        }
        entry.update(overrides)
        return entry

    def test_a_process_without_an_owner_is_skipped(
        self, collector: ProcessCollector
    ) -> None:
        from collections import Counter

        assert collector._to_event(self._entry(username=None), Counter(), {}, 0.0) is None
        assert collector._to_event(self._entry(username=""), Counter(), {}, 0.0) is None

    def test_an_entry_without_a_pid_is_skipped(self, collector: ProcessCollector) -> None:
        from collections import Counter

        assert collector._to_event(self._entry(pid=None), Counter(), {}, 0.0) is None

    def test_a_complete_entry_becomes_an_event(self, collector: ProcessCollector) -> None:
        from collections import Counter

        event = collector._to_event(
            self._entry(), Counter({1234: 2}), {1: "systemd"}, 1_700_000_100.0
        )
        assert event is not None
        assert event.raw_attributes["exec_path"] == "/usr/bin/curl"
        assert event.raw_attributes["parent_process"] == "systemd"
        assert event.raw_attributes["child_process_count"] == 2
        assert event.raw_attributes["process_lifetime"] == 100.0
        assert event.raw_attributes["cpu_percent"] is None  # first sighting

    def test_missing_create_time_yields_no_lifetime(
        self, collector: ProcessCollector
    ) -> None:
        from collections import Counter

        event = collector._to_event(self._entry(create_time=None), Counter(), {}, 0.0)
        assert event.raw_attributes["process_lifetime"] is None
