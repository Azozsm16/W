"""Agent runner: sweep order, failure isolation, baseline separation."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from ebabf.collectors.base import Collector, CollectorContext
from ebabf.collectors.registry import CollectorRegistry
from ebabf.config import AgentConfig
from ebabf.engine.decision import DecisionEngine, DecisionOutcome, PassThroughDecisionEngine
from ebabf.engine.enforcement import NoOpEnforcementEngine
from ebabf.engine.killswitch import KillSwitch
from ebabf.bootstrap import build_agent
from ebabf.runner import AgentRunner, SweepResult
from ebabf.schema import Decision, EnforcementBlockedReason, Event, EventSource
from ebabf.storage import EventStore
from tests.conftest import AlwaysBlockEngine, make_event


class StubCollector(Collector):
    source = EventSource.PROCESS
    name = "stub"

    def __init__(self, context: CollectorContext, *, count: int = 3, explodes: bool = False) -> None:
        super().__init__(context)
        self._count = count
        self._explodes = explodes
        self.started = False
        self.closed = False
        self.sweeps = 0

    @classmethod
    def is_supported(cls) -> bool:
        return True

    def start(self) -> None:
        self.started = True

    def close(self) -> None:
        self.closed = True

    def collect(self) -> Iterator[Event]:
        self.sweeps += 1
        if self._explodes:
            raise RuntimeError("collector blew up")
        for index in range(self._count):
            yield self._build_event(
                subject="alice", raw_attributes={"n": index, "sweep": self.sweeps}
            )


class SecondCollector(StubCollector):
    name = "second"
    source = EventSource.FILE


def _runner(
    collectors, event_store: EventStore, kill_switch: KillSwitch, *, enabled: bool = True
) -> AgentRunner:
    return AgentRunner(
        collectors=collectors,
        decision_engine=PassThroughDecisionEngine(),
        enforcement_engine=NoOpEnforcementEngine(enabled=enabled, kill_switch=kill_switch),
        event_store=event_store,
    )


class TestSweep:
    def test_collects_decides_and_stores(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        runner = _runner([StubCollector(collector_context, count=4)], event_store, kill_switch)
        result = runner.sweep_once()
        assert result.collected == 4
        assert result.stored == 4
        assert result.dropped == 0
        assert event_store.count() == 4
        assert all(e.decision is Decision.LOG for e in event_store.query(limit=10))

    def test_every_stored_event_is_stamped_on_ingestion(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        _runner([StubCollector(collector_context)], event_store, kill_switch).sweep_once()
        assert all(e.ingested_at is not None for e in event_store.query(limit=10))

    def test_nothing_is_enforced_by_the_sprint_1_engines(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        result = _runner([StubCollector(collector_context)], event_store, kill_switch).sweep_once()
        assert result.enforced == 0
        assert all(e.enforced is False for e in event_store.query(limit=10))

    def test_sweeps_are_independent(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        runner = _runner([StubCollector(collector_context, count=2)], event_store, kill_switch)
        runner.sweep_once()
        runner.sweep_once()
        assert event_store.count() == 4

    def test_duration_is_measured(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        result = _runner([StubCollector(collector_context)], event_store, kill_switch).sweep_once()
        assert result.duration_seconds >= 0.0
        assert result.started_at.tzinfo is not None


class TestFailureIsolation:
    """Spec 11.3: one surface going down must not take the others with it."""

    def test_a_failing_collector_does_not_stop_the_rest(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        broken = StubCollector(collector_context, explodes=True)
        healthy = SecondCollector(collector_context, count=3)
        result = _runner([broken, healthy], event_store, kill_switch).sweep_once()

        assert result.collected == 3
        assert result.stored == 3
        assert len(result.failed_collectors) == 1
        assert result.failed_collectors[0][0] == "stub"
        assert "RuntimeError" in result.failed_collectors[0][1]

    def test_failures_are_named_not_counted(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        runner = _runner(
            [StubCollector(collector_context, explodes=True)], event_store, kill_switch
        )
        result = runner.sweep_once()
        assert result.failed_collectors[0][0] == "stub"

    def test_a_storage_failure_is_reported_not_swallowed(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        runner = _runner([StubCollector(collector_context, count=3)], event_store, kill_switch)
        event_store.close()  # storage now unusable
        result = runner.sweep_once()
        assert result.collected == 3
        assert result.stored == 0
        assert result.dropped == 3

    def test_a_broken_decision_engine_still_yields_stored_events(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        class Exploding(DecisionEngine):
            name = "boom"

            def _decide(self, event: Event) -> DecisionOutcome:
                raise RuntimeError("scoring down")

        runner = AgentRunner(
            collectors=[StubCollector(collector_context, count=2)],
            decision_engine=Exploding(),
            enforcement_engine=NoOpEnforcementEngine(enabled=True, kill_switch=kill_switch),
            event_store=event_store,
        )
        result = runner.sweep_once()
        assert result.stored == 2
        stored = event_store.query(limit=10)
        assert all("boom" in e.degraded_layers for e in stored)
        assert all(e.confidence is None for e in stored)


class TestKillSwitchThroughTheRunner:
    def test_recording_continues_while_enforcement_is_halted(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        kill_switch.engage(reason="halt", actor="ops")
        runner = AgentRunner(
            collectors=[StubCollector(collector_context, count=5)],
            decision_engine=PassThroughDecisionEngine(),
            enforcement_engine=AlwaysBlockEngine(enabled=True, kill_switch=kill_switch),
            event_store=event_store,
        )
        result = runner.sweep_once()
        assert result.stored == 5
        assert result.enforced == 0


class TestLifecycle:
    def test_start_and_close_reach_every_collector(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        collectors = [StubCollector(collector_context), SecondCollector(collector_context)]
        with _runner(collectors, event_store, kill_switch):
            assert all(c.started for c in collectors)
        assert all(c.closed for c in collectors)

    def test_start_is_idempotent(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        runner = _runner([StubCollector(collector_context)], event_store, kill_switch)
        runner.start()
        runner.start()
        runner.close()

    def test_a_collector_that_fails_to_start_does_not_stop_the_agent(
        self, collector_context: CollectorContext, event_store: EventStore, kill_switch: KillSwitch
    ) -> None:
        class BadStart(StubCollector):
            name = "bad_start"

            def start(self) -> None:
                raise OSError("no permission")

        collectors = [BadStart(collector_context), SecondCollector(collector_context, count=2)]
        runner = _runner(collectors, event_store, kill_switch)
        runner.start()
        assert runner.sweep_once().stored > 0
        runner.close()


class TestBuildAgent:
    def test_wires_from_config(self, config: AgentConfig) -> None:
        registry = CollectorRegistry()
        registry.register(StubCollector)
        runner, identity_store, event_store = build_agent(config, registry=registry)
        try:
            assert runner.collector_names == ("stub",)
            assert runner.coverage is not None and runner.coverage.is_complete
            assert runner.sweep_once().stored == 3
        finally:
            event_store.close()
            identity_store.close()

    def test_baseline_writes_to_its_own_database(self, config: AgentConfig, tmp_path: Path) -> None:
        """Spec 10: Baseline Collection is not Training Mode, and not the live store."""
        registry = CollectorRegistry()
        registry.register(StubCollector)
        baseline_db = tmp_path / "baseline.db"
        runner, identity_store, event_store = build_agent(
            config, registry=registry, event_db_path=baseline_db
        )
        try:
            runner.sweep_once()
            assert baseline_db.exists()
            assert event_store.count() == 3
        finally:
            event_store.close()
            identity_store.close()
        assert not config.event_db_path.exists()

    def test_coverage_gap_is_carried_on_the_runner(self, config: AgentConfig) -> None:
        class Unsupported(StubCollector):
            name = "unsupported"

            @classmethod
            def is_supported(cls) -> bool:
                return False

        registry = CollectorRegistry()
        registry.register(StubCollector)
        registry.register(Unsupported)
        runner, identity_store, event_store = build_agent(config, registry=registry)
        try:
            assert runner.coverage is not None
            assert runner.coverage.is_complete is False
            assert runner.coverage.unavailable[0][0] == "unsupported"
        finally:
            event_store.close()
            identity_store.close()


class TestNamingDiscipline:
    def test_no_identifier_conflates_baseline_with_training_mode(self) -> None:
        """Spec 10 says outright: do not mix the two names in the code.

        Checks identifiers and CLI command strings, not prose: a docstring
        explaining that the two are different is the right place for both
        words to appear.
        """
        import ast

        import ebabf.runner as module

        tree = ast.parse(Path(module.__file__).read_text())
        names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(node.name)
            elif isinstance(node, ast.Name):
                names.append(node.id)
            elif isinstance(node, ast.arg):
                names.append(node.arg)
            elif isinstance(node, ast.Attribute):
                names.append(node.attr)
            elif isinstance(node, ast.keyword) and node.arg:
                names.append(node.arg)

        offenders = [n for n in names if "training" in n.lower()]
        assert offenders == [], f"identifiers conflate the two concepts: {offenders}"

    def test_the_cli_offers_baseline_not_training(self) -> None:
        from ebabf.bootstrap import main

        with pytest.raises(SystemExit):
            main(["--help"])


class TestStartFailuresBecomeCoverageGaps:
    """A collector that will not start must leave the active list.

    Logging it and leaving it listed would have the coverage report claim a
    surface that produces nothing - the gap that this project keeps finding.
    """

    def _runner_with_bad_start(self, collector_context, event_store, kill_switch):
        from ebabf.collectors.registry import CoverageReport

        class BadStart(StubCollector):
            name = "bad_start"

            def start(self) -> None:
                raise OSError("libpcap missing")

        collectors = [BadStart(collector_context), SecondCollector(collector_context, count=2)]
        runner = AgentRunner(
            collectors=collectors,
            decision_engine=PassThroughDecisionEngine(),
            enforcement_engine=NoOpEnforcementEngine(enabled=True, kill_switch=kill_switch),
            event_store=event_store,
            coverage=CoverageReport(
                platform="Linux", active=("bad_start", "second"), unavailable=()
            ),
        )
        return runner

    def test_the_failed_collector_leaves_the_active_list(
        self, collector_context, event_store: EventStore, kill_switch
    ) -> None:
        runner = self._runner_with_bad_start(collector_context, event_store, kill_switch)
        runner.start()
        try:
            assert runner.coverage is not None
            assert "bad_start" not in runner.coverage.active
            assert "second" in runner.coverage.active
            assert runner.coverage.is_complete is False
            assert runner.coverage.unavailable[0][0] == "bad_start"
            assert "libpcap" in runner.coverage.unavailable[0][1]
        finally:
            runner.close()

    def test_it_is_not_swept_afterwards(
        self, collector_context, event_store: EventStore, kill_switch
    ) -> None:
        runner = self._runner_with_bad_start(collector_context, event_store, kill_switch)
        runner.start()
        try:
            assert runner.collector_names == ("second",)
            assert runner.sweep_once().collected == 2
        finally:
            runner.close()

    def test_healthy_collectors_leave_coverage_complete(
        self, collector_context, event_store: EventStore, kill_switch
    ) -> None:
        from ebabf.collectors.registry import CoverageReport

        runner = AgentRunner(
            collectors=[StubCollector(collector_context)],
            decision_engine=PassThroughDecisionEngine(),
            enforcement_engine=NoOpEnforcementEngine(enabled=True, kill_switch=kill_switch),
            event_store=event_store,
            coverage=CoverageReport(platform="Linux", active=("stub",), unavailable=()),
        )
        runner.start()
        try:
            assert runner.coverage.is_complete is True
        finally:
            runner.close()
