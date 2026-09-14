"""Agent runner - the sweep loop.

Built because spec 2's "start recording the Benign Baseline" cannot happen
without a loop that sweeps collectors and writes what they produce.

This module holds the loop only. Wiring lives in `ebabf.bootstrap`, which is
the one place allowed to hold the identity store alongside the event store.

Naming matters here and spec 10 says so outright: **Baseline Collection** is
7-14 days of clean data gathered during development to train on. **Training
Mode** is a 30-day customer-facing "what would have happened" report, and it
lands in Sprint 8. They are not the same thing and are not named as though
they were: this module says `baseline` and never `training`.

The sweep order follows spec 11.3 exactly - decide, then enforce, then record.
Recording happens last and unconditionally, so an event survives a failure in
either engine above it.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from ebabf.collectors.base import Collector
from ebabf.collectors.registry import CoverageReport
from ebabf.engine.decision import DecisionEngine
from ebabf.engine.enforcement import EnforcementEngine
from ebabf.schema import Event
from ebabf.storage import EventStore

__all__ = ["AgentRunner", "SweepResult"]

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SweepResult:
    """What one sweep produced. Failures are counted, never hidden."""

    started_at: datetime
    duration_seconds: float
    collected: int
    stored: int
    enforced: int
    failed_collectors: tuple[tuple[str, str], ...] = ()

    @property
    def dropped(self) -> int:
        """Events collected but not stored - always zero unless storage failed."""
        return self.collected - self.stored


class AgentRunner:
    """Sweeps every collector on an interval and records what they see."""

    def __init__(
        self,
        *,
        collectors: Sequence[Collector],
        decision_engine: DecisionEngine,
        enforcement_engine: EnforcementEngine,
        event_store: EventStore,
        coverage: CoverageReport | None = None,
    ) -> None:
        self._collectors = list(collectors)
        self._decision = decision_engine
        self._enforcement = enforcement_engine
        self._store = event_store
        self._coverage = coverage
        self._stop = threading.Event()
        self._started = False

    @property
    def coverage(self) -> CoverageReport | None:
        return self._coverage

    @property
    def collector_names(self) -> tuple[str, ...]:
        return tuple(c.name for c in self._collectors)

    def start(self) -> None:
        """Start the streaming collectors. Idempotent."""
        if self._started:
            return
        for collector in self._collectors:
            try:
                collector.start()
            except Exception:  # noqa: BLE001 - one surface down, not the agent
                logger.exception("collector %s failed to start", collector.name)
        self._started = True

    def close(self) -> None:
        for collector in self._collectors:
            try:
                collector.close()
            except Exception:  # noqa: BLE001 - shutdown must not raise
                logger.exception("collector %s failed to close", collector.name)
        self._started = False

    def __enter__(self) -> "AgentRunner":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def sweep_once(self) -> SweepResult:
        """One pass over every collector.

        A collector that raises is recorded as failed and the sweep continues.
        Losing the network surface must not cost us the process surface too.
        """
        started_at = datetime.now(timezone.utc)
        began = time.monotonic()
        collected = stored = enforced = 0
        failures: list[tuple[str, str]] = []

        for collector in self._collectors:
            try:
                events = list(collector.collect())
            except Exception as exc:  # noqa: BLE001
                logger.exception("collector %s failed during sweep", collector.name)
                failures.append((collector.name, f"{type(exc).__name__}: {exc}"))
                continue

            for event in events:
                collected += 1
                was_stored, was_enforced = self._handle(event)
                stored += int(was_stored)
                enforced += int(was_enforced)

        return SweepResult(
            started_at=started_at,
            duration_seconds=round(time.monotonic() - began, 4),
            collected=collected,
            stored=stored,
            enforced=enforced,
            failed_collectors=tuple(failures),
        )

    def _handle(self, event: Event) -> tuple[bool, bool]:
        """Decide, enforce, record. Returns (stored, enforced).

        Storage comes last and is attempted whatever the engines did, so an
        event survives a failure above it (spec 11.3, fail-safe for logging).
        """
        outcome = self._decision.decide(event)
        result = self._enforcement.enforce(outcome)
        final = result.apply_to(outcome.event)
        try:
            self._store.append(final)
        except Exception:  # noqa: BLE001 - try, then say so; never silently drop
            logger.exception("could not store event %s", final.event_id)
            return False, result.enforced
        return True, result.enforced

    def run_forever(self, interval_seconds: float = 30.0) -> None:
        """Sweep on an interval until stopped. Handles SIGINT and SIGTERM."""
        self.start()
        self._install_signal_handlers()
        logger.info(
            "agent running: collectors=%s interval=%ss", self.collector_names, interval_seconds
        )
        if self._coverage is not None and not self._coverage.is_complete:
            logger.warning("starting with a coverage gap: %s", self._coverage.as_dict())

        try:
            while not self._stop.is_set():
                result = self.sweep_once()
                logger.info(
                    "sweep: collected=%d stored=%d enforced=%d in %.3fs%s",
                    result.collected,
                    result.stored,
                    result.enforced,
                    result.duration_seconds,
                    f" failures={list(result.failed_collectors)}" if result.failed_collectors else "",
                )
                self._stop.wait(interval_seconds)
        finally:
            self.close()

    def stop(self) -> None:
        self._stop.set()

    def _install_signal_handlers(self) -> None:
        def handle(signum: int, _frame: object) -> None:
            logger.info("signal %s received; stopping after this sweep", signum)
            self.stop()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, handle)
            except ValueError:
                # Not on the main thread - the caller drives stop() instead.
                pass
