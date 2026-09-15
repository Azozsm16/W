"""Collector interface - spec 4, "every layer talks through an interface".

A collector turns platform observations into Events. It is the only place in
the system that sees a real identity, and therefore the only place that may
pseudonymise one: past this boundary no identity exists to leak.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, ClassVar, Iterator, Mapping, Protocol

from ebabf.schema import Event, EventSource

__all__ = ["Collector", "CollectorContext", "Pseudonymizer"]


class Pseudonymizer(Protocol):
    """Forward direction only: you must already know the subject to ask."""

    def pseudonymize(self, subject: str) -> str: ...


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_event_id() -> str:
    return f"EVT-{uuid.uuid4().hex}"


@dataclass(frozen=True, slots=True)
class CollectorContext:
    """Everything a collector needs that is not platform-specific."""

    host_id: str
    tenant_id: str
    pseudonymizer: Pseudonymizer
    clock: Callable[[], datetime] = _utc_now
    event_id_factory: Callable[[], str] = _new_event_id


class Collector(ABC):
    """Produces Events from one observation surface."""

    source: ClassVar[EventSource]
    name: ClassVar[str]

    def __init__(self, context: CollectorContext) -> None:
        self._context = context

    @classmethod
    @abstractmethod
    def is_supported(cls) -> bool:
        """Whether this collector can run on the current platform.

        The hook that keeps spec 3's "Linux now, Windows later" honest: a
        platform gains support by adding a collector that answers True, not
        by editing the layers above.
        """

    @classmethod
    def support_reason(cls) -> str | None:
        """Why this collector cannot run here, when it cannot.

        The coverage report exists to tell an operator what to fix. "not
        supported on Linux" tells them nothing; "libpcap is missing" tells them
        what to install. Collectors that know the specific cause override this.
        """
        return None

    @abstractmethod
    def collect(self) -> Iterator[Event]:
        """One sweep of the observation surface.

        Yields events with every scoring field unset. A collector observes;
        it does not judge.
        """

    def start(self) -> None:
        """Begin any background work. No-op for polling collectors."""

    def close(self) -> None:
        """Release resources. No-op for polling collectors."""

    def __enter__(self) -> "Collector":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- helper for subclasses ----------------------------------------------

    def _build_event(
        self,
        *,
        subject: str,
        raw_attributes: Mapping[str, Any],
        timestamp: datetime | None = None,
    ) -> Event:
        """Assemble an Event, pseudonymising `subject` on the way through."""
        return Event(
            event_id=self._context.event_id_factory(),
            timestamp=timestamp or self._context.clock(),
            host_id=self._context.host_id,
            tenant_id=self._context.tenant_id,
            subject_pseudonym=self._context.pseudonymizer.pseudonymize(subject),
            source=self.source,
            raw_attributes=dict(raw_attributes),
        )
