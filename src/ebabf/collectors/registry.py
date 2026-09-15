"""Platform abstraction - spec 3, 4.

v1 targets Linux, but no layer above this one should know that. Collectors
declare the platforms they support; the registry starts the ones that can run
here and **reports the ones that cannot**.

That report is the point. Spec 11.3 requires a coverage gap to be declared
always - a monitoring tool silently missing a whole observation surface is
more dangerous than one that is plainly switched off, because the operator
believes they are covered.
"""

from __future__ import annotations

import logging
import platform
from dataclasses import dataclass
from typing import Callable, Iterable

from ebabf.collectors.base import Collector, CollectorContext

__all__ = [
    "CollectorRegistry",
    "CoverageReport",
    "default_registry",
    "register_collector",
]

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CoverageReport:
    """Which observation surfaces are live on this host, and which are not."""

    platform: str
    active: tuple[str, ...]
    unavailable: tuple[tuple[str, str], ...]
    """(collector name, why) - never silently dropped."""

    @property
    def is_complete(self) -> bool:
        return not self.unavailable

    def as_dict(self) -> dict[str, object]:
        return {
            "platform": self.platform,
            "active": list(self.active),
            "unavailable": [{"collector": n, "reason": r} for n, r in self.unavailable],
            "is_complete": self.is_complete,
        }


class CollectorRegistry:
    """Knows every collector type; builds the ones this platform supports."""

    def __init__(self) -> None:
        self._types: dict[str, type[Collector]] = {}

    def register(self, collector_type: type[Collector]) -> type[Collector]:
        name = collector_type.name
        if name in self._types and self._types[name] is not collector_type:
            raise ValueError(f"collector name {name!r} is already registered")
        self._types[name] = collector_type
        return collector_type

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._types))

    def get(self, name: str) -> type[Collector]:
        try:
            return self._types[name]
        except KeyError:
            raise KeyError(f"no collector named {name!r}; known: {self.names()}") from None

    def build(self, name: str, context: CollectorContext) -> Collector:
        return self.get(name)(context)

    def build_supported(
        self,
        context: CollectorContext,
        *,
        only: Iterable[str] | None = None,
    ) -> tuple[list[Collector], CoverageReport]:
        """Instantiate every supported collector, and say what was left out.

        A collector that raises while being built is treated as unavailable,
        not fatal: one broken surface must not take the agent down with it
        (spec 11.3).
        """
        wanted = set(only) if only is not None else set(self._types)
        unknown = wanted - set(self._types)
        if unknown:
            raise KeyError(f"unknown collectors: {sorted(unknown)}")

        active: list[Collector] = []
        unavailable: list[tuple[str, str]] = []

        for name in sorted(wanted):
            collector_type = self._types[name]
            try:
                if not collector_type.is_supported():
                    reason = collector_type.support_reason()
                    unavailable.append(
                        (name, reason or f"not supported on {platform.system()}")
                    )
                    continue
                active.append(collector_type(context))
            except Exception as exc:  # noqa: BLE001 - one surface down, not the agent
                logger.exception("collector %s could not be built", name)
                unavailable.append((name, f"{type(exc).__name__}: {exc}"))

        report = CoverageReport(
            platform=platform.system(),
            active=tuple(c.name for c in active),
            unavailable=tuple(unavailable),
        )
        if not report.is_complete:
            logger.warning("coverage gap: %s", report.as_dict()["unavailable"])
        return active, report


default_registry = CollectorRegistry()


def register_collector(collector_type: type[Collector]) -> type[Collector]:
    """Class decorator: add a collector to the default registry."""
    return default_registry.register(collector_type)
