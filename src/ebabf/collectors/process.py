"""Process collector - the features in spec 5.1, via psutil.

Metadata only (spec 5.5 note): command lines, file contents and environment
are not read. What is collected is what the table asks for and nothing beyond.

Two fields are reported as None rather than guessed, because a wrong value
here is worse than a missing one (spec principle 1, "no guessing"):

- `is_signed`: Linux has no universal binary signature to check. The honest
  answer today is "unknown"; `False` would assert we checked and found it
  unsigned. Package provenance via dpkg lands with the inventory collector in
  Sprint 6.
- `cpu_percent`: psutil measures CPU between two observations of the same
  process, so the first sweep has nothing to measure against. Reporting 0.0
  would invent an idle process out of missing data - exactly the mistake spec
  6.3 forbids for absent layers.
"""

from __future__ import annotations

import sys
import time
from collections import Counter
from typing import Any, Iterator

import psutil

from ebabf.collectors.base import Collector
from ebabf.schema import Event, EventSource

__all__ = ["ProcessCollector"]

_ATTRS = [
    "pid",
    "ppid",
    "name",
    "exe",
    "username",
    "uids",
    "create_time",
    "cpu_percent",
    "status",
]


class ProcessCollector(Collector):
    """Polls the process table and emits one Event per live process."""

    source = EventSource.PROCESS
    name = "process"

    def __init__(self, context: Any) -> None:
        super().__init__(context)
        # Which pids we have already sampled. cpu_percent is only meaningful
        # from the second sweep onward.
        self._sampled: set[tuple[int, float]] = set()

    @classmethod
    def is_supported(cls) -> bool:
        """Spec 3 scopes v1 to Linux; privilege semantics below are POSIX."""
        return sys.platform.startswith("linux")

    def collect(self) -> Iterator[Event]:
        snapshot: list[dict[str, Any]] = []
        for proc in psutil.process_iter(attrs=_ATTRS, ad_value=None):
            try:
                snapshot.append(dict(proc.info))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # A process that exited mid-sweep is normal, not an error.
                continue

        # One pass to count children, rather than a syscall per process.
        child_counts = Counter(
            entry["ppid"] for entry in snapshot if entry.get("ppid") is not None
        )
        names_by_pid = {entry["pid"]: entry.get("name") for entry in snapshot}
        now = time.time()

        for entry in snapshot:
            event = self._to_event(entry, child_counts, names_by_pid, now)
            if event is not None:
                yield event

    def _to_event(
        self,
        entry: dict[str, Any],
        child_counts: Counter[int],
        names_by_pid: dict[int, str | None],
        now: float,
    ) -> Event | None:
        pid = entry.get("pid")
        if pid is None:
            return None

        username = entry.get("username")
        if not username:
            # Without an owner there is nothing to pseudonymise, and an event
            # attributed to nobody helps no investigation.
            return None

        create_time = entry.get("create_time")
        key = (pid, create_time if create_time is not None else -1.0)
        first_sighting = key not in self._sampled
        self._sampled.add(key)

        ppid = entry.get("ppid")
        raw_attributes: dict[str, Any] = {
            # spec 5.1
            "exec_path": entry.get("exe"),
            "is_signed": None,  # unknown on Linux; see module docstring
            "parent_process": names_by_pid.get(ppid) if ppid is not None else None,
            "process_lifetime": (
                round(now - create_time, 3) if create_time is not None else None
            ),
            "cpu_percent": None if first_sighting else entry.get("cpu_percent"),
            "child_process_count": int(child_counts.get(pid, 0)),
            "privilege_level": _privilege_level(entry.get("uids")),
            # context needed to correlate later, all non-identifying
            "pid": pid,
            "ppid": ppid,
            "process_name": entry.get("name"),
            "status": entry.get("status"),
        }

        timestamp = self._context.clock()
        return self._build_event(
            subject=username,
            raw_attributes=raw_attributes,
            timestamp=timestamp,
        )


def _privilege_level(uids: Any) -> str | None:
    """Classify a process by its uids (spec 5.1, privilege escalation signal)."""
    if uids is None:
        return None
    real = getattr(uids, "real", None)
    effective = getattr(uids, "effective", None)
    if real is None or effective is None:
        return None
    if effective == 0:
        return "root"
    if effective != real:
        return "elevated"
    return "user"
