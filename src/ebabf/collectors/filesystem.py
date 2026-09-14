"""File monitor - spec 5.3, via watchdog/inotify.

`file_entropy_change` is **not implemented**, by decision: computing it means
reading file bytes, and principle 5 forbids collecting file content. The
principle wins. See docs/decisions.md, D-010.

What is left is enough to see the behaviour that matters. Ransomware announces
itself by rewriting many files very fast, and `file_modification_rate` measures
exactly that without opening a single one.

Two further limits, stated rather than papered over:

- inotify reports *what* changed, never *who* changed it. Events are therefore
  attributed by path ownership, not by the process responsible. Real actor
  attribution needs fanotify or auditd, which are out of scope for v1.
- File paths are not stored. Spec 11.2's third retention tier treats paths as
  identifying, and `~/Documents/...` often is. Events carry the watched root's
  label, counts, and the sensitive-path category - never the filename.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Iterator

from watchdog.events import (
    EVENT_TYPE_CREATED,
    EVENT_TYPE_DELETED,
    EVENT_TYPE_MODIFIED,
    EVENT_TYPE_MOVED,
)

from ebabf.collectors.base import Collector, CollectorContext
from ebabf.collectors.registry import register_collector
from ebabf.schema import Event, EventSource

__all__ = ["FileMonitorCollector", "WatchRoot", "FileActivity", "SENSITIVE_CATEGORIES"]

logger = logging.getLogger(__name__)

_INOTIFY_LIMIT_PATH = "/proc/sys/fs/inotify/max_user_watches"
# Warn once the agent is using this share of the host's watch budget.
_WATCH_WARN_RATIO = 0.5

# Which watchdog events count as a change to a file.
#
# A positive allowlist, taken from watchdog's own constants rather than typed
# from memory, and bound to the four mutation types. Everything else -
# `opened`, `closed`, `closed_no_write`, and whatever a future version adds -
# is not a modification and is not counted as one.
#
# This was a bug: the previous code folded every unrecognised type into
# `modified`, so reading 20 files registered as 40 modifications. A backup
# job or a recursive grep over a documents folder looked exactly like mass
# encryption, in a system whose one binding metric is precision.
MUTATION_EVENTS: dict[str, str] = {
    EVENT_TYPE_CREATED: "created",
    EVENT_TYPE_DELETED: "deleted",
    EVENT_TYPE_MODIFIED: "modified",
    EVENT_TYPE_MOVED: "moved",
}

# Known non-mutating types. Listed so they are discarded quietly, while a type
# from outside both sets raises a warning.
_KNOWN_NON_MUTATION_EVENTS = frozenset({"opened", "closed", "closed_no_write"})

SENSITIVE_CATEGORIES: dict[str, tuple[str, ...]] = {
    "system_config": ("/etc",),
    "ssh_keys": (".ssh",),
    "autostart": (".config/autostart", "/etc/systemd/system", ".config/systemd/user"),
    "shell_init": (".bashrc", ".bash_profile", ".profile", ".zshrc"),
}


@dataclass(frozen=True, slots=True)
class WatchRoot:
    """A directory tree to watch, and the label events will carry for it."""

    path: Path
    label: str
    subject: str
    """Who events under this root are attributed to; `__host__` for system paths."""

    recursive: bool = True


@dataclass(slots=True)
class FileActivity:
    """Counters for one watch root since the last sweep."""

    created: int = 0
    modified: int = 0
    deleted: int = 0
    moved: int = 0
    ignored: int = 0
    """Non-mutating events seen and deliberately not counted (reads, opens)."""

    distinct_paths: set[str] = field(default_factory=set)
    sensitive_categories: set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def total(self) -> int:
        return self.created + self.modified + self.deleted + self.moved


def classify_sensitive(path: str) -> str | None:
    """Which sensitive category a path falls under, if any (spec 5.3)."""
    normalised = path.replace(os.sep, "/")
    for category, markers in SENSITIVE_CATEGORIES.items():
        for marker in markers:
            if marker.startswith("/"):
                if normalised == marker or normalised.startswith(marker + "/"):
                    return category
            elif f"/{marker}" in normalised or normalised.endswith(marker):
                return category
    return None


class _BufferingHandler:
    """watchdog handler that counts events instead of storing paths.

    Deliberately not a subclass of watchdog's handler: keeping it a plain
    object means the counting logic can be tested without an observer, a
    filesystem, or a real inotify watch.
    """

    def __init__(self, root: WatchRoot) -> None:
        self._root = root
        self._activity = FileActivity()
        self._lock = threading.Lock()
        self._unknown_seen: set[str] = set()

    def record(self, event_type: str, path: str, *, now: float | None = None) -> None:
        """Count one filesystem event.

        Only the four mutation types are counted. Opens and closes are seen and
        discarded: spec 5.3 asks about writes, and recording every file a user
        reads would be surveillance the spec never asked for.
        """
        counter = MUTATION_EVENTS.get(event_type)
        moment = now if now is not None else time.time()

        with self._lock:
            activity = self._activity
            if activity.first_seen == 0.0:
                activity.first_seen = moment
            activity.last_seen = moment

            if counter is None:
                activity.ignored += 1
                self._note_unknown(event_type)
                return

            setattr(activity, counter, getattr(activity, counter) + 1)
            # Hashed, not stored: we need the count of distinct files, not
            # which files they were.
            activity.distinct_paths.add(str(hash(path)))
            category = classify_sensitive(path)
            if category is not None:
                activity.sensitive_categories.add(category)

    def _note_unknown(self, event_type: str) -> None:
        """Warn once per unrecognised event type.

        A watchdog release adding a type must be noticed, not absorbed. It is
        already handled correctly - an unknown type is not a mutation - but
        silence here is how the previous bug survived.
        """
        if event_type in _KNOWN_NON_MUTATION_EVENTS or event_type in self._unknown_seen:
            return
        self._unknown_seen.add(event_type)
        logger.warning(
            "watchdog emitted an unrecognised event type %r; not counted as a "
            "modification. Check MUTATION_EVENTS against this watchdog version.",
            event_type,
        )

    def dispatch(self, event: Any) -> None:  # pragma: no cover - driven by watchdog
        if getattr(event, "is_directory", False):
            return
        self.record(event.event_type, str(getattr(event, "dest_path", "") or event.src_path))

    def drain(self) -> FileActivity:
        with self._lock:
            drained, self._activity = self._activity, FileActivity()
        return drained


@register_collector
class FileMonitorCollector(Collector):
    """Watches configured roots and reports per-root activity each sweep.

    One event per root per sweep, not one per file. A mass-encryption run would
    otherwise emit thousands of events and bury the very signal it represents,
    against the 5-alerts-per-host-per-day ceiling in spec 13.
    """

    source: ClassVar[EventSource] = EventSource.FILE
    name: ClassVar[str] = "file"

    def __init__(
        self,
        context: CollectorContext,
        *,
        roots: tuple[WatchRoot, ...] | None = None,
    ) -> None:
        super().__init__(context)
        self._roots = roots if roots is not None else default_watch_roots()
        self._handlers: dict[str, _BufferingHandler] = {
            root.label: _BufferingHandler(root) for root in self._roots
        }
        self._observer: Any = None
        self._last_sweep: float | None = None
        self._watch_count = 0

    @classmethod
    def is_supported(cls) -> bool:
        if not os.path.exists("/proc/sys/fs/inotify/max_user_watches"):
            logger.warning("file monitor unavailable: inotify not present")
            return False
        return True

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._observer is not None:
            return
        from watchdog.observers import Observer

        self._observer = Observer()
        for root in self._roots:
            if not root.path.exists():
                logger.info("watch root %s does not exist; skipped", root.path)
                continue
            handler = self._handlers[root.label]
            try:
                self._observer.schedule(handler, str(root.path), recursive=root.recursive)
                self._watch_count += _count_directories(root.path) if root.recursive else 1
            except OSError as exc:
                # Hitting the watch limit is a coverage gap, and coverage gaps
                # are declared (spec 11.3), never swallowed.
                logger.error("cannot watch %s: %s", root.path, exc)
        self._warn_if_near_watch_limit()
        self._observer.start()
        self._last_sweep = time.time()

    def close(self) -> None:
        if self._observer is None:
            return
        try:
            self._observer.stop()
            self._observer.join(timeout=5)
        except Exception:  # noqa: BLE001 - shutdown must not raise
            logger.debug("observer shutdown failed", exc_info=True)
        self._observer = None

    # -- collection ---------------------------------------------------------

    def collect(self) -> Iterator[Event]:
        # One clock read per sweep, reused as every event's timestamp, so all
        # events from one sweep agree on when the sweep happened.
        swept_at = self._context.clock()
        now = swept_at.timestamp()
        window = now - self._last_sweep if self._last_sweep else None
        self._last_sweep = now

        for root in self._roots:
            activity = self._handlers[root.label].drain()
            if activity.total == 0:
                continue
            yield self._build_event(
                subject=root.subject,
                raw_attributes=self._describe(root, activity, window),
                timestamp=swept_at,
            )

    def _describe(
        self, root: WatchRoot, activity: FileActivity, window: float | None
    ) -> dict[str, Any]:
        return {
            # spec 5.3
            "sensitive_path_write": bool(activity.sensitive_categories),
            "file_modification_rate": (
                round(activity.total / window, 3) if window and window > 0 else None
            ),
            # context - labels and counts, never filenames
            "watch_root_label": root.label,
            "sensitive_categories": sorted(activity.sensitive_categories),
            "files_created": activity.created,
            "files_modified": activity.modified,
            "files_deleted": activity.deleted,
            "files_moved": activity.moved,
            "events_total": activity.total,
            "ignored_events": activity.ignored,
            "distinct_file_count": len(activity.distinct_paths),
            "window_seconds": round(window, 3) if window else None,
        }

    # -- inotify budget -----------------------------------------------------

    def _warn_if_near_watch_limit(self) -> None:
        limit = read_inotify_limit()
        if limit is None:
            return
        if self._watch_count > limit * _WATCH_WARN_RATIO:
            logger.warning(
                "file monitor holds ~%d inotify watches of a %d limit; "
                "changes beyond the limit are silently missed - raise "
                "fs.inotify.max_user_watches or narrow the watch roots",
                self._watch_count,
                limit,
            )

    @property
    def watch_count(self) -> int:
        return self._watch_count


def read_inotify_limit() -> int | None:
    try:
        return int(Path(_INOTIFY_LIMIT_PATH).read_text().strip())
    except (OSError, ValueError):
        return None


def _count_directories(root: Path, cap: int = 20_000) -> int:
    """Approximate the watches a recursive watch will consume."""
    count = 0
    for _ in os.walk(root, onerror=lambda _exc: None):
        count += 1
        if count >= cap:
            break
    return count


def default_watch_roots(home_parent: Path = Path("/home")) -> tuple[WatchRoot, ...]:
    """Sensitive system paths plus each user's document directories.

    Documents are included because that is where ransomware encrypts; watching
    /etc alone would miss the case the feature exists for.
    """
    roots: list[WatchRoot] = []
    for system_path, label in (("/etc", "system_config"), ("/etc/systemd/system", "autostart_system")):
        path = Path(system_path)
        if path.exists():
            roots.append(WatchRoot(path=path, label=label, subject="__host__", recursive=True))

    if home_parent.exists():
        for home in sorted(home_parent.iterdir()):
            if not home.is_dir():
                continue
            owner = home.name
            for name in ("Documents", "Desktop", ".ssh", ".config/autostart"):
                candidate = home / name
                if candidate.exists():
                    roots.append(
                        WatchRoot(
                            path=candidate,
                            label=f"{owner}:{name}",
                            subject=owner,
                            recursive=True,
                        )
                    )
    return tuple(roots)
