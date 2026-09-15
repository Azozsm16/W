"""events.db - event records, with no identity in them, ever.

A separate SQLite file from identity.db, opened on its own connection that
never issues ATTACH. No SQL reachable from this class can join the two.

`verdict_type` is a VIRTUAL generated column: computed from `confidence` on
every read, stored nowhere. A stored copy could disagree with the confidence
beside it; a generated one cannot, by definition of the word.

Growth is bounded (spec 11.3): past `max_events` the oldest low-severity rows
are dropped, and every drop is recorded in `overflow_drops`. The record is the
important half - a baseline that was silently truncated is worse than one that
stopped, because it still looks complete when you come to train on it.
"""

from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from ebabf.schema import (
    CONFIDENCE_SUSPICION_THRESHOLD,
    CONFIDENCE_VERDICT_THRESHOLD,
    Event,
    EventSource,
    RiskLevel,
)

__all__ = [
    "EventStore",
    "StorageHalted",
    "DEFAULT_MAX_EVENTS",
    "DEFAULT_MIN_FREE_BYTES",
    "DEFAULT_GAP_THRESHOLD_SECONDS",
]

logger = logging.getLogger(__name__)

# Roughly two days of a chatty single host, or a few gigabytes at the outside.
# Overridable, and 0 means unbounded - see AgentConfig.max_stored_events.
DEFAULT_MAX_EVENTS = 2_000_000

# Once over the cap, evict down to this share of it rather than one row per
# append: a delete on every insert would thrash the table for no benefit.
_EVICT_TO_RATIO = 0.95

# Stop writing with this much room left, rather than discovering the ceiling
# by failing mid-write. Enough to record why we stopped and leave the host
# usable.
DEFAULT_MIN_FREE_BYTES = 512 * 1024 * 1024

# A break longer than this is the agent having been down, not a quiet host.
# Used both to detect downtime at startup and to report gaps in `status`, so
# the two can never disagree about what counts as a gap.
DEFAULT_GAP_THRESHOLD_SECONDS = 600.0

# statvfs is cheap but not free; at ~420 bytes an event this bounds the
# overshoot past the floor to well under a megabyte.
_FREE_SPACE_CHECK_EVERY = 500


class StorageHalted(RuntimeError):
    """Recording was stopped deliberately, and the reason is on the record.

    Raised instead of writing into a nearly full disk. Stopping on purpose and
    saying so beats being killed mid-write: a half-written database is a
    corrupt one, and a baseline that stopped silently still looks complete.
    """

# Built from the same constants the Python property uses, so SQL and Python
# cannot drift apart into two different definitions of "verdict".
_VERDICT_EXPRESSION = (
    "CASE "
    "WHEN confidence IS NULL THEN NULL "
    f"WHEN confidence >= {CONFIDENCE_VERDICT_THRESHOLD} THEN 'verdict' "
    f"WHEN confidence >= {CONFIDENCE_SUSPICION_THRESHOLD} THEN 'suspicion' "
    "ELSE 'unverified' END"
)

# Eviction order: least worth keeping first (spec 11.3, "drop the oldest
# low-severity events first").
#
# Unscored rows sit between Low and Medium on purpose. Nothing has judged them,
# so they are not dropped ahead of an event positively known to be boring, and
# not kept ahead of one positively known to be interesting. Uncertainty ranks
# between known-boring and known-interesting - it is not treated as either.
#
# Today every row is unscored, so this degrades to plain oldest-first, which is
# what baseline recording wants. It starts sorting by severity by itself the
# moment the scoring engine lands in Sprint 4, with nothing to remember.
_SEVERITY_RANK = {
    RiskLevel.NORMAL: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 3,
    RiskLevel.HIGH: 4,
    RiskLevel.CRITICAL: 5,
}
_UNSCORED_RANK = 2

_SEVERITY_EXPRESSION = (
    "CASE level "
    + " ".join(f"WHEN '{level.value}' THEN {rank}" for level, rank in _SEVERITY_RANK.items())
    + f" ELSE {_UNSCORED_RANK} END"
)

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS events (
    event_id                   TEXT PRIMARY KEY,
    timestamp                  TEXT NOT NULL,
    ingested_at                TEXT NOT NULL,
    host_id                    TEXT NOT NULL,
    tenant_id                  TEXT NOT NULL,

    -- The only subject reference this database holds. The CHECK is a second
    -- line of defence behind the schema's own validation: a real username
    -- cannot be written here even by a caller that bypassed Event.
    subject_pseudonym          TEXT NOT NULL
        CHECK (length(subject_pseudonym) = 36 AND substr(subject_pseudonym, 1, 4) = 'USR-'),

    source                     TEXT NOT NULL,
    raw_attributes             TEXT NOT NULL,
    extracted_features         TEXT NOT NULL,

    raw_score                  REAL,
    context_modifier           REAL,
    final_score                REAL,
    confidence                 REAL,
    level                      TEXT,
    degraded_layers            TEXT NOT NULL,
    triggered_rule_ids         TEXT NOT NULL,

    decision                   TEXT,
    enforced                   INTEGER NOT NULL DEFAULT 0,
    enforcement_blocked_reason TEXT,

    explanation                TEXT NOT NULL,
    schema_version             TEXT NOT NULL,

    verdict_type TEXT GENERATED ALWAYS AS ({_VERDICT_EXPRESSION}) VIRTUAL,

    CHECK (enforced IN (0, 1)),
    CHECK (enforced = 0 OR enforcement_blocked_reason IS NULL)
);
CREATE INDEX IF NOT EXISTS idx_events_ingested ON events(ingested_at);
CREATE INDEX IF NOT EXISTS idx_events_tenant   ON events(tenant_id, ingested_at);
CREATE INDEX IF NOT EXISTS idx_events_subject  ON events(subject_pseudonym);
CREATE INDEX IF NOT EXISTS idx_events_level    ON events(level);

-- Durable evidence that data was discarded. Named for overflow, not for
-- retention: spec 11.2's three-tier retention policy is a different mechanism
-- and arrives in Sprint 7. Conflating the two names would hide one behind the
-- other.
-- Periods where the agent recorded nothing, and why. Decision 11: a coverage
-- gap is always declared. systemd restarting the agent closes the outage; it
-- does not close the hole in the data, and only this table shows the hole.
CREATE TABLE IF NOT EXISTS coverage_gaps (
    gap_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at      TEXT NOT NULL,
    kind             TEXT NOT NULL,
    gap_start        TEXT,
    gap_end          TEXT,
    duration_seconds REAL,
    detail           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS overflow_drops (
    drop_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    dropped_at         TEXT NOT NULL,
    event_count        INTEGER NOT NULL,
    oldest_ingested_at TEXT,
    newest_ingested_at TEXT,
    level_breakdown    TEXT NOT NULL,
    reason             TEXT NOT NULL
);
"""

_COLUMNS = (
    "event_id",
    "timestamp",
    "ingested_at",
    "host_id",
    "tenant_id",
    "subject_pseudonym",
    "source",
    "raw_attributes",
    "extracted_features",
    "raw_score",
    "context_modifier",
    "final_score",
    "confidence",
    "level",
    "degraded_layers",
    "triggered_rule_ids",
    "decision",
    "enforced",
    "enforcement_blocked_reason",
    "explanation",
    "schema_version",
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EventStore:
    """Owns events.db."""

    def __init__(
        self,
        db_path: Path,
        *,
        clock: Callable[[], datetime] = _utc_now,
        max_events: int | None = None,
        min_free_bytes: int | None = None,
    ) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        # check_same_thread=False plus an explicit lock: the agent sweeps from
        # a worker thread while collectors run in their own, and a connection
        # pinned to its creating thread would fail there. SQLite is safe for
        # serialised access; the lock is what serialises it.
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self._path, isolation_level=None, check_same_thread=False
        )
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.executescript(_SCHEMA)

        # 0 or None means unbounded. The row count is cached rather than
        # counted per append: SQLite has no O(1) COUNT(*), and paying for a
        # full scan on every event would cost more than the events are worth.
        self._max_events = max_events if max_events else None
        self._row_count = int(
            self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        )

        self._min_free_bytes = min_free_bytes if min_free_bytes else None
        self._appends_since_space_check = _FREE_SPACE_CHECK_EVERY
        self._halted_reason: str | None = None

    @property
    def path(self) -> Path:
        return self._path

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "EventStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def append(self, event: Event) -> Event:
        """Persist `event` and return it stamped with `ingested_at`.

        The stamp is taken from this store's clock and overwrites whatever
        arrived on the event. `timestamp` comes from the host and can be
        moved; this one cannot, which is why retention (spec 11.2) and
        temporal splits (spec 10.4) key off it.
        """
        stamped = event.enriched(ingested_at=self._clock())
        payload = stamped.to_dict()
        values = (
            payload["event_id"],
            payload["timestamp"],
            payload["ingested_at"],
            payload["host_id"],
            payload["tenant_id"],
            payload["subject_pseudonym"],
            payload["source"],
            json.dumps(payload["raw_attributes"], ensure_ascii=False),
            json.dumps(payload["extracted_features"], ensure_ascii=False),
            payload["raw_score"],
            payload["context_modifier"],
            payload["final_score"],
            payload["confidence"],
            payload["level"],
            json.dumps(payload["degraded_layers"], ensure_ascii=False),
            json.dumps(payload["triggered_rule_ids"], ensure_ascii=False),
            payload["decision"],
            int(payload["enforced"]),
            payload["enforcement_blocked_reason"],
            json.dumps(payload["explanation"], ensure_ascii=False),
            payload["schema_version"],
        )
        placeholders = ", ".join("?" * len(_COLUMNS))
        with self._lock:
            self._conn.execute(
                f"INSERT INTO events ({', '.join(_COLUMNS)}) VALUES ({placeholders})", values
            )
            self._check_free_space_locked()
            self._row_count += 1
            if self._max_events is not None and self._row_count > self._max_events:
                self._evict_locked()
        return stamped

    # -- free space (decision 11: a coverage gap is always declared) --------

    @property
    def is_halted(self) -> bool:
        return self._halted_reason is not None

    @property
    def halted_reason(self) -> str | None:
        return self._halted_reason

    def free_bytes(self) -> int:
        """Space left on the filesystem holding the database."""
        return shutil.disk_usage(self._path.parent).free

    def _check_free_space_locked(self) -> None:
        """Refuse to write into a nearly full disk. Caller holds the lock.

        The danger is not a full disk; it is a disk that fills quietly and
        leaves a baseline with an unmarked hole in it. So recording stops on
        purpose, the reason goes on the record, and the caller is told.
        """
        if self._halted_reason is not None:
            raise StorageHalted(self._halted_reason)
        if self._min_free_bytes is None:
            return

        self._appends_since_space_check += 1
        if self._appends_since_space_check < _FREE_SPACE_CHECK_EVERY:
            return
        self._appends_since_space_check = 0

        try:
            free = shutil.disk_usage(self._path.parent).free
        except OSError as exc:  # pragma: no cover - unreadable mount point
            logger.warning("cannot read free space for %s: %s", self._path.parent, exc)
            return
        if free >= self._min_free_bytes:
            return

        reason = (
            f"free space {free / 1e6:.0f} MB fell below the "
            f"{self._min_free_bytes / 1e6:.0f} MB floor"
        )
        self._halted_reason = reason
        self._record_gap_locked(
            kind="storage_halted",
            gap_start=self._clock().isoformat(),
            gap_end=None,
            duration_seconds=None,
            detail=reason,
        )
        logger.critical(
            "RECORDING HALTED: %s. Nothing further is being captured. "
            "Free space and restart the agent.",
            reason,
        )
        raise StorageHalted(reason)

    # -- coverage gaps ------------------------------------------------------

    def _record_gap_locked(
        self,
        *,
        kind: str,
        gap_start: str | None,
        gap_end: str | None,
        duration_seconds: float | None,
        detail: str,
    ) -> None:
        self._conn.execute(
            "INSERT INTO coverage_gaps (detected_at, kind, gap_start, gap_end, "
            "duration_seconds, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (
                self._clock().isoformat(),
                kind,
                gap_start,
                gap_end,
                duration_seconds,
                detail,
            ),
        )

    def detect_downtime(self, threshold_seconds: float = DEFAULT_GAP_THRESHOLD_SECONDS) -> float | None:
        """Record the outage since the last event, if there was one.

        Called when recording starts. systemd bringing the agent back closes
        the outage but not the hole it left; without this the hole is invisible
        and the operator believes the run was continuous.

        Returns the gap in seconds, or None if there was no meaningful one.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(ingested_at) FROM events"
            ).fetchone()
            last = row[0] if row else None
            if last is None:
                return None

            now = self._clock()
            gap = (now - datetime.fromisoformat(last)).total_seconds()
            if gap < threshold_seconds:
                return None

            self._record_gap_locked(
                kind="agent_downtime",
                gap_start=last,
                gap_end=now.isoformat(),
                duration_seconds=gap,
                detail=(
                    f"no events recorded for {gap / 3600:.1f} hours before this start"
                ),
            )
        logger.warning(
            "coverage gap: nothing was recorded for %.1f hours before this start "
            "(%s to %s). The data has a hole in it.",
            gap / 3600,
            last,
            now.isoformat(),
        )
        return gap

    def find_gaps(
        self, min_seconds: float = DEFAULT_GAP_THRESHOLD_SECONDS
    ) -> list[dict[str, Any]]:
        """Breaks between consecutive events longer than `min_seconds`.

        Computed from the data itself, so it finds outages nobody recorded -
        a kill -9, a power cut, an agent that never started after a reboot.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT prev_at, ingested_at, gap FROM ("
                "  SELECT ingested_at, LAG(ingested_at) OVER (ORDER BY ingested_at) AS prev_at,"
                "         (julianday(ingested_at) - LAG(julianday(ingested_at)) "
                "          OVER (ORDER BY ingested_at)) * 86400.0 AS gap"
                "  FROM events"
                ") WHERE prev_at IS NOT NULL AND gap > ? ORDER BY gap DESC",
                (min_seconds,),
            ).fetchall()
        return [
            {"start": start, "end": end, "duration_seconds": round(gap, 1)}
            for start, end, gap in rows
        ]

    def coverage_gap_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """Gaps the agent recorded about itself, newest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT gap_id, detected_at, kind, gap_start, gap_end, duration_seconds, "
                "detail FROM coverage_gaps ORDER BY gap_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        keys = (
            "gap_id",
            "detected_at",
            "kind",
            "gap_start",
            "gap_end",
            "duration_seconds",
            "detail",
        )
        return [dict(zip(keys, row)) for row in rows]

    def span(self) -> dict[str, Any]:
        """First and last ingestion times, and the wall-clock hours between."""
        with self._lock:
            row = self._conn.execute(
                "SELECT MIN(ingested_at), MAX(ingested_at), COUNT(*) FROM events"
            ).fetchone()
        first, last, count = row
        hours = None
        if first and last:
            hours = round(
                (datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds()
                / 3600,
                2,
            )
        return {"first": first, "last": last, "count": int(count), "span_hours": hours}

    # -- overflow (spec 11.3) ----------------------------------------------

    def _evict_locked(self) -> None:
        """Drop the least valuable rows and record that it happened.

        Caller must hold the lock. Evicts down to a fraction of the cap rather
        than to the cap exactly, so the next append does not trigger another
        delete immediately.
        """
        assert self._max_events is not None
        target = max(1, int(self._max_events * _EVICT_TO_RATIO))
        surplus = self._row_count - target
        if surplus <= 0:
            return

        # The same ordering is used to read the doomed rows and to delete them.
        # Nothing can change in between - the lock is held and the connection is
        # serialised - so both statements select exactly the same rows.
        order = f"ORDER BY ({_SEVERITY_EXPRESSION}) ASC, ingested_at ASC, event_id ASC"

        doomed = self._conn.execute(
            f"SELECT ingested_at, level FROM events {order} LIMIT ?", (surplus,)
        ).fetchall()
        if not doomed:
            return

        ingested = sorted(row[0] for row in doomed)
        breakdown: dict[str, int] = {}
        for _, level in doomed:
            key = level if level is not None else "unscored"
            breakdown[key] = breakdown.get(key, 0) + 1

        # One statement with a subquery, not one DELETE per row: at the real cap
        # a batch is ~100k rows, and both a per-row executemany and an IN clause
        # of that width would stall every collector waiting on this lock (SQLite
        # caps bound parameters well below that).
        self._conn.execute(
            f"DELETE FROM events WHERE event_id IN "
            f"(SELECT event_id FROM events {order} LIMIT ?)",
            (surplus,),
        )
        self._row_count -= len(doomed)

        self._conn.execute(
            "INSERT INTO overflow_drops (dropped_at, event_count, oldest_ingested_at, "
            "newest_ingested_at, level_breakdown, reason) VALUES (?, ?, ?, ?, ?, ?)",
            (
                self._clock().isoformat(),
                len(doomed),
                ingested[0],
                ingested[-1],
                json.dumps(breakdown, ensure_ascii=False),
                f"row count exceeded max_events={self._max_events}",
            ),
        )
        logger.warning(
            "storage full: dropped %d events (%s) spanning %s to %s. "
            "Data from this window is now incomplete.",
            len(doomed),
            breakdown,
            ingested[0],
            ingested[-1],
        )

    def drop_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """Every overflow drop, newest first. Empty means nothing was discarded."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT drop_id, dropped_at, event_count, oldest_ingested_at, "
                "newest_ingested_at, level_breakdown, reason FROM overflow_drops "
                "ORDER BY drop_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        keys = (
            "drop_id",
            "dropped_at",
            "event_count",
            "oldest_ingested_at",
            "newest_ingested_at",
            "level_breakdown",
            "reason",
        )
        entries = [dict(zip(keys, row)) for row in rows]
        for entry in entries:
            entry["level_breakdown"] = json.loads(entry["level_breakdown"])
        return entries

    def dropped_event_count(self) -> int:
        """Total events discarded to overflow. Non-zero means a gap in the data."""
        with self._lock:
            return int(
                self._conn.execute(
                    "SELECT COALESCE(SUM(event_count), 0) FROM overflow_drops"
                ).fetchone()[0]
            )

    @property
    def max_events(self) -> int | None:
        return self._max_events

    def get(self, event_id: str) -> Event | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        return self._to_event(row) if row else None

    def query(
        self,
        *,
        tenant_id: str | None = None,
        source: EventSource | None = None,
        level: RiskLevel | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """Filter stored events. Ranges apply to `ingested_at`."""
        clauses: list[str] = []
        params: list[Any] = []
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if source is not None:
            clauses.append("source = ?")
            params.append(source.value)
        if level is not None:
            clauses.append("level = ?")
            params.append(level.value)
        if since is not None:
            clauses.append("ingested_at >= ?")
            params.append(since.isoformat())
        if until is not None:
            clauses.append("ingested_at <= ?")
            params.append(until.isoformat())

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM events{where} "
                "ORDER BY ingested_at DESC, event_id DESC LIMIT ?",
                params,
            ).fetchall()
        return [self._to_event(row) for row in rows]

    def count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def verdict_types(self, event_ids: Iterable[str]) -> dict[str, str | None]:
        """Read the generated column directly - used to prove it matches Python."""
        ids = list(event_ids)
        if not ids:
            return {}
        marks = ", ".join("?" * len(ids))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT event_id, verdict_type FROM events WHERE event_id IN ({marks})", ids
            ).fetchall()
        return dict(rows)

    def column_names(self) -> list[str]:
        """Every column on `events`, generated ones included.

        table_xinfo, not table_info: the latter omits VIRTUAL generated
        columns, which would hide `verdict_type` from the isolation tests.
        """
        with self._lock:
            return [
                row[1] for row in self._conn.execute("PRAGMA table_xinfo(events)").fetchall()
            ]

    def stored_column_names(self) -> list[str]:
        """Only the columns that hold written data.

        The `hidden` flag is 0 for an ordinary column, 2 for VIRTUAL and 3 for
        STORED generated columns.
        """
        with self._lock:
            return [
                row[1]
                for row in self._conn.execute("PRAGMA table_xinfo(events)").fetchall()
                if row[6] == 0
            ]

    def _to_event(self, row: tuple[Any, ...]) -> Event:
        data = dict(zip(_COLUMNS, row))
        for key in ("raw_attributes", "extracted_features", "explanation"):
            data[key] = json.loads(data[key])
        for key in ("degraded_layers", "triggered_rule_ids"):
            data[key] = tuple(json.loads(data[key]))
        data["enforced"] = bool(data["enforced"])
        return Event.from_dict(data)
