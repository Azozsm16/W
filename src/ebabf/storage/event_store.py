"""events.db - event records, with no identity in them, ever.

A separate SQLite file from identity.db, opened on its own connection that
never issues ATTACH. No SQL reachable from this class can join the two.

`verdict_type` is a VIRTUAL generated column: computed from `confidence` on
every read, stored nowhere. A stored copy could disagree with the confidence
beside it; a generated one cannot, by definition of the word.
"""

from __future__ import annotations

import json
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

__all__ = ["EventStore"]

# Built from the same constants the Python property uses, so SQL and Python
# cannot drift apart into two different definitions of "verdict".
_VERDICT_EXPRESSION = (
    "CASE "
    "WHEN confidence IS NULL THEN NULL "
    f"WHEN confidence >= {CONFIDENCE_VERDICT_THRESHOLD} THEN 'verdict' "
    f"WHEN confidence >= {CONFIDENCE_SUSPICION_THRESHOLD} THEN 'suspicion' "
    "ELSE 'unverified' END"
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

    def __init__(self, db_path: Path, *, clock: Callable[[], datetime] = _utc_now) -> None:
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
        return stamped

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
