"""events.db behaviour."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ebabf.schema import Decision, EnforcementBlockedReason, EventSource, RiskLevel
from ebabf.storage import EventStore
from tests.conftest import FIXED_TIME, make_event


class TestIngestedAt:
    def test_stamped_on_append(self, event_store: EventStore) -> None:
        stored = event_store.append(make_event())
        assert stored.ingested_at is not None
        assert stored.ingested_at.tzinfo is not None

    def test_host_supplied_value_is_overwritten(self, tmp_path) -> None:
        """`timestamp` comes from the host and can be moved; this one cannot."""
        receiving_clock = datetime(2026, 6, 1, tzinfo=timezone.utc)
        store = EventStore(tmp_path / "events.db", clock=lambda: receiving_clock)
        forged = datetime(1999, 1, 1, tzinfo=timezone.utc)
        stored = store.append(make_event(ingested_at=forged))
        assert stored.ingested_at == receiving_clock
        assert store.get(stored.event_id).ingested_at == receiving_clock
        store.close()

    def test_separate_from_timestamp(self, tmp_path) -> None:
        receiving_clock = datetime(2026, 6, 1, tzinfo=timezone.utc)
        store = EventStore(tmp_path / "events.db", clock=lambda: receiving_clock)
        stored = store.append(make_event(timestamp=FIXED_TIME))
        assert stored.timestamp == FIXED_TIME
        assert stored.ingested_at == receiving_clock
        store.close()

    def test_queries_filter_on_ingestion_not_host_time(self, tmp_path) -> None:
        clock = datetime(2026, 6, 1, tzinfo=timezone.utc)
        store = EventStore(tmp_path / "events.db", clock=lambda: clock)
        store.append(make_event(timestamp=datetime(1999, 1, 1, tzinfo=timezone.utc)))
        assert len(store.query(since=clock - timedelta(days=1))) == 1
        assert len(store.query(until=clock - timedelta(days=1))) == 0
        store.close()


class TestRoundtrip:
    def test_full_event_survives(self, event_store: EventStore) -> None:
        event = make_event(
            raw_attributes={"exec_path": "/usr/bin/curl", "cpu_percent": None},
            raw_score=0.5,
            context_modifier=1.4,
            final_score=0.7,
            confidence=0.9,
            level=RiskLevel.HIGH,
            degraded_layers=("classifier",),
            triggered_rule_ids=("R-001", "R-002"),
            decision=Decision.SUSPEND,
            explanation={"mitre_technique": "T1071.001"},
        )
        stored = event_store.append(event)
        read_back = event_store.get(event.event_id)
        assert read_back == stored
        assert read_back.raw_attributes["exec_path"] == "/usr/bin/curl"
        assert read_back.triggered_rule_ids == ("R-001", "R-002")

    def test_unevaluated_stays_null_not_zero(self, event_store: EventStore) -> None:
        event_store.append(make_event())
        read_back = event_store.get("EVT-test-0001")
        assert read_back.raw_score is None
        assert read_back.confidence is None
        assert read_back.level is None

    def test_blocked_enforcement_is_recorded(self, event_store: EventStore) -> None:
        event_store.append(
            make_event(
                decision=Decision.BLOCK_AND_ISOLATE,
                enforced=False,
                enforcement_blocked_reason=EnforcementBlockedReason.KILL_SWITCH_ACTIVE,
            )
        )
        read_back = event_store.get("EVT-test-0001")
        assert read_back.decision is Decision.BLOCK_AND_ISOLATE
        assert read_back.enforced is False
        assert (
            read_back.enforcement_blocked_reason
            is EnforcementBlockedReason.KILL_SWITCH_ACTIVE
        )

    def test_arabic_explanation_survives(self, event_store: EventStore) -> None:
        event_store.append(make_event(explanation={"note": "عملية أب غير متوقعة"}))
        assert event_store.get("EVT-test-0001").explanation["note"] == "عملية أب غير متوقعة"


class TestGeneratedVerdictColumn:
    """The database derives verdict_type too, so a stored copy cannot drift."""

    def test_column_is_generated_not_stored(self, event_store: EventStore) -> None:
        assert "verdict_type" in event_store.column_names()
        assert "verdict_type" not in event_store.stored_column_names()
        assert "confidence" in event_store.stored_column_names()

    @pytest.mark.parametrize(
        ("confidence", "expected"),
        [(None, None), (0.2, "unverified"), (0.6, "suspicion"), (0.95, "verdict")],
    )
    def test_sql_matches_python(
        self, event_store: EventStore, confidence: float | None, expected: str | None
    ) -> None:
        event = make_event(confidence=confidence)
        event_store.append(event)
        from_sql = event_store.verdict_types([event.event_id])[event.event_id]
        from_python = event.verdict_type.value if event.verdict_type else None
        assert from_sql == expected
        assert from_sql == from_python

    def test_cannot_be_written_directly(self, event_store: EventStore) -> None:
        event_store.append(make_event(confidence=0.2))
        with pytest.raises(Exception):
            event_store._conn.execute("UPDATE events SET verdict_type = 'verdict'")


class TestConstraints:
    def test_real_identity_is_refused_at_the_database_layer(
        self, event_store: EventStore
    ) -> None:
        """Second line of defence behind the schema's own validation."""
        with pytest.raises(Exception):
            event_store._conn.execute(
                "INSERT INTO events (event_id, timestamp, ingested_at, host_id, tenant_id, "
                "subject_pseudonym, source, raw_attributes, extracted_features, "
                "degraded_layers, triggered_rule_ids, explanation, schema_version) "
                "VALUES ('E','t','t','h','t','alice@example.com','process','{}','{}','[]','[]','{}','1.0.0')"
            )

    def test_enforced_with_a_blocked_reason_is_refused(self, event_store: EventStore) -> None:
        with pytest.raises(Exception):
            event_store._conn.execute(
                "INSERT INTO events (event_id, timestamp, ingested_at, host_id, tenant_id, "
                "subject_pseudonym, source, raw_attributes, extracted_features, "
                "degraded_layers, triggered_rule_ids, explanation, schema_version, "
                "enforced, enforcement_blocked_reason) "
                f"VALUES ('E','t','t','h','t','USR-{'0'*32}','process','{{}}','{{}}','[]','[]','{{}}','1.0.0',1,'fail_open')"
            )

    def test_duplicate_event_id_refused(self, event_store: EventStore) -> None:
        event_store.append(make_event())
        with pytest.raises(Exception):
            event_store.append(make_event())


class TestQuery:
    def test_filters_and_limits(self, event_store: EventStore) -> None:
        for index in range(5):
            event_store.append(
                make_event(
                    event_id=f"EVT-{index:04d}",
                    level=RiskLevel.HIGH if index % 2 else RiskLevel.LOW,
                )
            )
        assert event_store.count() == 5
        assert len(event_store.query(level=RiskLevel.HIGH)) == 2
        assert len(event_store.query(source=EventSource.PROCESS)) == 5
        assert len(event_store.query(source=EventSource.NETWORK)) == 0
        assert len(event_store.query(limit=3)) == 3

    def test_tenant_filter(self, event_store: EventStore) -> None:
        event_store.append(make_event(event_id="EVT-a", tenant_id="acme"))
        event_store.append(make_event(event_id="EVT-b", tenant_id="globex"))
        assert len(event_store.query(tenant_id="acme")) == 1

    def test_missing_event_returns_none(self, event_store: EventStore) -> None:
        assert event_store.get("EVT-nope") is None
