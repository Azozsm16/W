"""Shared fixtures. Every test gets its own temp directory and its own stores."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import pytest

from ebabf.collectors.base import CollectorContext
from ebabf.config import AgentConfig
from ebabf.engine.decision import DecisionOutcome
from ebabf.engine.enforcement import EnforcementEngine, EnforcementResult
from ebabf.engine.killswitch import KillSwitch, TamperReport
from ebabf.schema import Decision, Event, EventSource
from ebabf.storage import EventStore, IdentityCipher, IdentityStore, TenantPseudonymizer

FIXED_TIME = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def config(tmp_path: Path) -> AgentConfig:
    return AgentConfig.for_testing(tmp_path)


@pytest.fixture()
def cipher(config: AgentConfig) -> IdentityCipher:
    return IdentityCipher.from_key_file(config.identity_key_path, create_if_missing=True)


@pytest.fixture()
def identity_store(config: AgentConfig, cipher: IdentityCipher) -> Iterator[IdentityStore]:
    with IdentityStore(config.identity_db_path, cipher) as store:
        yield store


@pytest.fixture()
def event_store(config: AgentConfig) -> Iterator[EventStore]:
    with EventStore(config.event_db_path) as store:
        yield store


@pytest.fixture()
def pseudonymizer(identity_store: IdentityStore, config: AgentConfig) -> TenantPseudonymizer:
    return TenantPseudonymizer(identity_store, config.tenant_id)


@pytest.fixture()
def collector_context(
    config: AgentConfig, pseudonymizer: TenantPseudonymizer
) -> CollectorContext:
    return CollectorContext(
        host_id=config.host_id,
        tenant_id=config.tenant_id,
        pseudonymizer=pseudonymizer,
    )


@pytest.fixture()
def tamper_reports() -> list[TamperReport]:
    return []


@pytest.fixture()
def kill_switch(config: AgentConfig, tamper_reports: list[TamperReport]) -> KillSwitch:
    return KillSwitch(
        config.kill_switch_path,
        trusted_owner_uid=os.getuid(),
        on_tamper=tamper_reports.append,
    )


def make_event(**overrides: object) -> Event:
    """A minimal valid Event. Scoring fields stay unset unless overridden."""
    base: dict[str, object] = {
        "event_id": "EVT-test-0001",
        "timestamp": FIXED_TIME,
        "host_id": "test-host",
        "tenant_id": "test-tenant",
        "subject_pseudonym": "USR-" + "0" * 32,
        "source": EventSource.PROCESS,
    }
    base.update(overrides)
    return Event(**base)  # type: ignore[arg-type]


class AlwaysBlockEngine(EnforcementEngine):
    """Test double that would enforce, so the guards above it can be observed."""

    name = "always-block"

    def __init__(self, *, enabled: bool, kill_switch: KillSwitch) -> None:
        super().__init__(enabled=enabled, kill_switch=kill_switch)
        self.calls = 0

    def _enforce(self, outcome: DecisionOutcome) -> EnforcementResult:
        self.calls += 1
        return EnforcementResult(enforced=True, blocked_reason=None, detail="blocked")


def blocking_outcome() -> DecisionOutcome:
    """A decision that genuinely asks for enforcement."""
    return DecisionOutcome(event=make_event(decision=Decision.BLOCK_AND_ISOLATE))
