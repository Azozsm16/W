"""Composition root - the only place that wires every layer together.

It holds both stores because building the agent requires both: the identity
store backs the pseudonymiser, the event store receives events. It does not
join them. Correlating a pseudonym back to a person is possible in exactly one
function, `ebabf.storage.bridge.resolve_subject_for_event`, and
`tests/test_storage_isolation.py` fails the build if anything here reaches for
the restricted methods behind it.

Kept apart from `ebabf.runner` so that boundary is visible in the import graph
rather than buried inside the loop.
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from pathlib import Path
from typing import Sequence

from ebabf.collectors.base import CollectorContext
from ebabf.collectors.registry import CollectorRegistry, default_registry
from ebabf.config import AgentConfig
from ebabf.engine.decision import PassThroughDecisionEngine
from ebabf.engine.enforcement import NoOpEnforcementEngine
from ebabf.engine.killswitch import KillSwitch
from ebabf.runner import AgentRunner
from ebabf.storage import EventStore, IdentityCipher, IdentityStore, TenantPseudonymizer

__all__ = ["build_agent", "main"]

logger = logging.getLogger(__name__)


def build_agent(
    config: AgentConfig,
    *,
    registry: CollectorRegistry | None = None,
    only: Sequence[str] | None = None,
    event_db_path: Path | None = None,
) -> tuple[AgentRunner, IdentityStore, EventStore]:
    """Wire a runner from config. Returns the stores so the caller can close them.

    `event_db_path` overrides where events land - that is how baseline
    recording writes to its own database instead of the live one, without any
    change to the event schema.
    """
    registry = registry if registry is not None else default_registry

    cipher = IdentityCipher.from_key_file(config.identity_key_path, create_if_missing=True)
    identity_store = IdentityStore(config.identity_db_path, cipher)
    event_store = EventStore(
        event_db_path or config.event_db_path, max_events=config.max_stored_events
    )

    context = CollectorContext(
        host_id=config.host_id,
        tenant_id=config.tenant_id,
        pseudonymizer=TenantPseudonymizer(identity_store, config.tenant_id),
    )
    collectors, coverage = registry.build_supported(context, only=only)

    kill_switch = KillSwitch(
        config.kill_switch_path, trusted_owner_uid=config.trusted_owner_uid
    )
    runner = AgentRunner(
        collectors=collectors,
        decision_engine=PassThroughDecisionEngine(),
        enforcement_engine=NoOpEnforcementEngine(
            enabled=config.enforcement_enabled, kill_switch=kill_switch
        ),
        event_store=event_store,
        coverage=coverage,
    )
    return runner, identity_store, event_store


def main(argv: list[str] | None = None) -> int:
    """`ebabf-agent run` / `ebabf-agent baseline`."""
    import argparse

    parser = argparse.ArgumentParser(prog="ebabf-agent", description=__doc__)
    parser.add_argument("--interval", type=float, default=30.0, help="seconds between sweeps")
    parser.add_argument("--only", nargs="*", default=None, help="restrict to these collectors")
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="cap on stored events; 0 disables the cap (spec 11.3)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="run the agent")
    baseline = sub.add_parser(
        "baseline",
        help="record a clean Benign Baseline (spec 10.1) - NOT Training Mode",
    )
    baseline.add_argument("--db", type=Path, default=Path("baseline.db"))
    sub.add_parser("coverage", help="report which collectors can run here")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    config = AgentConfig()
    if args.max_events is not None:
        config = replace(config, max_stored_events=args.max_events)
    if args.command == "baseline":
        # Enforcement off while recording a baseline: the machine is known
        # clean, and anything blocked would poison the very data being gathered.
        config = replace(config, enforcement_enabled=False)
        runner, identity_store, event_store = build_agent(
            config, only=args.only, event_db_path=args.db
        )
    else:
        runner, identity_store, event_store = build_agent(config, only=args.only)

    try:
        if args.command == "coverage":
            report = runner.coverage
            print(json.dumps(report.as_dict() if report else {}, indent=2, ensure_ascii=False))
            return 0
        runner.run_forever(interval_seconds=args.interval)
    finally:
        event_store.close()
        identity_store.close()
    return 0
