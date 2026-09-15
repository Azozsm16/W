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
import sys
from dataclasses import replace
from pathlib import Path
from typing import Sequence

from ebabf.collectors.base import CollectorContext
from ebabf.collectors.registry import CollectorRegistry, default_registry
from ebabf.config import AgentConfig
from ebabf.engine.decision import PassThroughDecisionEngine
from ebabf.engine.enforcement import NoOpEnforcementEngine
from ebabf.engine.killswitch import KillSwitch
from ebabf.packaging import (
    EXIT_STORAGE_HALTED,
    UnitSpec,
    default_executable,
    render_unit,
    validate_unit,
)
from ebabf.runner import AgentRunner
from ebabf.storage import EventStore, IdentityCipher, IdentityStore, TenantPseudonymizer
from ebabf.storage.event_store import StorageHalted
from ebabf.storage.event_store import DEFAULT_GAP_THRESHOLD_SECONDS

__all__ = ["build_agent", "recording_status", "format_status", "main"]

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
        event_db_path or config.event_db_path,
        max_events=config.max_stored_events,
        min_free_bytes=config.min_free_bytes,
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




def recording_status(
    store: EventStore, *, gap_threshold: float = DEFAULT_GAP_THRESHOLD_SECONDS
) -> dict[str, object]:
    """Everything needed to tell a healthy recording from a holed one.

    Collecting data on trust is how a fortnight gets wasted. The three numbers
    that matter are the span actually covered, the gaps inside it, and whether
    anything was discarded - none of which is visible from the event count.
    """
    span = store.span()
    gaps = store.find_gaps(min_seconds=gap_threshold)
    covered = span["span_hours"]
    lost_hours = round(sum(g["duration_seconds"] for g in gaps) / 3600, 2)

    return {
        "database": str(store.path),
        "events": span["count"],
        "first_event": span["first"],
        "last_event": span["last"],
        "span_hours": covered,
        "effective_hours": round(covered - lost_hours, 2) if covered is not None else None,
        "gap_threshold_seconds": gap_threshold,
        "gaps": gaps,
        "gap_count": len(gaps),
        "hours_lost_to_gaps": lost_hours,
        "recorded_gaps": store.coverage_gap_log(limit=20),
        "events_dropped_to_overflow": store.dropped_event_count(),
        "free_bytes": store.free_bytes(),
        "max_events": store.max_events,
        "halted": store.is_halted,
        "halted_reason": store.halted_reason,
    }


def format_status(status: dict[str, object]) -> str:
    """Render `recording_status` for a terminal."""
    lines: list[str] = []
    add = lines.append

    add(f"database        {status['database']}")
    add(f"events          {status['events']:,}")
    add(f"first event     {status['first_event'] or '-'}")
    add(f"last event      {status['last_event'] or '-'}")

    span = status["span_hours"]
    effective = status["effective_hours"]
    if span is None:
        add("span            - (nothing recorded yet)")
    else:
        add(f"span            {span:.2f} h wall clock")
        add(f"covered         {effective:.2f} h after removing gaps")
        add(f"                {effective / 24:.2f} of the 7-14 days a baseline needs")

    free_gb = status["free_bytes"] / 1e9
    add(f"free disk       {free_gb:.1f} GB")
    cap = status["max_events"]
    add(f"event cap       {f'{cap:,}' if cap else 'unbounded'}")

    dropped = status["events_dropped_to_overflow"]
    add(f"dropped         {dropped:,}" + ("  <-- the data has a hole" if dropped else ""))

    gaps = status["gaps"]
    threshold_minutes = status["gap_threshold_seconds"] / 60
    if not gaps:
        add(f"gaps            none over {threshold_minutes:.0f} minutes")
    else:
        add(
            f"gaps            {status['gap_count']} over {threshold_minutes:.0f} minutes, "
            f"{status['hours_lost_to_gaps']:.2f} h lost"
        )
        for gap in gaps[:10]:
            add(
                f"                {gap['start']} -> {gap['end']}  "
                f"({gap['duration_seconds'] / 3600:.2f} h)"
            )
        if len(gaps) > 10:
            add(f"                ... and {len(gaps) - 10} more")

    recorded = status["recorded_gaps"]
    if recorded:
        add(f"declared        {len(recorded)} outage(s) the agent recorded about itself")
        for entry in recorded[:5]:
            add(f"                [{entry['kind']}] {entry['detail']}")

    if status["halted"]:
        add("")
        add(f"HALTED          {status['halted_reason']}")
        add("                Nothing is being recorded. Free space, then restart.")

    return "\n".join(lines)


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

    status = sub.add_parser(
        "status", help="report what has actually been recorded, and any gaps in it"
    )
    status.add_argument("--db", type=Path, default=None, help="database to inspect")
    status.add_argument(
        "--gap-minutes",
        type=float,
        default=DEFAULT_GAP_THRESHOLD_SECONDS / 60,
        help="a break longer than this counts as a gap",
    )
    status.add_argument("--json", action="store_true", help="machine-readable output")

    unit = sub.add_parser(
        "unit", help="render a systemd unit, validated with systemd-analyze"
    )
    unit.add_argument("--mode", choices=("run", "baseline"), default="run")
    unit.add_argument("--user", default="root")
    unit.add_argument("--db", type=Path, default=None, help="baseline database path")
    unit.add_argument(
        "--install",
        action="store_true",
        help="write the unit to /etc/systemd/system instead of printing it",
    )

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    config = AgentConfig()

    if args.command == "status":
        return _status_command(args, config)
    if args.command == "unit":
        return _unit_command(args, config)

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
    except StorageHalted as exc:
        # Deliberate stop, already on the record. Exiting with this specific
        # code tells systemd not to restart into the same full disk; the unit
        # names it in RestartPreventExitStatus.
        logger.critical("exiting: %s", exc)
        return EXIT_STORAGE_HALTED
    finally:
        event_store.close()
        identity_store.close()
    return 0


def _status_command(args: object, config: AgentConfig) -> int:
    path = getattr(args, "db", None) or config.event_db_path
    if not Path(path).exists():
        print(f"no database at {path}: nothing has been recorded yet")
        return 1
    # Opened with the configured cap so the report names the limit the running
    # agent applies, not the default of a read-only handle.
    store = EventStore(
        path, max_events=config.max_stored_events, min_free_bytes=config.min_free_bytes
    )
    try:
        status = recording_status(store, gap_threshold=args.gap_minutes * 60)
    finally:
        store.close()
    if args.json:
        print(json.dumps(status, indent=2, ensure_ascii=False))
    else:
        print(format_status(status))
    return 0


def _unit_command(args: object, config: AgentConfig) -> int:
    extra: tuple[str, ...] = ()
    name = "ebabf-agent"
    if args.mode == "baseline":
        name = "ebabf-baseline"
        extra = ("--db", str(args.db or Path("/var/lib/ebabf/baseline.db")))

    spec = UnitSpec(
        name=name,
        description=(
            "EB-ABF benign baseline recording"
            if args.mode == "baseline"
            else "EB-ABF behavioural firewall agent"
        ),
        executable=default_executable(),
        command=args.mode,
        user=args.user,
        working_directory=config.event_db_path.parent,
        extra_args=extra,
    )
    text = render_unit(spec)

    problems = validate_unit(text, name=spec.filename)
    if problems:
        print("systemd did not accept this unit:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        # A directive systemd ignores is worse than one it rejects: the unit
        # starts and quietly lacks the protection it claims.
        print("refusing to emit an unvalidated unit", file=sys.stderr)
        return 1

    if not args.install:
        print(text)
        print(f"# validated with systemd-analyze. To install:", file=sys.stderr)
        print(f"#   sudo tee /etc/systemd/system/{spec.filename} <<'EOF'", file=sys.stderr)
        print(f"#   ... the text above ...", file=sys.stderr)
        print(f"#   EOF", file=sys.stderr)
        print(f"#   sudo systemctl daemon-reload", file=sys.stderr)
        print(f"#   sudo systemctl enable --now {spec.name}", file=sys.stderr)
        return 0

    target = Path("/etc/systemd/system") / spec.filename
    try:
        target.write_text(text, encoding="utf-8")
    except OSError as exc:
        print(f"could not write {target}: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {target}")
    print(f"now run: systemctl daemon-reload && systemctl enable --now {spec.name}")
    return 0
