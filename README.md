# EB-ABF — Evidence-Based Adaptive Behavioral Firewall

Linux host agent that judges program **behaviour** rather than identity,
emitting a risk score and a separate confidence score, and acting on the two
together.

Reference specification: [`docs/behavioral-firewall-spec.md`](docs/behavioral-firewall-spec.md).
Implementation decisions: [`docs/decisions.md`](docs/decisions.md).

## Status — Sprint 1 (Foundation) complete

| Component | Where |
|---|---|
| Event schema (the contract) | `src/ebabf/schema/` |
| Decision engine, separate from enforcement | `src/ebabf/engine/decision.py` |
| Enforcement engine, one setting disables it | `src/ebabf/engine/enforcement.py` |
| Kill-switch | `src/ebabf/engine/killswitch.py` |
| Storage: events and identity, physically separate | `src/ebabf/storage/` |
| Process collector | `src/ebabf/collectors/process.py` |

Sprints 2-9 are not started. Declared gaps: [`docs/sprint-1-debts.md`](docs/sprint-1-debts.md).

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Test

```bash
.venv/bin/python -m pytest
```

## Kill-switch

Halts every enforcement action immediately. No restart, no server contact;
detection and logging carry on.

```bash
ebabf-killswitch engage --reason "blocking our build agent" --actor amal
ebabf-killswitch status
ebabf-killswitch release --actor amal
```

The sentinel must live in a directory owned by the agent's user with mode
0700. A sentinel that fails the ownership or permission check does **not**
halt enforcement, and is reported as a tampering attempt.

## Layout

```
src/ebabf/     implementation
tests/         pytest
reference/     read-only reference material, off the build path
experiments/   weight-tuning records (Sprint 6 onward)
docs/          specification and decision log
```
