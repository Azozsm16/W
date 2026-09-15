# EB-ABF — Evidence-Based Adaptive Behavioral Firewall

Linux host agent that judges program **behaviour** rather than identity,
emitting a risk score and a separate confidence score, and acting on the two
together.

Reference specification: [`docs/behavioral-firewall-spec.md`](docs/behavioral-firewall-spec.md).
Implementation decisions: [`docs/decisions.md`](docs/decisions.md).

## Status — Sprints 1 and 2 complete

**Sprint 1 — Foundation**

| Component | Where |
|---|---|
| Event schema (the contract) | `src/ebabf/schema/` |
| Decision engine, separate from enforcement | `src/ebabf/engine/decision.py` |
| Enforcement engine, one setting disables it | `src/ebabf/engine/enforcement.py` |
| Kill-switch | `src/ebabf/engine/killswitch.py` |
| Storage: events and identity, physically separate | `src/ebabf/storage/` |
| Process collector | `src/ebabf/collectors/process.py` |

**Sprint 2 — Collectors**

| Component | Where |
|---|---|
| Network collector (packet capture, headers only) | `src/ebabf/collectors/network.py` |
| File monitor (inotify) | `src/ebabf/collectors/filesystem.py` |
| User activity collector (UEBA) | `src/ebabf/collectors/user_activity.py` |
| Platform abstraction and coverage reporting | `src/ebabf/collectors/registry.py` |
| Agent runner and baseline recording | `src/ebabf/runner.py`, `src/ebabf/bootstrap.py` |

Sprints 3-9 are not started. Declared gaps:
[`docs/sprint-1-debts.md`](docs/sprint-1-debts.md),
[`docs/sprint-2-debts.md`](docs/sprint-2-debts.md).

## Run the agent

```bash
ebabf-agent coverage              # which collectors can run on this host
ebabf-agent run --interval 30     # sweep every 30s
ebabf-agent baseline --db baseline.db   # record a clean Benign Baseline (spec 10.1)
ebabf-agent status --db baseline.db     # what was actually recorded, and any gaps
ebabf-agent unit --mode baseline        # a systemd unit, validated before it is printed
```

### Recording a baseline that survives a fortnight

A 7-14 day recording must not stop quietly. Install it as a service:

```bash
ebabf-agent unit --mode baseline --db /var/lib/ebabf/baseline.db | \
  sudo tee /etc/systemd/system/ebabf-baseline.service
sudo systemctl daemon-reload
sudo systemctl enable --now ebabf-baseline
```

Then check it daily. `status` reports the hours actually covered, not the hours
elapsed:

```
span            13.46 h wall clock
covered         7.45 h after removing gaps
gaps            1 over 10 minutes, 6.01 h lost
dropped         184  <-- the data has a hole
```

The agent records an outage whenever it starts after being down, stops writing
with 512 MB of disk still free rather than filling it, and drops the oldest
low-severity events past the row cap - each of these leaves a record, so a
truncated recording cannot pass for a complete one.

Packet capture needs `CAP_NET_RAW`; without it the network collector reports
itself unavailable and the gap is named in the coverage report rather than
passing unnoticed.

## Install

Requires **Linux** (Ubuntu 22.04 or newer) and **Python 3.11+**. The agent
reads `/proc`, inotify and raw sockets, none of which exist on Windows or
macOS; on those the collectors report themselves unavailable rather than
pretending to work.

```bash
sudo apt install -y python3-venv libpcap0.8   # libpcap0.8t64 on Ubuntu 24.04+
git clone https://github.com/Azozsm16/W.git
cd W
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

`libpcap` is what compiles the capture filter. Without it the network collector
reports itself unavailable and says so in `ebabf-agent coverage` - the other
three keep running.

Check what the host supports before anything else:

```bash
.venv/bin/ebabf-agent coverage
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
