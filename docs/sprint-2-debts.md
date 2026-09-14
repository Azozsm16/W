# Declared debts after Sprint 2

Sprint 1's debts still stand (see `sprint-1-debts.md`). These are new.

## `file_entropy_change` is gone, not deferred

Dropped by decision D-010, because computing it means reading file content and
principle 5 forbids that. This is a **closed** decision, not a gap waiting to
be filled. Reopening it would need a privacy review, not a sprint.

**What it costs**: encryption that is slow and preserves file sizes and names
may pass this layer unremarked. The anomaly layer in Sprint 4 is the next line
of defence.

## Packet capture cost is unmeasured

Spec 13 caps CPU at 5% averaged over an hour under realistic load. Python-level
capture is the most expensive component in the agent, and no measurement exists
yet - this host generates almost no traffic, so a number taken here would be
meaningless.

`PacketSource` is an interface so the implementation can be replaced once
Sprint 9 measures it under load. If capture turns out to breach the budget, the
fallback is socket-table polling plus `/proc/net/nf_conntrack`, at the cost of
missing short-lived beacon connections.

## Network attribution is best-effort

Flows are matched to users through a socket-table snapshot taken once per
sweep. Two gaps:

- A connection that opens and closes between sweeps is never in the table, and
  is recorded against `__host__`.
- Without privileges the socket table is partial, so most flows are
  host-attributed.

Both are visible on the event as `subject_attributed: false`, so a consumer
can tell an unattributed flow from an attributed one. Reliable attribution
needs eBPF socket tracing, which is out of scope for v1.

## DNS names are not retained

Only `dns_entropy` is stored, per the feature table in spec 5.2. Layer 4
(Reputation, spec 6.2) will need the domains themselves to match against threat
intelligence. That is a Sprint 4 requirement and a separate privacy decision;
it is not assumed here.

## File actor attribution

inotify cannot say which process changed a file, so events are attributed by
path ownership (D-013). A file written under `/home/alice` by a compromised
service running as root is attributed to alice. fanotify or auditd would fix
this and are out of scope for v1.

## Baseline recording is manual

`ebabf-agent baseline --db baseline.db` runs the agent with enforcement off and
writes to a separate database. Nothing yet schedules it for the 7-14 days spec
10.1 requires, verifies the host was clean before recording (spec 15, Baseline
Poisoning), or reports progress. Those belong with the feature pipeline in
Sprint 3.

## No service unit

The agent runs in the foreground and stops on SIGINT or SIGTERM. There is no
systemd unit, no restart policy, and no agent self-protection (spec 11.4:
signing, integrity checking, mTLS). Spec 11.3 also requires that tampering with
the agent raise a Critical event; the kill-switch detects tampering with its
own sentinel, but nothing watches the agent binary itself.

## Retention still not implemented

Unchanged from Sprint 1. Events now arrive from four collectors instead of one,
so the three-tier policy in spec 11.2 matters more than it did, but it remains
Sprint 7 work.
