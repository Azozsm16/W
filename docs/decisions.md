# Decision Log

Decisions settled during implementation that are not already in the
specification's own decision table. The spec's table stays authoritative for
everything in it; nothing here contradicts it.

| # | Decision | Settled | Spec reference |
|---|---|---|---|
| D-001 | Pseudonym format is `USR-<uuid4 hex>` | Sprint 1 | 11.1 |
| D-002 | `WATCHLIST` is a logging marker, not an enforcement action | Sprint 1 | 8, 8.1 |
| D-003 | Matrix 8.1 is authoritative wherever it disagrees with the table in section 8 | Sprint 1 | 8, 8.1 |
| D-004 | Two SQLite files, not two tables in one file | Sprint 1 | 11.2, 18.3 |
| D-005 | Identity encrypted with Fernet, key from a 0600 key file | Sprint 1 | 12 |
| D-006 | `verdict_type` is derived from `confidence`, never stored | Sprint 1 | 9 |
| D-007 | `ingested_at` recorded separately from `timestamp` | Sprint 1 | 11.2, 10.4 |
| D-008 | `context_modifier` bounded `(0, 2]` in the schema | Sprint 1 | 6.4, 13.2 |
| D-009 | Break-Glass severity gate is written to arm itself | Sprint 1 | 18.4 |

---

## D-001 — Pseudonym format: `USR-<uuid4 hex>`

Section 11.1 shows `USR-8842`. That is an illustration, not a binding format:
four digits give ten thousand possible values, so collisions are near-certain
on any real deployment, and a collision means two people's events merge into
one subject.

**Settled**: `USR-` followed by a uuid4 hex, e.g.
`USR-7be59d9227bd4d09ad9b35c9a253712f`.

Mandatory properties:

- **Fully random.** Not derived from any property of the subject - not the
  name, not an email, not a hash of either. There is no key whose compromise
  reveals who anybody is; the mapping is the only link.
- **Scoped per tenant.** The mapping row is keyed on `(tenant_id, subject)`, so
  the same person under two tenants gets two unrelated pseudonyms and no
  cross-tenant correlation is possible even for whoever holds both databases.
- **Stable for the life of the account.** Never rotated: rotation would sever
  an account's own history and destroy the longitudinal analysis that section
  10.4 depends on.

Enforced by `PSEUDONYM_PATTERN` in `ebabf.schema.event` (the Event refuses any
other shape) and by a CHECK constraint on `events.subject_pseudonym`.

## D-002 — `WATCHLIST` is a marker, not an action

Section 8 gives Low as "log + add to watchlist"; matrix 8.1 collapses
Normal/Low to "log" across all three confidence bands.

**Settled**: `WATCHLIST` stays in the `Decision` enum and means *a marker
attached to a logged event* - no alert, no intervention. Consequently
`Decision.WATCHLIST.requires_enforcement` is `False`, and the enforcement
engine is never reached for it.

## D-003 — Matrix 8.1 wins

Where section 8's table and matrix 8.1 disagree, **8.1 is authoritative**. It
is the later and more specific statement: section 8 gives the suggested action
by score alone, while 8.1 adds the confidence dimension and explicitly merges
the two previously separate rules.

## D-004 — Two SQLite files

Section 11.2 requires identity storage separated from event data; decision 12
requires that separation to be *technical, not policy*.

**Settled**: `events.db` and `identity.db` are separate files, in separate
directories, opened on separate connections. No `ATTACH` is issued anywhere in
the package, so no SQL statement reachable from either connection can join
them.

This is what makes the claim testable: hand somebody `events.db` and they
still cannot say who `USR-...` is, because the mapping is not in the file they
hold and the key is not on disk they can read.

## D-005 — Fernet, with the key in a 0600 file

Section 12 names neither a crypto library nor a key source.

**Settled**: Fernet (AES-128-CBC with an HMAC tag) from `cryptography`, key
read at boot from a file that must be mode 0600 in a 0700 directory - the
agent refuses to load a key whose permissions are wider.

Rejected alternatives: an environment variable (leaks through `/proc`, `ps`
and crash dumps) and a boot-time passphrase (blocks unattended restart, which
a host agent needs).

Consequence worth stating: Fernet output is non-deterministic, so ciphertext
cannot be indexed or searched. That is why the forward map is decrypted into
memory once at boot rather than queried per event.

## D-006 — `verdict_type` is derived

Section 9 defines the mapping from confidence to verdict band. Storing the
result beside `confidence` would permit a row where the two disagree.

**Settled**: `Event.verdict_type` is a read-only property, and the `events`
table carries it as a **VIRTUAL generated column** so SQL sees it too without
storing it. `Event.from_dict` discards any `verdict_type` key it is handed.

`confidence is None` yields `verdict_type is None`, not `unverified`: "no
judgement was made" is a different claim from "we judged, and the evidence was
weak".

## D-007 — `ingested_at` separate from `timestamp`

`timestamp` comes from the host. A root-level adversary can move the clock,
and ordinary drift is enough to reorder events.

**Settled**: `ingested_at` is stamped by `EventStore.append` from the store's
own clock, overwriting whatever arrived. Retention (11.2), temporal splitting
(10.4) and every range query key off it. Adding it later would have meant
migrating every stored event.

## D-008 — `context_modifier` bounded `(0, 2]`

Section 6.4's 0.3-1.4 are the calibration values known today, not a law. The
schema pinning them would mean a database migration at the first
re-calibration under 13.2.

**Settled**: the schema rejects only what is impossible - zero or negative
(which would erase the score) and anything above 2.0. The values actually in
use belong in configuration.

Rule: **the schema bounds the impossible, configuration bounds the sensible.**

## D-009 — The Break-Glass severity gate arms itself

Section 18.4 requires a critical severity before an identity may be revealed.
No event carries a `level` until the scoring engine lands in Sprint 4, so a
gate demanding Critical today would refuse every request and be dead code.

**Settled**: written as

```python
if event.level is not None and event.level is not RiskLevel.CRITICAL:
    raise BreakGlassDenied("level below critical threshold")
```

Today it passes, because `level` is None. The moment events start carrying a
level it begins refusing anything below Critical - with no configuration
change and nobody having to remember. There is deliberately no setting that
turns it off; a gate with an off switch is a back door.

---

# Sprint 2 decisions

| # | Decision | Settled | Spec reference |
|---|---|---|---|
| D-010 | `file_entropy_change` is not implemented - the privacy principle wins | Sprint 2 | 5.3, 5.5 |
| D-011 | Network features come from packet capture, headers only | Sprint 2 | 5.2, 12 |
| D-012 | Unattributable flows go to a reserved host subject | Sprint 2 | 5.2, principle 1 |
| D-013 | File events are attributed by path ownership, not by actor | Sprint 2 | 5.3 |
| D-014 | File paths are not stored; only labels, categories and counts | Sprint 2 | 5.3, 11.2 |
| D-015 | Sudo command text is discarded at the parser | Sprint 2 | 5.4, principle 5 |
| D-016 | Watched roots are sensitive paths plus home document directories | Sprint 2 | 5.3 |
| D-017 | Coverage gaps are reported by the registry, never silent | Sprint 2 | 11.3 |

## D-010 — `file_entropy_change` is not implemented

**The conflict**: spec 5.3 lists `file_entropy_change` to catch mass
encryption. Spec 5.5's note and principle 5 both state that file content is
never collected. Entropy cannot be computed without reading file bytes.

**Settled**: the principle wins; the field is dropped. `file_modification_rate`
and `sensitive_path_write` carry the ransomware signal instead, and both are
pure metadata - a mass-encryption run is visible as hundreds of files rewritten
per second without opening any of them.

**What this costs**: slow encryption that preserves file sizes and names may
pass unremarked by this layer. That is the price of the principle, and it is
recorded rather than hidden.

The collector's module holds no file-reading call at all, and a test asserts
so, because a principle checked only by intention decays.

## D-011 — Packet capture, headers only

Spec 12 sanctions `scapy`. Capture was chosen over socket-table polling
because a beacon that opens a 200 ms connection every 60 seconds slips between
polls, and beaconing is the flagship detection.

**Boundary**: choosing capture as the *method* does not relax principle 5 about
*what may be read from it*. The collector reads IP and TCP/UDP header fields,
frame lengths, and DNS question names. Payloads are never parsed, and
`AsyncSniffer` runs with `store=False` so no frame is retained.

**Open risk**: spec 13 caps CPU at 5% under realistic load. Python-level
capture is the most expensive thing in the agent and this has not been
measured yet. `PacketSource` is an interface precisely so the implementation
can be swapped after Sprint 9 measures it.

## D-012 — Unattributable flows go to a reserved host subject

A captured packet carries no pid, so the wire alone cannot say who opened a
connection. Attribution comes from a separate socket-table snapshot, which is
partial without privileges and races against short-lived sockets.

**Settled**: a flow with no matching socket is recorded against `__host__`,
pseudonymised like any other subject, with `subject_attributed: false` on the
event. The alternative - assigning it to a plausible user - is the guessing
principle 1 forbids.

## D-013 — File events are attributed by path, not by actor

inotify reports what changed, never who changed it. Events are therefore
attributed to the owner of the watched root. Real actor attribution needs
fanotify or auditd; both are out of scope for v1 and recorded as debts.

## D-014 — File paths are not stored

Spec 11.2's third retention tier names paths as identifying, alongside
identities and IPs, and `~/Documents/...` frequently is. Events carry the
watched root's label, the sensitive-path category, and counts. Distinct files
are counted through a hash so the number survives while the names do not.

## D-015 — Sudo command text is discarded at the parser

A sudo line in the auth log carries the command that ran, and command lines
routinely carry secrets (`sudo mysql -pHUNTER2`). The parser extracts the fact
that sudo was used and the user who used it, and drops the rest of the line
before it can reach an event.

## D-016 — Watched roots: sensitive paths plus home documents

`/etc`, `~/.ssh` and autostart locations serve `sensitive_path_write`.
Document directories are watched as well because that is where ransomware
encrypts - watching `/etc` alone would miss the case the feature exists for.

inotify's default watch budget is finite, so the collector counts the watches
it holds and warns when it passes half the host's limit. Watches beyond the
limit fail silently at the kernel, which would be an undeclared coverage gap.

## D-017 — Coverage gaps are declared

The registry returns a `CoverageReport` naming every collector that could not
start and why. Spec 11.3 requires a coverage gap to be announced always: a
tool silently missing a whole observation surface is more dangerous than one
plainly switched off, because the operator believes they are covered.

---

## D-018 — Library interfaces are pinned, not remembered

**What went wrong**: `_BufferingHandler.record()` classified filesystem events
with string literals typed from memory - `"created"`, `"deleted"`, `"moved"` -
and folded everything else into `modified`. watchdog 6.0 also emits `opened`,
`closed` and `closed_no_write`.

Measured on a real inotify watch:

| Action | Counted as modifications | Correct |
|---|---|---|
| Writing 20 files | 80 | 40 |
| **Reading 20 files** | **40** | **0** |

A backup job, an antivirus scan or a recursive grep over a documents folder
registered as mass file modification - the ransomware signature - in a system
whose one binding metric is precision (spec 13.1) and whose hard constraint is
five alerts per host per day.

The bug was silent. Nothing failed; the numbers were simply wrong. It would
have reached Sprint 4 as a poisoned baseline.

**Settled**, three parts:

1. Constants are imported from the library, never retyped. `MUTATION_EVENTS`
   is keyed on watchdog's own `EVENT_TYPE_*` values.
2. Classification is a positive allowlist. Anything not a known mutation is not
   counted as one, so a type added by a future watchdog is handled correctly
   rather than absorbed.
3. An unrecognised type raises a warning once and increments `ignored_events`.
   The previous bug survived because it was silent.

`tests/test_library_contracts.py` pins every assumption this agent makes about
psutil, scapy and watchdog - field names, event types, exception classes,
signatures - so a library upgrade fails the build instead of quietly emptying
a field. That file exists because of this bug.

**Rule added to CLAUDE.md**: verify a library's interface before using it;
never assume attribute or function names from memory.

---

## D-019 — Bounded storage, with the drop on the record

Spec 11.3: "local storage full -> drop the oldest low-severity events first,
with the drop logged." Unimplemented until now, and on the critical path: a
7-14 day baseline recording (spec 10.1) at this host's event rate is roughly
three million events, and a store that filled the disk would stop recording
**silently** on day ten. The gap would surface at training time in Sprint 4,
by which point the two weeks are gone.

**Settled**, in three parts:

1. **A cap.** `AgentConfig.max_stored_events`, default 2,000,000. Measured at
   ~420 bytes per event, that bounds the database at roughly 840 MB. Setting it
   to 0 disables the cap - a real choice for a machine with the disk to spare,
   and an explicit one rather than the default.
2. **An eviction order.** Least worth keeping first: severity ascending, then
   age ascending. Severity outranks age, so the oldest Critical event outlives
   the newest Normal one.
3. **A durable record.** Every drop writes a row to `overflow_drops` - when,
   how many, the breakdown by level, the time span lost - and logs at WARNING.

The record is the half that matters. A store that quietly discarded a week of
a baseline still looks complete when you come to train on it; one that says so
can be re-run. `dropped_event_count()` returning non-zero is the signal that
the data has a hole in it.

**Where unscored events rank**: between Low and Medium. Nothing has judged
them, so they are not dropped ahead of an event positively known to be boring,
nor kept ahead of one positively known to be interesting. Uncertainty ranks
between known-boring and known-interesting, and is not silently treated as
either - the same reasoning as spec 6.3's missing-layer rule.

Today every event is unscored, so the order degrades to plain oldest-first,
which is what baseline recording wants. It begins sorting by severity on its
own once the scoring engine lands in Sprint 4 - the self-arming pattern already
used for the Break-Glass severity gate (D-009).

**Named for overflow, not retention.** Spec 11.2's three-tier retention policy
is a different mechanism arriving in Sprint 7. Sharing a name would let one
hide behind the other.

---

## D-020 — Three silent failures closed before the baseline runs

All three were declared as debts and accepted as such. That was wrong: each is
an *undeclared coverage gap*, which decision 11 forbids outright. A 7-14 day
recording that dies quietly is worse than one that never started, because the
dataset still looks complete when a model is trained on it, and the fault is
then diagnosed as a model problem in Sprint 5.

### The unit (`ebabf-agent unit`)

Two findings from checking this systemd rather than recalling it:

- **`Restart=always` alone does not keep a service alive.** The default start
  rate limit is five starts in ten seconds (`DefaultStartLimitBurst=5`,
  `DefaultStartLimitIntervalSec=10s` in system.conf); past it the unit enters
  `failed` and is never restarted. A crash loop would end the recording
  permanently while appearing protected. `StartLimitIntervalSec=0` in `[Unit]`
  removes the limit - the same thing `/lib/systemd/system/modprobe@.service`
  does.
- **A misspelled directive is ignored, not rejected.** `systemd-analyze verify`
  reports `Restrt=always` as "Unknown key name ... ignoring"; the unit starts
  with no restart policy. `ProtectHome=banana` is likewise "Failed to parse ...
  ignoring". Generated units are therefore validated by systemd's own parser
  before install, and an invalid one is refused rather than written.

`RestartPreventExitStatus=78` stops systemd restarting into a disk that is
still full; the reason is already in `coverage_gaps`.

**No sandboxing directives are emitted.** The agent reads /home for the file
monitor and /var/log for authentication. `ProtectHome=` or `ProtectSystem=`
getting either wrong would blind a collector silently, and their runtime effect
could not be verified here (systemd is not PID 1 in this environment, and the
upstream documentation is unreachable). Shipping hardening whose effect is
unverified would add a silent failure while removing three.

### The status command (`ebabf-agent status`)

Prints what was actually recorded, not what was attempted: event count, first
and last timestamps, wall-clock span, **span after subtracting gaps**, every
break over ten minutes with its timestamps, outages the agent recorded about
itself, events dropped to overflow, and free disk.

Gaps are computed from the data with a `LAG()` window function, so it finds
outages nobody recorded - a `kill -9`, a power cut, an agent that never came
back after a reboot. The gap threshold is one constant shared with downtime
detection, so the two can never disagree about what counts as a gap.

### The disk floor

Recording stops with `min_free_bytes` (default 512 MB) still free, writes a
`storage_halted` row, logs at CRITICAL, and raises `StorageHalted`. The danger
was never a full disk; it was a disk filling quietly and leaving an unmarked
hole.

### Two more found while building these

- **The network collector reported itself healthy while capturing nothing.**
  `libpcap` is absent here, so the BPF filter cannot compile - and scapy raises
  that inside the capture thread, where nobody listens. `AsyncSniffer.start()`
  returned cleanly, `sniffer.running` stayed **True**, and the capture thread
  was already dead. `is_available()` now compiles the filter up front, and
  `start()` checks thread liveness and the stored exception, since `running`
  lies.
- **The file monitor watched roots it could not read.** A root that is missing,
  unreadable or refused by the kernel emits exactly what a quiet root emits.
  Unwatchable roots are now listed on the collector and logged as a gap.

A collector that fails to start is also moved out of `CoverageReport.active`
rather than merely logged, so the report can no longer claim a surface that
produces nothing.
