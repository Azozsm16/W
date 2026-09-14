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
