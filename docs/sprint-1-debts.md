# Declared debts after Sprint 1

Things that are deliberately not built, so that nothing here reads as done
when it is not.

## Break-Glass — two of five conditions outstanding

Section 18.4 requires five conditions. Three are enforced today by
`ebabf.storage.bridge.resolve_subject_for_event`:

- a written reason, non-empty;
- a second approver, who may not be the requester (two-person rule);
- an audit row written **before** decryption, not after - written after, any
  exception in between yields a disclosure with no record.

The severity gate is present and self-arming (see D-009). Outstanding:

| Condition | Blocked on | Sprint |
|---|---|---|
| Tamper-evident audit log (hash chaining) | Immutable Audit Log | 7 |
| Notifying the subject afterwards | RBAC and a notification channel | 7 |

Also outstanding: **denied** Break-Glass attempts are logged through Python's
logging only, not persisted. Persisting them belongs with the audit log
proper in Sprint 7; a half-built audit schema now would be worse than the
declared gap.

## Collector coverage

`is_signed` is reported as `None` on every process. Linux has no universal
binary signature to check, and `False` would assert that we looked and found
it unsigned. Package provenance (`dpkg -S` and friends) arrives with the
inventory collector in **Sprint 6**; until then the honest value is unknown.

`cpu_percent` is `None` on the first sighting of each process, for the same
reason: psutil measures CPU between two observations, and the first has
nothing to measure against.

No filtering of kernel threads. Deciding what is worth observing is a feature
pipeline concern (**Sprint 3**), not a collection concern.

## Concurrency

Pseudonym minting is guarded by a lock within one process. Two agent
processes sharing one `identity.db` could mint two pseudonyms for the same
subject - the uniqueness guard is the in-memory map, and ciphertext cannot be
indexed to enforce it in SQL (see D-005). v1 runs a single agent process. A
multi-process deployment needs a transaction-level guard first.

## Retention

The three-tier retention policy of section 11.2 is not implemented. The
column it will key off (`ingested_at`) exists and is populated, which is the
part that could not be added later without a migration.

## Not started, by design

Everything in Sprints 2-9: feature extraction, the five scoring layers,
context modifiers, the VIP module, graduated response, RBAC, the audit log,
Training Mode, the Arabic explanation generator, ECC evidence, and the
dashboard.
