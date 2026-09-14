"""identity.db - the pseudonym-to-subject mapping, in its own file.

This is the only place real identities exist, and it is a separate SQLite
file from events.db so the two can carry separate filesystem permissions.
That is what makes spec decision 12 real: hand someone events.db and they
still cannot tell who `USR-...` is, because the mapping is not in the file
they hold and the key is not on disk they can read.

Decryption is causally bound to the audit trail. `resolve_subject_with_grant`
accepts only an `AccessGrant`, and a grant can only be produced by
`begin_break_glass_access`, which writes the audit row first and hands back
its row id. There is no code path from ciphertext to plaintext that does not
leave a record - not by convention, by construction.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ebabf.storage.crypto import IdentityCipher

__all__ = ["IdentityStore", "AccessGrant", "PseudonymNotFound"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS identity_map (
    pseudonym          TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    subject_ciphertext BLOB NOT NULL,
    created_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_identity_tenant ON identity_map(tenant_id);

-- Append-only by construction: no UPDATE or DELETE statement against this
-- table exists anywhere in the package. Hash chaining (spec 11.2) lands in
-- Sprint 7; see docs/sprint-1-debts.md.
CREATE TABLE IF NOT EXISTS identity_access_log (
    access_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    pseudonym       TEXT NOT NULL,
    event_id        TEXT,
    actor           TEXT NOT NULL,
    second_approver TEXT NOT NULL,
    reason          TEXT NOT NULL,
    requested_at    TEXT NOT NULL
);
"""


class PseudonymNotFound(KeyError):
    """No mapping row exists for this pseudonym."""


@dataclass(frozen=True, slots=True)
class AccessGrant:
    """Proof that an identity disclosure was recorded before it happened.

    Carries the row id of the audit entry. `resolve_subject_with_grant`
    re-reads that row and checks it names the pseudonym being disclosed, so a
    grant cannot be reused to unmask somebody else.
    """

    access_id: int
    pseudonym: str


class IdentityStore:
    """Owns identity.db. Constructed once, at boot."""

    def __init__(self, db_path: Path, cipher: IdentityCipher) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._cipher = cipher
        # No ATTACH is ever issued on this connection, so no SQL statement
        # reachable from here can join against events.db.
        #
        # check_same_thread=False plus a lock, for the same reason as the event
        # store: pseudonyms are minted from whichever thread a collector sweeps
        # on, not the one that opened the database.
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self._path, isolation_level=None, check_same_thread=False
        )
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)
        self._path.chmod(0o600)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "IdentityStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- writing ------------------------------------------------------------

    def mint_pseudonym(self, tenant_id: str, subject: str) -> str:
        """Create and store a fresh pseudonym for `subject` under `tenant_id`.

        The pseudonym is a uuid4: random, derived from nothing about the
        subject, and scoped per tenant because the row is keyed on the pair -
        so the same person under two tenants gets two unrelated pseudonyms.
        Never rotated; rotating would sever an account's own history and
        destroy any longitudinal analysis (spec 10.4).
        """
        if not tenant_id or not subject:
            raise ValueError("tenant_id and subject are required")
        pseudonym = f"USR-{uuid.uuid4().hex}"
        with self._lock:
            self._conn.execute(
                "INSERT INTO identity_map (pseudonym, tenant_id, subject_ciphertext, created_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    pseudonym,
                    tenant_id,
                    self._cipher.encrypt(subject),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return pseudonym

    # -- restricted interfaces ----------------------------------------------

    def load_forward_map_internal(self, tenant_id: str) -> dict[str, str]:
        """Return {subject: pseudonym} for one tenant.

        RESTRICTED. The sole permitted caller is
        `ebabf.storage.pseudonymizer.TenantPseudonymizer`, which holds the
        result privately and never exposes it. `tests/test_storage_isolation.py`
        fails the build if anything else calls this.

        The direction matters: subject-to-pseudonym is not disclosure - the
        caller must already know the subject, and gets back an opaque label.
        The reverse direction is disclosure, and lives behind Break-Glass.
        Handing out this mapping wholesale would be handing out the reverse
        one too, since a dict is trivially inverted.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT pseudonym, subject_ciphertext FROM identity_map WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
        return {self._cipher.decrypt(ciphertext): pseudonym for pseudonym, ciphertext in rows}

    def begin_break_glass_access(
        self,
        *,
        pseudonym: str,
        actor: str,
        second_approver: str,
        reason: str,
        event_id: str | None = None,
    ) -> AccessGrant:
        """Record an intended disclosure and return the grant that permits it.

        RESTRICTED. The sole permitted caller is
        `ebabf.storage.bridge.resolve_subject_for_event`, which applies the
        Break-Glass policy in spec 18.4 before reaching here.

        The audit row is written before any decryption, not after: written
        after, any exception in between yields a disclosure with no record.
        """
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO identity_access_log "
                "(pseudonym, event_id, actor, second_approver, reason, requested_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    pseudonym,
                    event_id,
                    actor,
                    second_approver,
                    reason,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            access_id = int(cursor.lastrowid)
        return AccessGrant(access_id=access_id, pseudonym=pseudonym)

    def resolve_subject_with_grant(self, grant: AccessGrant) -> str:
        """Decrypt the real identity behind `grant.pseudonym`.

        RESTRICTED. The sole permitted caller is
        `ebabf.storage.bridge.resolve_subject_for_event`.
        """
        if not isinstance(grant, AccessGrant):
            raise TypeError("identity disclosure requires an AccessGrant")

        with self._lock:
            audit_row = self._conn.execute(
                "SELECT pseudonym FROM identity_access_log WHERE access_id = ?",
                (grant.access_id,),
            ).fetchone()
        if audit_row is None:
            raise PermissionError(
                f"access grant {grant.access_id} has no audit record; refusing disclosure"
            )
        if audit_row[0] != grant.pseudonym:
            raise PermissionError(
                "access grant does not match its audit record; refusing disclosure"
            )

        with self._lock:
            row = self._conn.execute(
                "SELECT subject_ciphertext FROM identity_map WHERE pseudonym = ?",
                (grant.pseudonym,),
            ).fetchone()
        if row is None:
            raise PseudonymNotFound(grant.pseudonym)
        return self._cipher.decrypt(row[0])

    # -- read-only introspection (no identities) ----------------------------

    def access_log(self, limit: int = 100) -> list[dict[str, object]]:
        """The disclosure trail. Contains pseudonyms and reasons, no identities."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT access_id, pseudonym, event_id, actor, second_approver, reason, requested_at "
                "FROM identity_access_log ORDER BY access_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        keys = (
            "access_id",
            "pseudonym",
            "event_id",
            "actor",
            "second_approver",
            "reason",
            "requested_at",
        )
        return [dict(zip(keys, row)) for row in rows]

    def count(self, tenant_id: str | None = None) -> int:
        with self._lock:
            if tenant_id is None:
                return int(
                    self._conn.execute("SELECT COUNT(*) FROM identity_map").fetchone()[0]
                )
            return int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM identity_map WHERE tenant_id = ?", (tenant_id,)
                ).fetchone()[0]
            )
