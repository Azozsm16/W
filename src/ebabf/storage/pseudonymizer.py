"""Forward-only pseudonym lookup.

Collectors need subject-to-pseudonym on every single event, which rules out a
database round trip per event. This holds the mapping in memory, loaded once
at boot.

The class deliberately exposes no way to read the map back out. Handing a
caller {subject: pseudonym} would hand them {pseudonym: subject} as well -
one dict comprehension - and every Break-Glass control would be decoration.
You can ask "what is the pseudonym for this subject I already know", and
nothing else: no enumeration, no reverse lookup.
"""

from __future__ import annotations

import threading

from ebabf.storage.identity_store import IdentityStore

__all__ = ["TenantPseudonymizer"]


class TenantPseudonymizer:
    """Pseudonyms for one tenant, cached in memory.

    Caveat worth stating rather than hiding: this in-memory map is invertible
    by anyone who can read the agent's process memory. That is a root-level
    adversary, which spec 3.1 places outside the threat model explicitly. The
    agent cannot label events without knowing who they belong to.
    """

    def __init__(self, store: IdentityStore, tenant_id: str) -> None:
        if not tenant_id:
            raise ValueError("tenant_id is required")
        self._store = store
        self._tenant_id = tenant_id
        self._lock = threading.Lock()
        self._forward: dict[str, str] = store.load_forward_map_internal(tenant_id)

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    def pseudonymize(self, subject: str) -> str:
        """Return the stable pseudonym for `subject`, minting one on first sight."""
        if not isinstance(subject, str) or not subject:
            raise ValueError("subject must be a non-empty string")
        cached = self._forward.get(subject)
        if cached is not None:
            return cached
        with self._lock:
            # Re-check: another thread may have minted while we waited.
            cached = self._forward.get(subject)
            if cached is not None:
                return cached
            pseudonym = self._store.mint_pseudonym(self._tenant_id, subject)
            self._forward[subject] = pseudonym
            return pseudonym

    def known_subject_count(self) -> int:
        """How many subjects are cached. Deliberately a count, not the keys."""
        return len(self._forward)
