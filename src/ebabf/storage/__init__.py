"""Storage. Two physically separate SQLite files, joined in exactly one place."""

from ebabf.storage.bridge import BreakGlassDenied, resolve_subject_for_event
from ebabf.storage.crypto import IdentityCipher, InsecureKeyFile, create_key, load_key
from ebabf.storage.event_store import EventStore
from ebabf.storage.identity_store import AccessGrant, IdentityStore, PseudonymNotFound
from ebabf.storage.pseudonymizer import TenantPseudonymizer

__all__ = [
    "EventStore",
    "IdentityStore",
    "AccessGrant",
    "PseudonymNotFound",
    "TenantPseudonymizer",
    "IdentityCipher",
    "InsecureKeyFile",
    "create_key",
    "load_key",
    "resolve_subject_for_event",
    "BreakGlassDenied",
]
