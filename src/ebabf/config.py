"""Agent configuration.

Note what is absent: there is no setting that disables the decision engine.
Spec 4 requires decisions to be computed and logged always, and the surest
way to enforce that is to give the operator no switch for it. Enforcement,
by contrast, has exactly one switch - `enforcement_enabled`.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["AgentConfig", "DEFAULT_TENANT_ID"]

# v1 is a single-host agent, but the field exists from day one (decision 19).
DEFAULT_TENANT_ID = "default"


def _default_host_id() -> str:
    return socket.gethostname() or "unknown-host"


@dataclass(frozen=True, slots=True)
class AgentConfig:
    """Everything the agent needs to start, resolved once at boot."""

    host_id: str = field(default_factory=_default_host_id)
    tenant_id: str = DEFAULT_TENANT_ID

    # Two physically separate SQLite files, not two tables in one file.
    # Separate files can carry separate filesystem permissions, which is what
    # makes spec decision 12 ("Platform Admin: technical isolation, not
    # policy") true rather than aspirational: hand over events.db and the
    # identity mapping remains unreadable.
    event_db_path: Path = Path("/var/lib/ebabf/events.db")
    identity_db_path: Path = Path("/var/lib/ebabf/identity/identity.db")
    identity_key_path: Path = Path("/var/lib/ebabf/identity/identity.key")

    # Kill-switch sentinel. Must live in a directory only the agent's owner
    # can write to - see ebabf.engine.killswitch.
    kill_switch_path: Path = Path("/etc/ebabf/KILL_SWITCH")

    # The single setting that turns enforcement off entirely (spec 4, 14.2).
    # Training Mode (spec 17.1) is this set to False.
    enforcement_enabled: bool = True

    # Whose ownership makes a kill-switch sentinel trustworthy. Defaults to
    # root; overridable because spec 11.4 asks the agent to run under least
    # privilege, and a dedicated service account is the usual way to do that.
    trusted_owner_uid: int = 0

    @classmethod
    def for_testing(cls, root: Path, **overrides: object) -> "AgentConfig":
        """Config rooted at a temp directory, owned by the current user."""
        defaults: dict[str, object] = {
            "host_id": "test-host",
            "tenant_id": "test-tenant",
            "event_db_path": root / "events.db",
            "identity_db_path": root / "identity" / "identity.db",
            "identity_key_path": root / "identity" / "identity.key",
            "kill_switch_path": root / "run" / "KILL_SWITCH",
            "trusted_owner_uid": os.getuid(),
        }
        defaults.update(overrides)
        return cls(**defaults)  # type: ignore[arg-type]
