"""Proof that events and identities are separated, and stay that way.

The spec asks for two physically separate tables joined in exactly one
auditable place. These tests check the separation holds in the files on disk,
in the SQL that can be issued, and - for the part no runtime check can cover -
in the source itself.
"""

from __future__ import annotations

import ast
import sqlite3
from pathlib import Path

import pytest

from ebabf.config import AgentConfig
from ebabf.storage import EventStore, IdentityStore, TenantPseudonymizer
from tests.conftest import make_event

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "ebabf"

# Restricted methods, and the only module permitted to call each.
RESTRICTED_CALLERS = {
    "load_forward_map_internal": {"pseudonymizer.py"},
    "begin_break_glass_access": {"bridge.py"},
    "resolve_subject_with_grant": {"bridge.py"},
}


class TestPhysicalSeparation:
    def test_two_distinct_files(self, config: AgentConfig) -> None:
        assert config.event_db_path != config.identity_db_path
        assert config.event_db_path.parent != config.identity_db_path.parent

    def test_identity_lives_in_its_own_directory(self, config: AgentConfig) -> None:
        """Separate directories so they can carry separate permissions -
        which is what makes spec decision 12 technical rather than policy."""
        assert config.identity_key_path.parent == config.identity_db_path.parent
        assert config.event_db_path.parent != config.identity_key_path.parent

    def test_events_database_holds_no_identity_table(
        self, event_store: EventStore, identity_store: IdentityStore, config: AgentConfig
    ) -> None:
        conn = sqlite3.connect(config.event_db_path)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        assert "identity_map" not in tables
        assert "identity_access_log" not in tables
        assert "events" in tables

    def test_identity_database_holds_no_events_table(
        self, identity_store: IdentityStore, config: AgentConfig
    ) -> None:
        conn = sqlite3.connect(config.identity_db_path)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        assert "events" not in tables
        assert {"identity_map", "identity_access_log"} <= tables


class TestEventsCarryNoIdentity:
    def test_no_identity_column_exists(self, event_store: EventStore) -> None:
        columns = set(event_store.column_names())
        forbidden = {"username", "user", "subject", "uid", "email", "real_name", "owner"}
        assert columns & forbidden == set()
        assert "subject_pseudonym" in columns

    def test_a_real_username_never_reaches_the_events_file(
        self, event_store: EventStore, pseudonymizer: TenantPseudonymizer, config: AgentConfig
    ) -> None:
        pseudonym = pseudonymizer.pseudonymize("alice@example.com")
        event_store.append(make_event(subject_pseudonym=pseudonym))
        event_store.close()
        assert b"alice@example.com" not in config.event_db_path.read_bytes()

    def test_the_schema_refuses_a_raw_identity(self) -> None:
        with pytest.raises(ValueError):
            make_event(subject_pseudonym="alice")


class TestNoJoinIsPossible:
    def test_event_store_connection_cannot_see_identity_tables(
        self, event_store: EventStore, identity_store: IdentityStore
    ) -> None:
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            event_store._conn.execute("SELECT * FROM identity_map")

    def test_identity_store_connection_cannot_see_events(
        self, event_store: EventStore, identity_store: IdentityStore
    ) -> None:
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            identity_store._conn.execute("SELECT * FROM events")

    def test_no_attach_statement_anywhere_in_the_package(self) -> None:
        """ATTACH is the one SQL statement that would make a join possible.

        Scans string literals rather than raw file text: a comment explaining
        that ATTACH is never used is not an ATTACH.
        """
        offenders: list[str] = []
        for path in SRC_ROOT.rglob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if "attach " in node.value.lower():
                        offenders.append(f"{path.name}:{node.lineno}")
        assert offenders == [], f"ATTACH found in SQL at {offenders}"


class TestRestrictedInterfacesHaveOnePermittedCaller:
    """Guards the constraint a runtime check cannot: that nothing new starts
    calling these six months from now."""

    @staticmethod
    def _calls_in(path: Path) -> set[str]:
        tree = ast.parse(path.read_text())
        found: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in RESTRICTED_CALLERS:
                    found.add(node.func.attr)
        return found

    @pytest.mark.parametrize("method", sorted(RESTRICTED_CALLERS))
    def test_only_the_permitted_module_calls_it(self, method: str) -> None:
        permitted = RESTRICTED_CALLERS[method]
        callers = {
            path.name
            for path in SRC_ROOT.rglob("*.py")
            if method in self._calls_in(path)
        }
        assert callers <= permitted, (
            f"{method} is restricted to {sorted(permitted)}, but is also called by "
            f"{sorted(callers - permitted)}. Route the access through "
            f"ebabf.storage.bridge instead."
        )

    @pytest.mark.parametrize("method", sorted(RESTRICTED_CALLERS))
    def test_the_restriction_is_documented_on_the_method(self, method: str) -> None:
        source = (SRC_ROOT / "storage" / "identity_store.py").read_text()
        index = source.index(f"def {method}")
        assert "RESTRICTED" in source[index : index + 1200]

    def test_only_the_bridge_imports_both_stores(self) -> None:
        holders: set[str] = set()
        for path in SRC_ROOT.rglob("*.py"):
            text = path.read_text()
            if "EventStore" in text and "IdentityStore" in text and path.name != "__init__.py":
                holders.add(path.name)
        assert holders == {"bridge.py"}, (
            f"only the bridge may hold both stores; also found: {sorted(holders - {'bridge.py'})}"
        )
