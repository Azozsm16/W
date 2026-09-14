"""identity.db: minting, tenant scoping, and the grant-gated reverse lookup."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from ebabf.storage import IdentityCipher, IdentityStore, TenantPseudonymizer
from ebabf.storage.crypto import InsecureKeyFile, create_key, load_key
from ebabf.storage.identity_store import AccessGrant, PseudonymNotFound


class TestPseudonymProperties:
    def test_format(self, pseudonymizer: TenantPseudonymizer) -> None:
        from ebabf.schema import PSEUDONYM_PATTERN

        assert PSEUDONYM_PATTERN.match(pseudonymizer.pseudonymize("alice"))

    def test_random_not_derived_from_the_subject(
        self, identity_store: IdentityStore
    ) -> None:
        """Two stores with the same subject must produce unrelated pseudonyms."""
        a = TenantPseudonymizer(identity_store, "t1").pseudonymize("alice")
        b = TenantPseudonymizer(identity_store, "t2").pseudonymize("alice")
        assert a != b
        assert "alice" not in a and "alice" not in b

    def test_stable_for_the_life_of_the_account(
        self, pseudonymizer: TenantPseudonymizer
    ) -> None:
        """Rotation would sever an account's own history (spec 10.4)."""
        first = pseudonymizer.pseudonymize("alice")
        for _ in range(50):
            assert pseudonymizer.pseudonymize("alice") == first

    def test_stable_across_agent_restarts(
        self, identity_store: IdentityStore
    ) -> None:
        first = TenantPseudonymizer(identity_store, "t").pseudonymize("alice")
        reloaded = TenantPseudonymizer(identity_store, "t")  # simulates a boot
        assert reloaded.pseudonymize("alice") == first
        assert identity_store.count("t") == 1

    def test_scoped_per_tenant(self, identity_store: IdentityStore) -> None:
        """The same person under two tenants gets two unrelated pseudonyms."""
        acme = TenantPseudonymizer(identity_store, "acme").pseudonymize("alice")
        globex = TenantPseudonymizer(identity_store, "globex").pseudonymize("alice")
        assert acme != globex
        assert identity_store.count("acme") == 1
        assert identity_store.count("globex") == 1

    def test_distinct_subjects_get_distinct_pseudonyms(
        self, pseudonymizer: TenantPseudonymizer
    ) -> None:
        names = [f"user{i}" for i in range(200)]
        pseudonyms = {pseudonymizer.pseudonymize(n) for n in names}
        assert len(pseudonyms) == 200

    def test_blank_subject_refused(self, pseudonymizer: TenantPseudonymizer) -> None:
        with pytest.raises(ValueError):
            pseudonymizer.pseudonymize("")


class TestForwardOnly:
    """The cache answers one question only: the pseudonym for a known subject."""

    def test_exposes_no_way_to_read_the_map(
        self, pseudonymizer: TenantPseudonymizer
    ) -> None:
        pseudonymizer.pseudonymize("alice")
        public = {name for name in dir(pseudonymizer) if not name.startswith("_")}
        assert public == {"pseudonymize", "tenant_id", "known_subject_count"}

    def test_count_not_keys(self, pseudonymizer: TenantPseudonymizer) -> None:
        pseudonymizer.pseudonymize("alice")
        pseudonymizer.pseudonymize("bob")
        assert pseudonymizer.known_subject_count() == 2

    def test_no_database_query_per_event(
        self, identity_store: IdentityStore, monkeypatch
    ) -> None:
        """Constraint: the map lives in memory, not behind a per-event query."""
        pseud = TenantPseudonymizer(identity_store, "t")
        pseud.pseudonymize("alice")

        def fail(*args, **kwargs):
            raise AssertionError("hot path must not touch the database")

        monkeypatch.setattr(identity_store, "mint_pseudonym", fail)
        monkeypatch.setattr(identity_store, "load_forward_map_internal", fail)
        for _ in range(1000):
            pseud.pseudonymize("alice")


class TestReverseLookupNeedsAGrant:
    def test_plain_pseudonym_cannot_be_resolved(
        self, identity_store: IdentityStore, pseudonymizer: TenantPseudonymizer
    ) -> None:
        pseudonym = pseudonymizer.pseudonymize("alice")
        with pytest.raises(TypeError):
            identity_store.resolve_subject_with_grant(pseudonym)  # type: ignore[arg-type]

    def test_forged_grant_is_refused(
        self, identity_store: IdentityStore, pseudonymizer: TenantPseudonymizer
    ) -> None:
        """A grant with no audit row behind it discloses nothing."""
        pseudonym = pseudonymizer.pseudonymize("alice")
        with pytest.raises(PermissionError, match="no audit record"):
            identity_store.resolve_subject_with_grant(
                AccessGrant(access_id=9999, pseudonym=pseudonym)
            )

    def test_grant_cannot_be_reused_for_another_subject(
        self, identity_store: IdentityStore, pseudonymizer: TenantPseudonymizer
    ) -> None:
        alice = pseudonymizer.pseudonymize("alice")
        bob = pseudonymizer.pseudonymize("bob")
        grant = identity_store.begin_break_glass_access(
            pseudonym=alice, actor="a", second_approver="b", reason="r"
        )
        hijacked = AccessGrant(access_id=grant.access_id, pseudonym=bob)
        with pytest.raises(PermissionError, match="does not match"):
            identity_store.resolve_subject_with_grant(hijacked)

    def test_a_valid_grant_resolves(
        self, identity_store: IdentityStore, pseudonymizer: TenantPseudonymizer
    ) -> None:
        pseudonym = pseudonymizer.pseudonymize("alice")
        grant = identity_store.begin_break_glass_access(
            pseudonym=pseudonym, actor="a", second_approver="b", reason="incident 42"
        )
        assert identity_store.resolve_subject_with_grant(grant) == "alice"

    def test_unknown_pseudonym_raises(self, identity_store: IdentityStore) -> None:
        grant = identity_store.begin_break_glass_access(
            pseudonym="USR-" + "f" * 32, actor="a", second_approver="b", reason="r"
        )
        with pytest.raises(PseudonymNotFound):
            identity_store.resolve_subject_with_grant(grant)


class TestAuditTrail:
    def test_the_row_exists_before_disclosure(
        self, identity_store: IdentityStore, pseudonymizer: TenantPseudonymizer
    ) -> None:
        pseudonym = pseudonymizer.pseudonymize("alice")
        assert identity_store.access_log() == []
        identity_store.begin_break_glass_access(
            pseudonym=pseudonym, actor="amal", second_approver="sami", reason="incident 42"
        )
        log = identity_store.access_log()
        assert len(log) == 1
        assert log[0]["actor"] == "amal"
        assert log[0]["second_approver"] == "sami"
        assert log[0]["reason"] == "incident 42"

    def test_log_holds_no_real_identities(
        self, identity_store: IdentityStore, pseudonymizer: TenantPseudonymizer
    ) -> None:
        pseudonym = pseudonymizer.pseudonymize("alice")
        identity_store.begin_break_glass_access(
            pseudonym=pseudonym, actor="a", second_approver="b", reason="r"
        )
        assert "alice" not in str(identity_store.access_log())

    def test_no_delete_or_update_statement_exists_against_the_log(self) -> None:
        """Append-only by construction, not by convention."""
        import ebabf.storage.identity_store as module

        source = Path(module.__file__).read_text().lower()
        assert "delete from identity_access_log" not in source
        assert "update identity_access_log" not in source


class TestEncryptionAtRest:
    def test_subject_is_not_readable_in_the_file(
        self, identity_store: IdentityStore, pseudonymizer: TenantPseudonymizer, config
    ) -> None:
        pseudonymizer.pseudonymize("alice@example.com")
        raw = config.identity_db_path.read_bytes()
        assert b"alice@example.com" not in raw
        assert b"alice" not in raw

    def test_ciphertext_is_non_deterministic(self, cipher: IdentityCipher) -> None:
        assert cipher.encrypt("alice") != cipher.encrypt("alice")

    def test_tampered_ciphertext_is_rejected(self, cipher: IdentityCipher) -> None:
        token = bytearray(cipher.encrypt("alice"))
        token[-1] ^= 0xFF
        with pytest.raises(ValueError, match="failed authentication"):
            cipher.decrypt(bytes(token))

    def test_database_file_is_not_world_readable(self, identity_store, config) -> None:
        assert stat.S_IMODE(config.identity_db_path.stat().st_mode) == 0o600


class TestKeyFile:
    def test_created_with_0600(self, tmp_path: Path) -> None:
        key_path = tmp_path / "id" / "identity.key"
        create_key(key_path)
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600

    def test_refuses_to_overwrite(self, tmp_path: Path) -> None:
        key_path = tmp_path / "identity.key"
        create_key(key_path)
        with pytest.raises(FileExistsError):
            create_key(key_path)

    def test_world_readable_key_refused(self, tmp_path: Path) -> None:
        key_path = tmp_path / "id" / "identity.key"
        create_key(key_path)
        key_path.chmod(0o644)
        with pytest.raises(InsecureKeyFile, match="0600"):
            load_key(key_path)

    def test_world_readable_directory_refused(self, tmp_path: Path) -> None:
        key_path = tmp_path / "id" / "identity.key"
        create_key(key_path)
        key_path.parent.chmod(0o755)
        with pytest.raises(InsecureKeyFile, match="0700"):
            load_key(key_path)

    def test_symlinked_key_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "id" / "identity.key"
        create_key(real)
        link = tmp_path / "id" / "link.key"
        link.symlink_to(real)
        with pytest.raises(InsecureKeyFile, match="symlink"):
            load_key(link)

    def test_missing_key_is_an_error_unless_asked_to_create(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_key(tmp_path / "absent.key")

    def test_wrong_key_cannot_read_the_mapping(self, tmp_path: Path) -> None:
        db = tmp_path / "identity.db"
        store = IdentityStore(db, IdentityCipher.from_key_file(tmp_path / "a.key", create_if_missing=True))
        pseudonym = store.mint_pseudonym("t", "alice")
        store.close()

        other = IdentityStore(db, IdentityCipher.from_key_file(tmp_path / "b.key", create_if_missing=True))
        grant = other.begin_break_glass_access(
            pseudonym=pseudonym, actor="a", second_approver="b", reason="r"
        )
        with pytest.raises(ValueError, match="failed authentication"):
            other.resolve_subject_with_grant(grant)
        other.close()


class TestPseudonymizerGuards:
    def test_tenant_id_is_required(self, identity_store: IdentityStore) -> None:
        with pytest.raises(ValueError, match="tenant_id"):
            TenantPseudonymizer(identity_store, "")

    def test_tenant_id_is_exposed(self, identity_store: IdentityStore) -> None:
        assert TenantPseudonymizer(identity_store, "acme").tenant_id == "acme"

    def test_non_string_subject_refused(self, pseudonymizer: TenantPseudonymizer) -> None:
        with pytest.raises(ValueError, match="non-empty string"):
            pseudonymizer.pseudonymize(None)  # type: ignore[arg-type]

    def test_mint_requires_both_arguments(self, identity_store: IdentityStore) -> None:
        with pytest.raises(ValueError, match="required"):
            identity_store.mint_pseudonym("", "alice")
        with pytest.raises(ValueError, match="required"):
            identity_store.mint_pseudonym("t", "")

    def test_cipher_refuses_an_empty_subject(self, cipher: IdentityCipher) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            cipher.encrypt("")

    def test_count_across_all_tenants(self, identity_store: IdentityStore) -> None:
        TenantPseudonymizer(identity_store, "a").pseudonymize("alice")
        TenantPseudonymizer(identity_store, "b").pseudonymize("bob")
        assert identity_store.count() == 2
