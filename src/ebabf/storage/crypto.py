"""Key handling for the identity mapping.

Spec 12 names no crypto library and no key source, so both are settled here:
Fernet (AES-128-CBC with an HMAC tag) from `cryptography`, and a key file the
agent reads at boot. A key file lets the agent start unattended after a
reboot, which a passphrase cannot; environment variables were rejected because
they leak through /proc, `ps` and crash dumps.

The file's permissions are enforced, not assumed. A key readable by every
local user is not a key.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

__all__ = ["IdentityCipher", "InsecureKeyFile", "load_key", "create_key"]

_FORBIDDEN_KEY_BITS = 0o077  # anything beyond owner read/write


class InsecureKeyFile(RuntimeError):
    """The key file, or the directory holding it, is readable by others."""


def _check_permissions(path: Path) -> None:
    directory = path.parent
    dir_info = os.lstat(directory)
    if stat.S_IMODE(dir_info.st_mode) & _FORBIDDEN_KEY_BITS:
        raise InsecureKeyFile(
            f"{directory} has mode {oct(stat.S_IMODE(dir_info.st_mode))}; "
            "the identity key directory must be 0700"
        )
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise InsecureKeyFile(f"{path} is a symlink; refusing to follow it to a key")
    if stat.S_IMODE(info.st_mode) & _FORBIDDEN_KEY_BITS:
        raise InsecureKeyFile(
            f"{path} has mode {oct(stat.S_IMODE(info.st_mode))}; the identity key must be 0600"
        )


def create_key(path: Path) -> bytes:
    """Generate a key at `path` with mode 0600. Refuses to overwrite."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"{path} already exists; refusing to replace an identity key")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = Fernet.generate_key()
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".identity-key-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return key


def load_key(path: Path, *, create_if_missing: bool = False) -> bytes:
    """Read the key at `path`, checking its permissions first."""
    path = Path(path)
    if not path.exists():
        if not create_if_missing:
            raise FileNotFoundError(f"identity key not found at {path}")
        return create_key(path)
    _check_permissions(path)
    return path.read_bytes().strip()


class IdentityCipher:
    """Encrypts and decrypts subject identifiers.

    Fernet output is non-deterministic (each token carries a fresh IV), so
    ciphertext cannot be indexed or searched. That is a property, not an
    oversight: it is why the forward map is built in memory at boot rather
    than by querying on an encrypted column.
    """

    def __init__(self, key: bytes) -> None:
        self._fernet = Fernet(key)

    @classmethod
    def from_key_file(cls, path: Path, *, create_if_missing: bool = False) -> "IdentityCipher":
        return cls(load_key(path, create_if_missing=create_if_missing))

    def encrypt(self, subject: str) -> bytes:
        if not isinstance(subject, str) or not subject:
            raise ValueError("subject must be a non-empty string")
        return self._fernet.encrypt(subject.encode("utf-8"))

    def decrypt(self, token: bytes) -> str:
        try:
            return self._fernet.decrypt(token).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("identity ciphertext failed authentication") from exc
