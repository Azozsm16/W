"""Kill-switch - spec 14.2.

One command stops all enforcement immediately. No restart, no server.
Detection and logging carry on regardless; that asymmetry is the whole point
(spec 11.3: fail-open for enforcement, fail-safe for logging).

Why a sentinel file rather than an in-process flag: a flag set in the agent's
memory is invisible to a command typed in another terminal, and would need a
restart to take effect - which is exactly what spec 14.2 forbids. The file
also survives a reboot, because whoever killed enforcement after the tool
misbehaved does not want it switching itself back on.

Why the file's ownership is checked: a sentinel in a directory any local user
can write to would let any local user disable enforcement with a single
`touch`. A sentinel that fails the check is treated as NOT engaged - so the
bypass gains nothing - and is reported as a tampering attempt, never ignored.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

__all__ = [
    "KillSwitch",
    "KillSwitchState",
    "TamperReport",
    "TamperKind",
    "InsecureSentinelLocation",
]

logger = logging.getLogger(__name__)

# Nobody outside the owner may read, write or traverse. 0700 for the
# directory, 0600 for the sentinel itself.
_FORBIDDEN_DIR_BITS = 0o077
_FORBIDDEN_FILE_BITS = 0o077


class InsecureSentinelLocation(RuntimeError):
    """The sentinel directory is writable by someone other than its owner.

    Raised at construction. The agent must refuse to start rather than run
    with a kill-switch any local user could trip: a bypassable kill-switch is
    worse than an absent one, because it is believed.
    """


class TamperKind:
    """Why a sentinel was rejected. Each of these is a Critical event."""

    WRONG_OWNER = "sentinel_wrong_owner"
    WORLD_WRITABLE = "sentinel_world_writable"
    SYMLINK = "sentinel_is_symlink"
    DIRECTORY_INSECURE = "sentinel_directory_insecure"
    UNREADABLE = "sentinel_unreadable"


@dataclass(frozen=True, slots=True)
class TamperReport:
    """A rejected sentinel. Spec 11.3 classifies agent tampering as Critical."""

    kind: str
    path: Path
    detail: str
    detected_at: datetime
    observed_uid: int | None = None
    observed_mode: int | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "path": str(self.path),
            "detail": self.detail,
            "detected_at": self.detected_at.isoformat(),
            "observed_uid": self.observed_uid,
            "observed_mode": oct(self.observed_mode) if self.observed_mode is not None else None,
        }


@dataclass(frozen=True, slots=True)
class KillSwitchState:
    """What the sentinel says, for operators and the dashboard."""

    engaged: bool
    reason: str | None = None
    actor: str | None = None
    engaged_at: str | None = None


def _log_tamper(report: TamperReport) -> None:
    logger.critical("kill-switch tampering detected: %s", report.as_dict())


class KillSwitch:
    """Disk-backed switch that halts every enforcement action."""

    def __init__(
        self,
        sentinel_path: Path,
        *,
        trusted_owner_uid: int = 0,
        on_tamper: Callable[[TamperReport], None] | None = None,
    ) -> None:
        self._path = Path(sentinel_path)
        self._directory = self._path.parent
        self._trusted_uid = trusted_owner_uid
        self._on_tamper = on_tamper or _log_tamper

        self._ensure_directory()
        problem = self._directory_problem()
        if problem is not None:
            raise InsecureSentinelLocation(
                f"{self._directory}: {problem}. Refusing to start with a kill-switch "
                "any local user could trip."
            )

    # -- state ---------------------------------------------------------------

    def is_engaged(self) -> bool:
        """Whether enforcement is currently halted.

        Re-reads the filesystem on every call. Caching would mean a switch
        thrown from another terminal is not seen until restart, which defeats
        spec 14.2; one stat() is nothing next to the cost of an enforcement
        action.
        """
        return self.read_state().engaged

    def read_state(self) -> KillSwitchState:
        problem = self._directory_problem()
        if problem is not None:
            self._report(TamperKind.DIRECTORY_INSECURE, problem)
            return KillSwitchState(engaged=False)

        try:
            info = os.lstat(self._path)
        except FileNotFoundError:
            return KillSwitchState(engaged=False)
        except OSError as exc:
            self._report(TamperKind.UNREADABLE, f"cannot stat sentinel: {exc}")
            return KillSwitchState(engaged=False)

        # lstat, not stat: a symlink planted here could point at any
        # root-owned file and pass an ownership check made after following it.
        if stat.S_ISLNK(info.st_mode):
            self._report(TamperKind.SYMLINK, "sentinel is a symlink", info)
            return KillSwitchState(engaged=False)

        if info.st_uid != self._trusted_uid:
            self._report(
                TamperKind.WRONG_OWNER,
                f"sentinel owned by uid {info.st_uid}, expected {self._trusted_uid}",
                info,
            )
            return KillSwitchState(engaged=False)

        if stat.S_IMODE(info.st_mode) & _FORBIDDEN_FILE_BITS:
            self._report(
                TamperKind.WORLD_WRITABLE,
                f"sentinel mode {oct(stat.S_IMODE(info.st_mode))} grants access beyond its owner",
                info,
            )
            return KillSwitchState(engaged=False)

        return KillSwitchState(engaged=True, **self._read_metadata())

    # -- operations ----------------------------------------------------------

    def engage(self, *, reason: str, actor: str) -> None:
        """Halt all enforcement, now. Takes effect on the next check."""
        if not reason.strip():
            raise ValueError("a kill-switch needs a written reason")
        if not actor.strip():
            raise ValueError("a kill-switch needs a named actor")

        payload = json.dumps(
            {
                "reason": reason,
                "actor": actor,
                "engaged_at": datetime.now(timezone.utc).isoformat(),
            },
            ensure_ascii=False,
            indent=2,
        )
        self._ensure_directory()
        # Written to a temp file and renamed so a reader never sees a
        # half-written sentinel and concludes enforcement is still live.
        fd, tmp_name = tempfile.mkstemp(dir=self._directory, prefix=".killswitch-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self._path)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise
        logger.critical("kill-switch ENGAGED by %s: %s", actor, reason)

    def release(self, *, actor: str) -> None:
        """Allow enforcement again."""
        if not actor.strip():
            raise ValueError("releasing the kill-switch needs a named actor")
        self._path.unlink(missing_ok=True)
        logger.warning("kill-switch released by %s", actor)

    # -- internals -----------------------------------------------------------

    def _ensure_directory(self) -> None:
        self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _directory_problem(self) -> str | None:
        try:
            info = os.lstat(self._directory)
        except OSError as exc:
            return f"cannot stat directory: {exc}"
        if not stat.S_ISDIR(info.st_mode):
            return "not a directory"
        if info.st_uid != self._trusted_uid:
            return f"owned by uid {info.st_uid}, expected {self._trusted_uid}"
        if stat.S_IMODE(info.st_mode) & _FORBIDDEN_DIR_BITS:
            return f"mode {oct(stat.S_IMODE(info.st_mode))} grants access beyond its owner"
        return None

    def _read_metadata(self) -> dict[str, str | None]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # A sentinel with unreadable contents still counts as engaged.
            # Failing to stop enforcement because the reason field is corrupt
            # would be the worst possible reading of spec 14.2.
            return {"reason": None, "actor": None, "engaged_at": None}
        return {
            "reason": data.get("reason"),
            "actor": data.get("actor"),
            "engaged_at": data.get("engaged_at"),
        }

    def _report(self, kind: str, detail: str, info: os.stat_result | None = None) -> None:
        report = TamperReport(
            kind=kind,
            path=self._path,
            detail=detail,
            detected_at=datetime.now(timezone.utc),
            observed_uid=info.st_uid if info else None,
            observed_mode=stat.S_IMODE(info.st_mode) if info else None,
        )
        try:
            self._on_tamper(report)
        except Exception:  # noqa: BLE001 - a broken handler must not suppress the check
            logger.exception("tamper handler failed for %s", kind)


def main(argv: list[str] | None = None) -> int:
    """`ebabf-killswitch engage|release|status`."""
    import argparse

    from ebabf.config import AgentConfig

    parser = argparse.ArgumentParser(prog="ebabf-killswitch", description=__doc__)
    parser.add_argument("--path", type=Path, default=None, help="sentinel path override")
    sub = parser.add_subparsers(dest="command", required=True)

    engage = sub.add_parser("engage", help="halt all enforcement immediately")
    engage.add_argument("--reason", required=True)
    engage.add_argument("--actor", default=os.environ.get("USER", "unknown"))

    release = sub.add_parser("release", help="allow enforcement again")
    release.add_argument("--actor", default=os.environ.get("USER", "unknown"))

    sub.add_parser("status", help="report whether enforcement is halted")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    path = args.path or AgentConfig().kill_switch_path
    switch = KillSwitch(path)

    if args.command == "engage":
        switch.engage(reason=args.reason, actor=args.actor)
        print(f"enforcement HALTED via {path}")
    elif args.command == "release":
        switch.release(actor=args.actor)
        print(f"enforcement allowed again; {path} removed")
    else:
        state = switch.read_state()
        print(f"engaged: {state.engaged}")
        if state.engaged:
            print(f"reason:  {state.reason}\nactor:   {state.actor}\nsince:   {state.engaged_at}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
