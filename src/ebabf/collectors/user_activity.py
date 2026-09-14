"""User activity collector - the UEBA features in spec 5.4.

Counts only. A sudo line in the auth log carries the command that was run, and
a command line routinely carries secrets (`sudo mysql -pHUNTER2`). The parser
therefore extracts the fact that sudo was used and discards the rest of the
line - principle 5 applies to log text exactly as it applies to file content.

Auth records sit in a different place on every distribution (journald,
/var/log/auth.log on Debian, /var/log/secure on RHEL), so the source is behind
an interface. When none is readable the collector says so and reports the
affected fields as None; it does not report zero failed logins for a log it
could not open.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar, Iterator, Sequence

import psutil

from ebabf.collectors.base import Collector, CollectorContext
from ebabf.collectors.registry import register_collector
from ebabf.schema import Event, EventSource

__all__ = [
    "UserActivityCollector",
    "AuthEvent",
    "AuthEventSource",
    "JournaldAuthSource",
    "AuthLogFileSource",
    "NullAuthSource",
    "select_auth_source",
]

logger = logging.getLogger(__name__)

AUTH_LOG_CANDIDATES = ("/var/log/auth.log", "/var/log/secure")

# Deliberately narrow: each pattern captures a username and nothing else.
_FAILED_PATTERNS = (
    re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+)"),
    re.compile(r"authentication failure;.*?user=(?P<user>\S+)"),
    re.compile(r"Invalid user (?P<user>\S+)"),
)
_SUDO_PATTERN = re.compile(r"sudo:\s+(?P<user>\S+)\s*:")


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """One authentication-relevant record. Carries no command text."""

    kind: str  # "failed_auth" | "sudo"
    username: str
    timestamp: float


class AuthEventSource(ABC):
    """Where authentication records come from on this host."""

    name: ClassVar[str] = "auth"

    @classmethod
    @abstractmethod
    def is_available(cls) -> bool: ...

    @abstractmethod
    def read_since(self, since: float) -> list[AuthEvent]: ...


class NullAuthSource(AuthEventSource):
    """No readable source. Fields depending on it are reported as unknown."""

    name = "none"

    @classmethod
    def is_available(cls) -> bool:
        return True

    def read_since(self, since: float) -> list[AuthEvent]:
        return []


class JournaldAuthSource(AuthEventSource):
    """Reads journald, which is where most current distributions put this."""

    name = "journald"

    @classmethod
    def is_available(cls) -> bool:
        if shutil.which("journalctl") is None:
            return False
        try:
            result = subprocess.run(
                ["journalctl", "--no-pager", "-n", "1", "-o", "json"],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0

    def read_since(self, since: float) -> list[AuthEvent]:
        stamp = datetime.fromtimestamp(since, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            result = subprocess.run(
                [
                    "journalctl", "--no-pager", "-o", "json",
                    "--since", stamp, "--utc",
                    "SYSLOG_FACILITY=10",  # authpriv
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("journalctl read failed: %s", exc)
            return []
        if result.returncode != 0:
            return []

        events: list[AuthEvent] = []
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            message = record.get("MESSAGE") or ""
            micros = record.get("__REALTIME_TIMESTAMP")
            moment = int(micros) / 1_000_000 if micros else since
            events.extend(parse_auth_line(message, moment))
        return events


class AuthLogFileSource(AuthEventSource):
    """Reads /var/log/auth.log or /var/log/secure."""

    name = "auth_log_file"

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or self._find()

    @staticmethod
    def _find() -> Path | None:
        """First candidate that exists and this process can actually open."""
        for candidate in AUTH_LOG_CANDIDATES:
            path = Path(candidate)
            try:
                with path.open("rb"):
                    return path
            except OSError:
                continue
        return None

    @classmethod
    def is_available(cls) -> bool:
        return cls._find() is not None

    def read_since(self, since: float) -> list[AuthEvent]:
        if self._path is None:
            return []
        try:
            text = self._path.read_text(errors="replace")
        except OSError as exc:
            logger.warning("auth log read failed: %s", exc)
            return []
        events: list[AuthEvent] = []
        for line in text.splitlines():
            events.extend(parse_auth_line(line, since))
        return events


def parse_auth_line(line: str, moment: float) -> list[AuthEvent]:
    """Extract auth facts from one log line, discarding everything else.

    Returns at most a kind and a username. The command text in a sudo line is
    never captured - see the module docstring.
    """
    events: list[AuthEvent] = []
    for pattern in _FAILED_PATTERNS:
        match = pattern.search(line)
        if match:
            events.append(AuthEvent("failed_auth", match.group("user"), moment))
            break
    sudo = _SUDO_PATTERN.search(line)
    if sudo:
        events.append(AuthEvent("sudo", sudo.group("user"), moment))
    return events


def select_auth_source() -> AuthEventSource:
    """Pick the best readable source, falling back to none."""
    for source_type in (JournaldAuthSource, AuthLogFileSource):
        try:
            if source_type.is_available():
                return source_type()
        except Exception:  # noqa: BLE001 - a broken probe is just unavailability
            logger.debug("auth source %s probe failed", source_type.name, exc_info=True)
    logger.warning(
        "no readable authentication log; failed_auth_count and sudo_usage_pattern "
        "will be reported as unknown"
    )
    return NullAuthSource()


@register_collector
class UserActivityCollector(Collector):
    """One event per logged-in session per sweep."""

    source: ClassVar[EventSource] = EventSource.USER
    name: ClassVar[str] = "user_activity"

    def __init__(
        self,
        context: CollectorContext,
        *,
        auth_source: AuthEventSource | None = None,
    ) -> None:
        super().__init__(context)
        self._auth = auth_source if auth_source is not None else select_auth_source()
        self._last_read: float | None = None

    @classmethod
    def is_supported(cls) -> bool:
        import sys

        return sys.platform.startswith("linux")

    @property
    def auth_source_name(self) -> str:
        return self._auth.name

    def collect(self) -> Iterator[Event]:
        now = self._context.clock()
        since = self._last_read if self._last_read is not None else now.timestamp() - 3600
        self._last_read = now.timestamp()

        auth_available = not isinstance(self._auth, NullAuthSource)
        failed = Counter()
        sudo = Counter()
        if auth_available:
            for record in self._auth.read_since(since):
                if record.kind == "failed_auth":
                    failed[record.username] += 1
                elif record.kind == "sudo":
                    sudo[record.username] += 1

        try:
            sessions = psutil.users()
        except Exception:  # noqa: BLE001 - degraded, not fatal
            logger.exception("session table unreadable")
            sessions = []

        seen: set[str] = set()
        for session in sessions:
            username = session.name
            if not username:
                continue
            seen.add(username)
            yield self._build_event(
                subject=username,
                raw_attributes={
                    # spec 5.4
                    "activity_hour": now.hour,
                    "failed_auth_count": failed.get(username, 0) if auth_available else None,
                    "sudo_usage_pattern": sudo.get(username, 0) if auth_available else None,
                    "session_duration": (
                        round(time.time() - session.started, 3) if session.started else None
                    ),
                    # context
                    "session_terminal": session.terminal,
                    "session_is_remote": bool(session.host and session.host not in {"", ":0"}),
                    "auth_source": self._auth.name,
                    "auth_log_readable": auth_available,
                },
            )

        # Failed logins for users with no session are the brute-force case, and
        # would be invisible if only live sessions were reported.
        if auth_available:
            for username, count in failed.items():
                if username in seen:
                    continue
                yield self._build_event(
                    subject=username,
                    raw_attributes={
                        "activity_hour": now.hour,
                        "failed_auth_count": count,
                        "sudo_usage_pattern": sudo.get(username, 0),
                        "session_duration": None,
                        "session_terminal": None,
                        "session_is_remote": None,
                        "auth_source": self._auth.name,
                        "auth_log_readable": True,
                    },
                )
