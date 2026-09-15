"""systemd unit generation - spec 11.3, decision 11.

A 7-14 day baseline (spec 10.1) cannot survive a reboot without a service
manager, and an interrupted recording is worse than a short one: the hole is
invisible, so the dataset still looks complete when the model is trained on it.

Two findings from checking this systemd rather than recalling it, both of
which decide how the unit below is written:

- `Restart=always` alone does not keep a service alive. systemd's default
  start rate limit is five starts in ten seconds; past that the unit enters
  `failed` and is not restarted again. A crash loop would therefore end the
  recording permanently while appearing to be protected. `StartLimitIntervalSec=0`
  removes the limit, which is what /lib/systemd/system/modprobe@.service does.
- A misspelled directive is *ignored*, not rejected: `systemd-analyze verify`
  reports `Restrt=always` as "Unknown key name ... ignoring", and the unit
  starts anyway with no restart policy at all. Generated units are therefore
  validated before they are installed, never after.

No sandboxing directives are emitted. The agent reads /home for the file
monitor and /var/log for authentication records, and `ProtectHome=` or
`ProtectSystem=` getting in the way of either would blind a collector silently -
the exact failure this module exists to prevent. Hardening belongs here only
once its effect can be verified on the target host.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "UnitSpec",
    "render_unit",
    "validate_unit",
    "EXIT_STORAGE_HALTED",
    "UnitValidationError",
]

# Returned when recording stopped on purpose - the disk floor was reached.
# Restarting would hit the same floor immediately, so the unit declares this
# code as one that must not trigger a restart; the reason is already recorded
# in the database's coverage_gaps table.
EXIT_STORAGE_HALTED = 78


class UnitValidationError(RuntimeError):
    """systemd rejected or silently ignored part of the generated unit."""


@dataclass(frozen=True, slots=True)
class UnitSpec:
    """Everything that varies between one install and another."""

    name: str = "ebabf-agent"
    description: str = "EB-ABF behavioural firewall agent"
    executable: Path = Path("/usr/local/bin/ebabf-agent")
    command: str = "run"
    interval: float = 30.0
    user: str = "root"
    working_directory: Path = Path("/var/lib/ebabf")
    extra_args: tuple[str, ...] = ()

    @property
    def filename(self) -> str:
        return f"{self.name}.service"

    @property
    def exec_start(self) -> str:
        parts = [str(self.executable), self.command, "--interval", str(self.interval)]
        parts.extend(self.extra_args)
        return " ".join(parts)


_TEMPLATE = """\
[Unit]
Description={description}
Documentation=https://github.com/Azozsm16/W
After=network-online.target
Wants=network-online.target
# systemd's default start rate limit is 5 starts in 10 seconds; once hit, the
# unit enters failed state and is NOT restarted again. A 14-day recording must
# not end because of one burst of fast restarts, so the limit is removed.
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart={exec_start}
User={user}
WorkingDirectory={working_directory}

Restart=always
RestartSec=10
# Exit {halt_code} means recording stopped deliberately because free disk space
# reached the floor. Restarting would hit the same floor at once; the reason is
# already written to the coverage_gaps table.
RestartPreventExitStatus={halt_code}

# SIGTERM lets the agent close the databases and stop its collectors cleanly.
KillSignal=SIGTERM
TimeoutStopSec=30

StandardOutput=journal
StandardError=journal
SyslogIdentifier={name}

[Install]
WantedBy=multi-user.target
"""


def render_unit(spec: UnitSpec) -> str:
    """Produce the unit file text for `spec`."""
    return _TEMPLATE.format(
        description=spec.description,
        exec_start=spec.exec_start,
        user=spec.user,
        working_directory=spec.working_directory,
        halt_code=EXIT_STORAGE_HALTED,
        name=spec.name,
    )


def validate_unit(text: str, *, name: str = "ebabf-agent.service") -> list[str]:
    """Run the unit through systemd's own parser.

    Returns the problems found. An empty list means systemd parsed every
    directive; a non-empty one usually means a key it would have ignored at
    runtime, which is the failure mode worth catching before install.

    Returns a single explanatory entry when systemd-analyze is unavailable,
    rather than reporting a clean result it did not earn.
    """
    analyzer = shutil.which("systemd-analyze")
    if analyzer is None:
        return ["systemd-analyze not available; unit was not validated"]

    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / name
        path.write_text(text, encoding="utf-8")
        try:
            result = subprocess.run(
                [analyzer, "verify", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return [f"systemd-analyze could not be run: {exc}"]

    problems: list[str] = []
    for line in (result.stderr + result.stdout).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # "Unknown key name ... ignoring" is the silent one: systemd accepts
        # the unit and drops the directive.
        if "Unknown key name" in stripped or "Failed to parse" in stripped:
            problems.append(stripped)
        elif "not found" in stripped.lower() and ".service" not in stripped:
            problems.append(stripped)
    return problems


def default_executable() -> Path:
    """Where the installed `ebabf-agent` script is, falling back to this venv."""
    found = shutil.which("ebabf-agent")
    if found:
        return Path(found)
    return Path(sys.prefix) / "bin" / "ebabf-agent"
