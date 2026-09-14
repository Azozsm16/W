"""Enforcement engine - spec 4, 11.3, 14.2.

Separate from the decision engine and switchable off in its entirety through
one setting (`AgentConfig.enforcement_enabled`). Training Mode is that setting
set to False; there is no second mechanism.

Two rules govern every implementation:

- The kill-switch is checked immediately before each action, never cached.
- An internal fault fails open: no enforcement, event still recorded. A
  security tool that bricks the host it defends is the problem, not the fix.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from ebabf.engine.decision import DecisionOutcome
from ebabf.engine.killswitch import KillSwitch
from ebabf.schema import EnforcementBlockedReason, Event

__all__ = ["EnforcementEngine", "EnforcementResult", "NoOpEnforcementEngine"]

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class EnforcementResult:
    """What enforcement did, or why it did nothing."""

    enforced: bool
    blocked_reason: EnforcementBlockedReason | None
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.enforced and self.blocked_reason is not None:
            raise ValueError("an action cannot be both enforced and blocked")
        if not self.enforced and self.blocked_reason is None:
            raise ValueError("not enforcing requires a reason; silence hides outages")

    def apply_to(self, event: Event) -> Event:
        """Write the outcome onto the event, keeping `enforced` truthful."""
        return event.enriched(
            enforced=self.enforced,
            enforcement_blocked_reason=self.blocked_reason,
        )


class EnforcementEngine(ABC):
    """Acts on decisions. Can be switched off completely."""

    name: ClassVar[str] = "enforcement_engine"

    def __init__(self, *, enabled: bool, kill_switch: KillSwitch) -> None:
        self._enabled = enabled
        self._kill_switch = kill_switch

    def is_enabled(self) -> bool:
        """False when disabled by config, or while the kill-switch is engaged."""
        if not self._enabled:
            return False
        return not self._kill_switch.is_engaged()

    def enforce(self, outcome: DecisionOutcome) -> EnforcementResult:
        """Act on `outcome`. Never raises.

        The order of the checks matters: the kill-switch is read here, on
        this call, so that a switch thrown a millisecond ago is honoured.
        """
        if not outcome.action_required:
            return EnforcementResult(
                enforced=False,
                blocked_reason=EnforcementBlockedReason.NO_ACTION_REQUIRED,
                detail="decision asks for no enforcement action",
            )

        if not self._enabled:
            return EnforcementResult(
                enforced=False,
                blocked_reason=EnforcementBlockedReason.ENFORCEMENT_DISABLED,
                detail="enforcement disabled by configuration",
            )

        if self._kill_switch.is_engaged():
            return EnforcementResult(
                enforced=False,
                blocked_reason=EnforcementBlockedReason.KILL_SWITCH_ACTIVE,
                detail="kill-switch engaged",
            )

        try:
            return self._enforce(outcome)
        except Exception as exc:  # noqa: BLE001 - fail-open, spec 11.3
            logger.exception(
                "enforcement engine %s failed on event %s; failing open",
                self.name,
                outcome.event.event_id,
            )
            return EnforcementResult(
                enforced=False,
                blocked_reason=EnforcementBlockedReason.FAIL_OPEN,
                detail=f"internal fault: {type(exc).__name__}: {exc}",
            )

    @abstractmethod
    def _enforce(self, outcome: DecisionOutcome) -> EnforcementResult:
        """Subclass hook, reached only when enforcement is permitted."""


class NoOpEnforcementEngine(EnforcementEngine):
    """Sprint 1 placeholder: performs no action, reports honestly that it did not.

    Reporting NOT_SUPPORTED rather than pretending to enforce keeps Training
    Mode's "what would have happened" count truthful once it arrives.
    """

    name: ClassVar[str] = "noop"

    def _enforce(self, outcome: DecisionOutcome) -> EnforcementResult:
        decision = outcome.event.decision
        return EnforcementResult(
            enforced=False,
            blocked_reason=EnforcementBlockedReason.NOT_SUPPORTED,
            detail=f"no enforcer implements {decision.value if decision else 'unknown'} yet",
        )
