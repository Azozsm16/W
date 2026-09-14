"""Decision engine - spec 4.

Always runs. Never enforces. It computes a decision and hands it on; whether
anything acts on that decision is somebody else's concern, and that split is
what makes Training Mode (spec 17.1) possible at all.

`decide` is concrete and final: it wraps the subclass's `_decide` so that no
implementation can break the "always runs" guarantee by raising. Making the
guarantee structural rather than documented is the only way it survives the
next five layers being added.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from ebabf.schema import Decision, Event

__all__ = ["DecisionEngine", "DecisionOutcome", "PassThroughDecisionEngine"]

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DecisionOutcome:
    """A decision plus the event it was written onto."""

    event: Event

    @property
    def action_required(self) -> bool:
        """Whether the enforcement engine has anything to do.

        Derived, not stored, for the same reason as `Event.verdict_type`: a
        stored copy of something computable eventually disagrees with it.
        """
        decision = self.event.decision
        return decision is not None and decision.requires_enforcement


class DecisionEngine(ABC):
    """Computes what should happen. Never makes it happen."""

    name: ClassVar[str] = "decision_engine"

    def decide(self, event: Event) -> DecisionOutcome:
        """Evaluate `event`. Never raises.

        On an internal fault the event is still decided - as LOG, with
        `confidence` cleared and this engine named in `degraded_layers`.
        Silence would be the real failure: spec 11.3 keeps detection and
        logging alive precisely when the evaluator is broken, and spec 6.3
        forbids treating an absent layer as a clean result.
        """
        try:
            return self._decide(event)
        except Exception:  # noqa: BLE001 - fail-safe for logging, by design
            logger.exception("decision engine %s failed; degrading event %s", self.name, event.event_id)
            return DecisionOutcome(event=self._degrade(event))

    @abstractmethod
    def _decide(self, event: Event) -> DecisionOutcome:
        """Subclass hook. May raise; `decide` contains the damage."""

    def _degrade(self, event: Event) -> Event:
        degraded = event.degraded_layers
        if self.name not in degraded:
            degraded = degraded + (self.name,)
        return event.enriched(
            decision=Decision.LOG,
            confidence=None,
            degraded_layers=degraded,
            enforced=False,
        )


class PassThroughDecisionEngine(DecisionEngine):
    """Sprint 1 placeholder: records the event and decides nothing.

    `decision=LOG` here is not a scoring result, it is the absence of one.
    No layer has run, so no score is written - leaving `raw_score` at None
    rather than 0.0 keeps "nobody looked" distinguishable from "looked, and
    it was clean". The scoring engine replaces this in Sprint 4.
    """

    name: ClassVar[str] = "pass_through"

    def _decide(self, event: Event) -> DecisionOutcome:
        return DecisionOutcome(event=event.enriched(decision=Decision.LOG))
