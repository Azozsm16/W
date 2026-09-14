"""The single auditable join between events.db and identity.db.

Nothing else in the package holds both stores. This function applies the
Break-Glass policy of spec 18.4 and then calls the two restricted methods on
`IdentityStore`, in that order.

Of the five conditions in spec 18.4, three are enforced here today - written
reason, two-person approval, and an audit record written before disclosure.
The severity gate is written so that it arms itself: while no event carries a
`level`, it passes; the moment the scoring engine lands in Sprint 4 and events
start carrying one, it starts refusing anything below Critical, with no
configuration change and nobody having to remember. The remaining two -
tamper-evident hash chaining and notifying the subject afterwards - are
declared in docs/sprint-1-debts.md.
"""

from __future__ import annotations

import logging

from ebabf.schema import RiskLevel
from ebabf.storage.event_store import EventStore
from ebabf.storage.identity_store import IdentityStore

__all__ = ["resolve_subject_for_event", "BreakGlassDenied"]

logger = logging.getLogger(__name__)


class BreakGlassDenied(PermissionError):
    """The disclosure request failed a Break-Glass precondition."""


def resolve_subject_for_event(
    *,
    event_store: EventStore,
    identity_store: IdentityStore,
    event_id: str,
    actor: str,
    second_approver: str,
    reason: str,
) -> str:
    """Reveal the real identity behind one event's subject.

    Raises `BreakGlassDenied` unless every precondition holds. On success the
    disclosure is already recorded in `identity_access_log` before the
    plaintext exists in memory.
    """
    if not reason or not reason.strip():
        raise BreakGlassDenied("a written reason is required")
    if not actor or not actor.strip():
        raise BreakGlassDenied("a named requester is required")
    if not second_approver or not second_approver.strip():
        raise BreakGlassDenied("a second approver is required")
    if actor.strip() == second_approver.strip():
        raise BreakGlassDenied("two-person rule: the approver cannot be the requester")

    event = event_store.get(event_id)
    if event is None:
        raise BreakGlassDenied(f"no such event: {event_id}")

    # Self-arming severity gate. Passes while `level` is None (nothing has
    # scored anything yet); refuses below Critical the moment scoring exists.
    if event.level is not None and event.level is not RiskLevel.CRITICAL:
        raise BreakGlassDenied("level below critical threshold")

    grant = identity_store.begin_break_glass_access(
        pseudonym=event.subject_pseudonym,
        actor=actor,
        second_approver=second_approver,
        reason=reason,
        event_id=event_id,
    )
    subject = identity_store.resolve_subject_with_grant(grant)
    logger.warning(
        "break-glass disclosure: event=%s pseudonym=%s actor=%s approver=%s access_id=%s",
        event_id,
        event.subject_pseudonym,
        actor,
        second_approver,
        grant.access_id,
    )
    return subject
