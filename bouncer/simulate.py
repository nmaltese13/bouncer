"""Replay a candidate policy against the decisions already recorded.

Answers the question an operator actually has before changing a rule: *what
would this policy have done to the traffic I have already seen?* Tightening a
cap is easy; knowing it would have blocked six legitimate purchases last month
is the part that stops you doing it blind.

Threat model: this module is **read-only and writes nothing**. It mints no
mandates, appends no audit rows, and touches no approval queue. A simulation
that recorded anything would let a what-if question consume real budget, and a
simulation that minted anything would hand out spending authority for a policy
nobody had adopted. It reads the log and evaluates in memory.

The subtlety worth stating: rolling-window ceilings depend on cumulative spend,
so the replay maintains its **own** spend history built from *simulated* allows,
not the historical ones. If the candidate policy blocks the third payment, the
fourth is judged against a total that never included it. Replaying each intent
against the recorded history instead would silently mis-answer every rolling
window in the policy — the rule most likely to be under review.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal

from .audit import AuditLog
from .engine import evaluate
from .models import Decision, Outcome, PaymentIntent, SpendRecord
from .policy import Policy

__all__ = ["Replayed", "Simulation", "replay"]

#: Placeholder currency used for rows that never carried a real payment —
#: unparseable traffic and CONNECT tunnels. There is nothing to re-decide.
_PLACEHOLDER_CURRENCY = "XXX"


@dataclass(frozen=True)
class Replayed:
    """One historical payment attempt, re-judged under the candidate policy."""

    intent: PaymentIntent
    at: datetime
    recorded: Outcome
    decision: Decision

    @property
    def outcome(self) -> Outcome:
        return self.decision.outcome

    @property
    def changed(self) -> bool:
        return self.outcome is not self.recorded

    @property
    def newly_blocked(self) -> bool:
        """Was allowed before, would not be allowed now."""
        return self.recorded is Outcome.ALLOW and self.outcome is not Outcome.ALLOW

    @property
    def newly_allowed(self) -> bool:
        """Was not allowed before, would be allowed now."""
        return self.recorded is not Outcome.ALLOW and self.outcome is Outcome.ALLOW


@dataclass(frozen=True)
class Simulation:
    """The result of replaying every recorded attempt."""

    attempts: list[Replayed]
    #: Rows carrying no real payment to re-decide (tunnels, unparseable traffic).
    skipped: int = 0

    @property
    def newly_blocked(self) -> list[Replayed]:
        return [a for a in self.attempts if a.newly_blocked]

    @property
    def newly_allowed(self) -> list[Replayed]:
        return [a for a in self.attempts if a.newly_allowed]

    @property
    def unchanged(self) -> list[Replayed]:
        return [a for a in self.attempts if not a.changed]

    @property
    def blocked_value(self) -> Decimal:
        """Money the candidate policy would have refused but the old one allowed."""
        return sum((a.intent.amount for a in self.newly_blocked), Decimal(0))

    @property
    def released_value(self) -> Decimal:
        return sum((a.intent.amount for a in self.newly_allowed), Decimal(0))

    def describe(self) -> str:
        if not self.attempts:
            return "no recorded payments to replay"
        return (
            f"replayed {len(self.attempts)} payment(s): "
            f"{len(self.newly_blocked)} newly blocked, "
            f"{len(self.newly_allowed)} newly allowed, "
            f"{len(self.unchanged)} unchanged"
        )


def _parse_ts(raw: str) -> datetime:
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def replay(
    log: AuditLog, policy: Policy, *, agent_id: str | None = None
) -> Simulation:
    """Judge every recorded payment attempt against ``policy``.

    Args:
        log: The audit log to read. It is never written to.
        policy: The candidate policy.
        agent_id: Restrict the replay to one agent.

    Returns:
        A :class:`Simulation` naming what would change.
    """
    # An approved payment leaves two rows -- the REQUIRE_APPROVAL that queued it
    # and the ALLOW that granted it -- both carrying the same intent. Replaying
    # both would count the money twice, so collapse on intent_id: the first row
    # gives the attempt and its time, the last gives how it actually ended.
    order: list[str] = []
    intents: dict[str, PaymentIntent] = {}
    moments: dict[str, datetime] = {}
    final: dict[str, Outcome] = {}
    skipped = 0

    with log.sessions() as session:
        for row in log.iter_entries(session):
            if row.currency == _PLACEHOLDER_CURRENCY:
                skipped += 1
                continue
            if agent_id is not None and row.agent_id != agent_id:
                continue
            try:
                payload = json.loads(row.payload)
                intent = PaymentIntent.model_validate(payload["intent"])
            except (ValueError, KeyError):
                # A row whose payload cannot be read is not a payment we can
                # re-judge. Counting it as either outcome would be a guess.
                skipped += 1
                continue

            key = intent.intent_id
            if key not in intents:
                order.append(key)
                intents[key] = intent
                moments[key] = _parse_ts(row.ts)
            final[key] = Outcome(row.outcome)

    # Spend accumulates from *simulated* allows, so a payment the candidate
    # policy blocks does not consume budget for the ones after it.
    history: list[SpendRecord] = []
    attempts: list[Replayed] = []

    for key in order:
        intent = intents[key]
        moment = moments[key]
        decision = evaluate(intent, policy, history, now=moment)
        if decision.outcome is Outcome.ALLOW:
            history.append(
                SpendRecord(
                    agent_id=intent.agent_id,
                    amount=intent.amount,
                    currency=intent.currency,
                    timestamp=moment,
                    merchant=intent.merchant,
                )
            )
        attempts.append(
            Replayed(
                intent=intent, at=moment, recorded=final[key], decision=decision
            )
        )

    return Simulation(attempts=attempts, skipped=skipped)
