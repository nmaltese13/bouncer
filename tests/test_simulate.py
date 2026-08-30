"""Replaying a candidate policy against the decisions already recorded."""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from bouncer.approvals import ApprovalQueue
from bouncer.audit import AuditLog
from bouncer.enforcement import Enforcer
from bouncer.errors import UnparseableIntent
from bouncer.keys import OperatorKey
from bouncer.mandate import NonceStore
from bouncer.models import Outcome, PaymentIntent
from bouncer.policy import Policy
from bouncer.simulate import replay
from bouncer.sources import StaticSource

from .conftest import NOW

LOOSE = """
version: 1
currency: USD
agents:
  research-bot:
    per_transaction_cap: 1000.00
    rolling_windows:
      - amount: 1000.00
        window: 30d
"""


class MovableClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def build(
    tmp_path: Path, key: OperatorKey, policy: str
) -> tuple[Enforcer, MovableClock]:
    clock = MovableClock(NOW)
    audit = AuditLog(tmp_path / "s.db", key)
    enforcer = Enforcer(
        source=StaticSource(Policy.from_yaml(policy)),
        audit=audit,
        key=key,
        nonces=NonceStore(tmp_path / "s.db", engine=audit.engine),
        approvals=ApprovalQueue(tmp_path / "s.db", engine=audit.engine),
        clock=clock,
    )
    return enforcer, clock


def spend(
    enforcer: Enforcer, clock: MovableClock, amount: str, agent: str = "research-bot"
) -> None:
    enforcer.authorize(
        PaymentIntent(
            agent_id=agent,
            merchant="api.vendor.example",
            amount=Decimal(amount),
            currency="USD",
        )
    )
    clock.now += timedelta(minutes=1)


def test_the_replay_uses_simulated_spend_not_recorded_spend(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    """The property the whole module turns on.

    Recorded: 500, 100, 100, all allowed under a loose policy. The candidate
    caps each payment at 200, so the 500 is blocked -- and the two 100s must
    then be judged against a running total that never included it.

    Replaying against the *recorded* history instead would see 500 already
    spent, block both 100s as well, and report three casualties where the true
    answer is one. That is the difference between a useful simulation and a
    misleading one.
    """
    enforcer, clock = build(tmp_path, operator_key, LOOSE)
    for amount in ("500.00", "100.00", "100.00"):
        spend(enforcer, clock, amount)

    candidate = Policy.from_yaml(
        "version: 1\ncurrency: USD\nagents:\n  research-bot:\n"
        "    per_transaction_cap: 200.00\n    rolling_windows:\n"
        "      - amount: 300.00\n        window: 30d\n"
    )
    result = replay(enforcer.audit, candidate)

    assert len(result.attempts) == 3
    assert len(result.newly_blocked) == 1, (
        "only the 500 exceeds the cap; the 100s fit inside the 300 ceiling "
        "precisely because the 500 was simulated as blocked"
    )
    assert result.newly_blocked[0].intent.amount == Decimal("500.00")
    assert result.blocked_value == Decimal("500.00")


def test_a_tightened_cap_reports_what_it_would_have_cost(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    enforcer, clock = build(tmp_path, operator_key, LOOSE)
    for amount in ("40.00", "60.00", "30.00", "90.00"):
        spend(enforcer, clock, amount)

    candidate = Policy.from_yaml(
        LOOSE.replace("per_transaction_cap: 1000.00", "per_transaction_cap: 50.00")
    )
    result = replay(enforcer.audit, candidate)

    assert [a.intent.amount for a in result.newly_blocked] == [
        Decimal("60.00"),
        Decimal("90.00"),
    ]
    assert result.blocked_value == Decimal("150.00")
    assert len(result.unchanged) == 2


def test_a_loosened_policy_reports_what_it_would_release(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    strict = LOOSE.replace("per_transaction_cap: 1000.00", "per_transaction_cap: 50.00")
    enforcer, clock = build(tmp_path, operator_key, strict)
    spend(enforcer, clock, "40.00")
    spend(enforcer, clock, "80.00")  # denied under the strict cap

    result = replay(enforcer.audit, Policy.from_yaml(LOOSE))
    assert len(result.newly_allowed) == 1
    assert result.released_value == Decimal("80.00")


def test_an_identical_policy_changes_nothing(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    enforcer, clock = build(tmp_path, operator_key, LOOSE)
    for amount in ("40.00", "60.00"):
        spend(enforcer, clock, amount)

    result = replay(enforcer.audit, Policy.from_yaml(LOOSE))
    assert result.newly_blocked == []
    assert result.newly_allowed == []
    assert len(result.unchanged) == 2


def test_an_approved_payment_is_replayed_once_not_twice(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    """Approval writes a second row for the same intent; money must not double."""
    enforcer, _ = build(
        tmp_path,
        operator_key,
        "version: 1\ncurrency: USD\nagents:\n  research-bot:\n"
        "    per_transaction_cap: 100.00\n    approval_required_above:\n"
        "      amount: 20.00\n      approver_role: finance\n",
    )
    queued = enforcer.authorize(
        PaymentIntent(
            agent_id="research-bot",
            merchant="api.vendor.example",
            amount=Decimal("50.00"),
            currency="USD",
        )
    )
    assert queued.pending_id is not None
    enforcer.resolve(queued.pending_id, role="finance", approve=True)
    assert enforcer.audit.count() == 2, "the approval flow writes two rows"

    result = replay(enforcer.audit, Policy.from_yaml(LOOSE))
    assert len(result.attempts) == 1, "two rows, one payment"
    assert result.attempts[0].recorded is Outcome.ALLOW, "the final outcome wins"


def test_rows_carrying_no_payment_are_skipped(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    """Tunnels and unparseable traffic have nothing to re-decide."""
    enforcer, clock = build(tmp_path, operator_key, LOOSE)
    spend(enforcer, clock, "40.00")
    enforcer.authorize_tunnel("api.vendor.example", "research-bot")
    enforcer.deny_unparseable(
        UnparseableIntent("nope"),
        PaymentIntent(
            agent_id="research-bot",
            merchant="unknown",
            amount=Decimal(0),
            currency="XXX",
        ),
    )

    result = replay(enforcer.audit, Policy.from_yaml(LOOSE))
    assert len(result.attempts) == 1
    assert result.skipped == 2


def test_replay_can_be_scoped_to_one_agent(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    enforcer, clock = build(
        tmp_path,
        operator_key,
        "version: 1\ncurrency: USD\nagents:\n"
        "  research-bot:\n    per_transaction_cap: 1000.00\n"
        "  other-bot:\n    per_transaction_cap: 1000.00\n",
    )
    spend(enforcer, clock, "40.00")
    spend(enforcer, clock, "70.00", agent="other-bot")

    scoped = replay(enforcer.audit, Policy.from_yaml(LOOSE), agent_id="research-bot")
    assert len(scoped.attempts) == 1
    assert scoped.attempts[0].intent.agent_id == "research-bot"


def test_simulation_writes_absolutely_nothing(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    """A what-if must not consume budget or mint authority."""
    enforcer, clock = build(tmp_path, operator_key, LOOSE)
    for amount in ("40.00", "60.00"):
        spend(enforcer, clock, amount)

    before_rows = enforcer.audit.count()
    before_head = enforcer.audit.head()
    before_nonces = enforcer.nonces.count()
    before_pending = len(enforcer.approvals.list())

    replay(
        enforcer.audit,
        Policy.from_yaml(
            LOOSE.replace("per_transaction_cap: 1000.00", "per_transaction_cap: 1.00")
        ),
    )

    assert enforcer.audit.count() == before_rows
    assert enforcer.audit.head() == before_head
    assert enforcer.nonces.count() == before_nonces
    assert len(enforcer.approvals.list()) == before_pending
    assert enforcer.audit.verify().ok


def test_replaying_an_empty_log_is_not_an_error(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    enforcer, _ = build(tmp_path, operator_key, LOOSE)
    result = replay(enforcer.audit, Policy.from_yaml(LOOSE))
    assert result.attempts == []
    assert "no recorded payments" in result.describe()
