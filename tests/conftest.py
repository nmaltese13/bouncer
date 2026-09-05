"""Shared fixtures and builders."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest

from bouncer.keys import OperatorKey
from bouncer.models import PaymentIntent, SpendRecord
from bouncer.policy import Policy

#: A fixed evaluation instant: Wednesday 2026-03-11, 14:30 UTC.
NOW = datetime(2026, 3, 11, 14, 30, tzinfo=timezone.utc)


def intent(**overrides: Any) -> PaymentIntent:
    """Build a payment intent, defaulting to one that passes a simple policy."""
    fields: dict[str, Any] = {
        "intent_id": "intent-1",
        "agent_id": "research-bot",
        "merchant": "api.example.com",
        "amount": Decimal("10.00"),
        "currency": "USD",
        "category": "api_credits",
    }
    fields.update(overrides)
    return PaymentIntent(**fields)


def spend(amount: str, *, days_ago: float = 1.0, agent_id: str = "research-bot",
          currency: str = "USD", merchant: str = "api.example.com") -> SpendRecord:
    return SpendRecord(
        agent_id=agent_id,
        amount=Decimal(amount),
        currency=currency,
        merchant=merchant,
        timestamp=NOW - timedelta(days=days_ago),
    )


def policy_from(body: str) -> Policy:
    return Policy.from_yaml(body)


SIMPLE_POLICY = """
version: 1
currency: USD
agents:
  research-bot:
    per_transaction_cap: 100.00
"""


@pytest.fixture()
def operator_key(tmp_path: Any) -> OperatorKey:
    return OperatorKey.generate(tmp_path / "operator.pem")


@pytest.fixture(autouse=True)
def isolate_from_real_bouncer_home(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never let a test read or write the developer's real ~/.bouncer state."""
    for variable in (
        "BOUNCER_HOME",
        "BOUNCER_POLICY",
        "BOUNCER_DB",
        "BOUNCER_KEY",
        "BOUNCER_WEBHOOK_URL",
        "BOUNCER_APPROVAL_TIMEOUT",
    ):
        monkeypatch.delenv(variable, raising=False)
