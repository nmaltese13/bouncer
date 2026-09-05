"""Ceilings scoped to one vendor rather than to the agent as a whole.

An agent may hold a large budget that is only spendable in small amounts at any
particular merchant. The property that matters throughout: a merchant limit can
only ever *tighten*.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import pytest

from bouncer import evaluate
from bouncer.errors import PolicyError
from bouncer.models import Outcome, PaymentIntent, ReasonCode, SpendRecord
from bouncer.policy import Policy

from .conftest import NOW

POLICY = """
version: 1
currency: USD
agents:
  bot:
    per_transaction_cap: 500.00
    rolling_windows:
      - amount: 2000.00
        window: 30d
    merchants:
      limits:
        "api.openai.com":
          per_transaction_cap: 50.00
        "*.vendor.example":
          rolling_windows:
            - amount: 100.00
              window: 30d
"""


def decide(
    merchant: str, amount: str, history: list[SpendRecord] | None = None,
    policy: str = POLICY,
) -> tuple[Outcome, ReasonCode]:
    result = evaluate(
        PaymentIntent(
            agent_id="bot", merchant=merchant, amount=Decimal(amount), currency="USD"
        ),
        Policy.from_yaml(policy),
        history or [],
        now=NOW,
    )
    return result.outcome, result.reason_code


def spent_at(merchant: str, amount: str, days_ago: float = 1.0) -> SpendRecord:
    return SpendRecord(
        agent_id="bot",
        amount=Decimal(amount),
        currency="USD",
        merchant=merchant,
        timestamp=NOW - timedelta(days=days_ago),
    )


# ---------------------------------------------------------------------------
# a merchant limit tightens
# ---------------------------------------------------------------------------


def test_a_merchant_cap_binds_below_the_agent_cap() -> None:
    assert decide("api.openai.com", "40.00") == (Outcome.ALLOW, ReasonCode.WITHIN_POLICY)
    assert decide("api.openai.com", "400.00") == (
        Outcome.DENY,
        ReasonCode.OVER_MERCHANT_CAP,
    )


def test_a_merchant_window_accumulates_across_the_pattern() -> None:
    """A limit on *.vendor.example is one budget, not one per subdomain."""
    history = [spent_at("a.vendor.example", "80.00")]
    assert decide("b.vendor.example", "15.00", history) == (
        Outcome.ALLOW,
        ReasonCode.WITHIN_POLICY,
    )
    assert decide("b.vendor.example", "30.00", history) == (
        Outcome.DENY,
        ReasonCode.OVER_MERCHANT_WINDOW,
    )


def test_one_merchants_budget_does_not_consume_anothers() -> None:
    history = [spent_at("a.vendor.example", "95.00")]
    assert decide("api.openai.com", "30.00", history) == (
        Outcome.ALLOW,
        ReasonCode.WITHIN_POLICY,
    )


def test_a_merchant_with_no_limit_is_governed_only_by_the_agent() -> None:
    assert decide("api.elsewhere.example", "400.00") == (
        Outcome.ALLOW,
        ReasonCode.WITHIN_POLICY,
    )


# ---------------------------------------------------------------------------
# a merchant limit must never loosen
# ---------------------------------------------------------------------------


def test_a_merchant_cap_above_the_agent_cap_changes_nothing() -> None:
    """Letting a nested rule widen an outer one would make the effective policy
    depend on reading two places at once."""
    loose = """
version: 1
currency: USD
agents:
  bot:
    per_transaction_cap: 50.00
    merchants:
      limits:
        "api.openai.com":
          per_transaction_cap: 9999.00
"""
    assert decide("api.openai.com", "400.00", policy=loose) == (
        Outcome.DENY,
        ReasonCode.OVER_PER_TXN_CAP,
    )


def test_a_merchant_window_above_the_agent_window_changes_nothing() -> None:
    loose = """
version: 1
currency: USD
agents:
  bot:
    per_transaction_cap: 500.00
    rolling_windows:
      - amount: 100.00
        window: 30d
    merchants:
      limits:
        "api.openai.com":
          rolling_windows:
            - amount: 9999.00
              window: 30d
"""
    history = [spent_at("api.openai.com", "95.00")]
    assert decide("api.openai.com", "50.00", history, policy=loose) == (
        Outcome.DENY,
        ReasonCode.OVER_ROLLING_WINDOW,
    )


def test_a_merchant_limit_cannot_rescue_a_denylisted_merchant() -> None:
    """Prohibitions are evaluated before ceilings and stay that way."""
    policy = """
version: 1
currency: USD
agents:
  bot:
    per_transaction_cap: 500.00
    merchants:
      deny: ["*.casino.example"]
      limits:
        "*.casino.example":
          per_transaction_cap: 400.00
"""
    assert decide("lucky.casino.example", "10.00", policy=policy) == (
        Outcome.DENY,
        ReasonCode.MERCHANT_DENIED,
    )


# ---------------------------------------------------------------------------
# the lookback horizon must reach past merchant windows
# ---------------------------------------------------------------------------


def test_longest_window_includes_merchant_windows() -> None:
    """The fail-open this guards against, one level down.

    Spend history is fetched using the rule set's longest window. A merchant
    window of 90d under an agent whose own longest is 30d would otherwise be
    judged against 30 days of history, letting the agent spend several times its
    ceiling at that vendor.
    """
    policy = Policy.from_yaml(
        """
version: 1
currency: USD
agents:
  bot:
    per_transaction_cap: 500.00
    rolling_windows:
      - amount: 2000.00
        window: 30d
    merchants:
      limits:
        "api.openai.com":
          rolling_windows:
            - amount: 100.00
              window: 90d
"""
    )
    assert policy.agents["bot"].longest_window == timedelta(days=90)


def test_a_merchant_window_is_enforced_across_its_full_span() -> None:
    """Spend from 60 days ago must still count against a 90-day merchant window."""
    policy = """
version: 1
currency: USD
agents:
  bot:
    per_transaction_cap: 500.00
    rolling_windows:
      - amount: 2000.00
        window: 30d
    merchants:
      limits:
        "api.openai.com":
          rolling_windows:
            - amount: 100.00
              window: 90d
"""
    history = [spent_at("api.openai.com", "95.00", days_ago=60)]
    assert decide("api.openai.com", "20.00", history, policy=policy) == (
        Outcome.DENY,
        ReasonCode.OVER_MERCHANT_WINDOW,
    )


# ---------------------------------------------------------------------------
# the schema refuses limits that would be misread
# ---------------------------------------------------------------------------


def test_an_empty_merchant_limit_is_a_load_error() -> None:
    """It restricts nothing while reading as though it does."""
    with pytest.raises(PolicyError, match="must set per_transaction_cap"):
        Policy.from_yaml(
            "version: 1\ncurrency: USD\nagents:\n  bot:\n"
            "    per_transaction_cap: 50.00\n    merchants:\n      limits:\n"
            '        "api.openai.com": {}\n'
        )


def test_two_limit_patterns_that_normalize_alike_are_a_load_error() -> None:
    with pytest.raises(PolicyError, match="normalize to the same pattern"):
        Policy.from_yaml(
            "version: 1\ncurrency: USD\nagents:\n  bot:\n"
            "    per_transaction_cap: 50.00\n    merchants:\n      limits:\n"
            '        "API.Example.com":\n          per_transaction_cap: 1.00\n'
            '        "api.example.com":\n          per_transaction_cap: 40.00\n'
        )


def test_the_first_matching_pattern_wins() -> None:
    """A specific host placed above a wildcard takes effect."""
    policy = """
version: 1
currency: USD
agents:
  bot:
    per_transaction_cap: 500.00
    merchants:
      limits:
        "special.vendor.example":
          per_transaction_cap: 5.00
        "*.vendor.example":
          per_transaction_cap: 200.00
"""
    assert decide("special.vendor.example", "10.00", policy=policy) == (
        Outcome.DENY,
        ReasonCode.OVER_MERCHANT_CAP,
    )
    assert decide("other.vendor.example", "10.00", policy=policy) == (
        Outcome.ALLOW,
        ReasonCode.WITHIN_POLICY,
    )


def test_a_policy_without_limits_is_unaffected() -> None:
    """The feature must be invisible to every existing policy."""
    policy = """
version: 1
currency: USD
agents:
  bot:
    per_transaction_cap: 50.00
"""
    assert decide("anywhere.example", "40.00", policy=policy) == (
        Outcome.ALLOW,
        ReasonCode.WITHIN_POLICY,
    )
