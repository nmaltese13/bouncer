"""M1 — the policy engine.

Boundary conditions are the substance of these tests: "exactly at the cap" and
"exactly at the threshold" are where a spending control is actually defined.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import pytest

from bouncer.engine import evaluate, evaluate_tunnel
from bouncer.errors import PolicyError
from bouncer.models import Outcome, ReasonCode
from bouncer.policy import Policy
from bouncer.sources import LoadedPolicy

from .conftest import NOW, SIMPLE_POLICY, intent, policy_from, spend

# ---------------------------------------------------------------------------
# deny by default
# ---------------------------------------------------------------------------


def test_no_policy_denies() -> None:
    decision = evaluate(intent(), None, now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.POLICY_MISSING


def test_failed_policy_load_denies_and_reports_the_error() -> None:
    loaded = LoadedPolicy.failed("file not found", origin="file:/nope.yaml")
    decision = evaluate(intent(), loaded, now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.POLICY_INVALID
    assert "file not found" in decision.reason


def test_empty_policy_document_is_rejected() -> None:
    with pytest.raises(PolicyError, match="empty"):
        Policy.from_yaml("")


def test_policy_with_no_agents_is_rejected() -> None:
    with pytest.raises(PolicyError):
        Policy.from_yaml("version: 1\ncurrency: USD\nagents: {}\n")


def test_unknown_agent_is_denied() -> None:
    decision = evaluate(intent(agent_id="rogue-bot"), policy_from(SIMPLE_POLICY), now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.AGENT_NOT_IN_POLICY


def test_wildcard_agent_must_be_written_explicitly() -> None:
    policy = policy_from(
        """
        version: 1
        agents:
          "*":
            per_transaction_cap: 5.00
        """
    )
    decision = evaluate(intent(amount=Decimal("4.00"), agent_id="anyone"), policy, now=NOW)
    assert decision.outcome is Outcome.ALLOW
    assert decision.rule == "agents.*"


def test_exact_agent_match_beats_wildcard() -> None:
    policy = policy_from(
        """
        version: 1
        agents:
          "*":
            per_transaction_cap: 1.00
          research-bot:
            per_transaction_cap: 500.00
        """
    )
    decision = evaluate(intent(amount=Decimal("400.00")), policy, now=NOW)
    assert decision.outcome is Outcome.ALLOW
    assert decision.rule == "agents.research-bot"


def test_typo_in_a_rule_name_is_a_hard_error_not_a_missing_restriction() -> None:
    with pytest.raises(PolicyError):
        Policy.from_yaml(
            "version: 1\nagents:\n  bot:\n    per_transaciton_cap: 5.00\n"
        )


def test_rule_set_without_a_cap_is_rejected() -> None:
    with pytest.raises(PolicyError):
        Policy.from_yaml("version: 1\nagents:\n  bot:\n    merchants:\n      deny: []\n")


# ---------------------------------------------------------------------------
# per-transaction cap boundaries
# ---------------------------------------------------------------------------


def test_below_cap_allows() -> None:
    decision = evaluate(intent(amount=Decimal("99.99")), policy_from(SIMPLE_POLICY), now=NOW)
    assert decision.outcome is Outcome.ALLOW
    assert decision.reason_code is ReasonCode.WITHIN_POLICY


def test_exactly_at_cap_allows() -> None:
    decision = evaluate(intent(amount=Decimal("100.00")), policy_from(SIMPLE_POLICY), now=NOW)
    assert decision.outcome is Outcome.ALLOW


def test_one_cent_over_cap_denies() -> None:
    decision = evaluate(intent(amount=Decimal("100.01")), policy_from(SIMPLE_POLICY), now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.OVER_PER_TXN_CAP
    assert decision.rule == "agents.research-bot.per_transaction_cap"


def test_zero_amount_denies() -> None:
    decision = evaluate(intent(amount=Decimal("0")), policy_from(SIMPLE_POLICY), now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.INVALID_AMOUNT


def test_cap_written_with_trailing_zeros_is_exact() -> None:
    """100.10 must not become 100.09999999999999 via a binary float."""
    policy = policy_from("version: 1\nagents:\n  research-bot:\n    per_transaction_cap: 100.10\n")
    rules = policy.agents["research-bot"]
    assert rules.per_transaction_cap == Decimal("100.10")
    assert evaluate(intent(amount=Decimal("100.10")), policy, now=NOW).outcome is Outcome.ALLOW


# ---------------------------------------------------------------------------
# rolling windows
# ---------------------------------------------------------------------------

WINDOW_POLICY = """
version: 1
currency: USD
agents:
  research-bot:
    per_transaction_cap: 500.00
    rolling_windows:
      - amount: 2000.00
        window: 30d
"""


def test_rolling_window_allows_when_under_ceiling() -> None:
    history = [spend("500.00", days_ago=2), spend("400.00", days_ago=10)]
    decision = evaluate(intent(amount=Decimal("100.00")), policy_from(WINDOW_POLICY), history, now=NOW)
    assert decision.outcome is Outcome.ALLOW


def test_rolling_window_exactly_at_ceiling_allows() -> None:
    history = [spend("1900.00", days_ago=5)]
    decision = evaluate(intent(amount=Decimal("100.00")), policy_from(WINDOW_POLICY), history, now=NOW)
    assert decision.outcome is Outcome.ALLOW


def test_rolling_window_one_cent_over_ceiling_denies() -> None:
    history = [spend("1900.00", days_ago=5)]
    decision = evaluate(intent(amount=Decimal("100.01")), policy_from(WINDOW_POLICY), history, now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.OVER_ROLLING_WINDOW
    assert decision.rule == "agents.research-bot.rolling_windows[0]"


def test_spend_rolls_out_of_the_window() -> None:
    """Spend from 31 days ago no longer counts against a 30-day ceiling."""
    history = [spend("1950.00", days_ago=31)]
    decision = evaluate(intent(amount=Decimal("100.00")), policy_from(WINDOW_POLICY), history, now=NOW)
    assert decision.outcome is Outcome.ALLOW


def test_spend_exactly_at_the_window_edge_has_aged_out() -> None:
    """The window is half-open: a record at exactly -30d is outside it."""
    history = [spend("1950.00", days_ago=30.0)]
    decision = evaluate(intent(amount=Decimal("100.00")), policy_from(WINDOW_POLICY), history, now=NOW)
    assert decision.outcome is Outcome.ALLOW


def test_spend_just_inside_the_window_still_counts() -> None:
    history = [spend("1950.00", days_ago=29.999)]
    decision = evaluate(intent(amount=Decimal("100.00")), policy_from(WINDOW_POLICY), history, now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.OVER_ROLLING_WINDOW


def test_other_agents_spend_does_not_count_against_this_agent() -> None:
    history = [spend("1990.00", days_ago=1, agent_id="other-bot")]
    decision = evaluate(intent(amount=Decimal("100.00")), policy_from(WINDOW_POLICY), history, now=NOW)
    assert decision.outcome is Outcome.ALLOW


def test_multiple_windows_all_apply() -> None:
    policy = policy_from(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 500.00
            rolling_windows:
              - amount: 2000.00
                window: 30d
              - amount: 200.00
                window: 24h
        """
    )
    history = [spend("150.00", days_ago=0.5)]
    decision = evaluate(intent(amount=Decimal("100.00")), policy, history, now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.rule == "agents.research-bot.rolling_windows[1]"


# ---------------------------------------------------------------------------
# merchant and category rules
# ---------------------------------------------------------------------------

LIST_POLICY = """
version: 1
agents:
  research-bot:
    per_transaction_cap: 100.00
    merchants:
      allow: ["api.example.com", "*.trusted.dev"]
      deny: ["evil.example.com", "*.casino.example"]
"""


def test_allowlisted_merchant_allows() -> None:
    decision = evaluate(intent(merchant="api.example.com"), policy_from(LIST_POLICY), now=NOW)
    assert decision.outcome is Outcome.ALLOW


def test_wildcard_allowlist_matches_subdomain() -> None:
    decision = evaluate(intent(merchant="billing.trusted.dev"), policy_from(LIST_POLICY), now=NOW)
    assert decision.outcome is Outcome.ALLOW


def test_merchant_not_on_allowlist_denies() -> None:
    decision = evaluate(intent(merchant="unknown.example.com"), policy_from(LIST_POLICY), now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.MERCHANT_NOT_ALLOWED


def test_denylist_beats_allowlist() -> None:
    """A merchant on both lists is denied. Prohibition wins."""
    policy = policy_from(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 100.00
            merchants:
              allow: ["*.example.com"]
              deny: ["evil.example.com"]
        """
    )
    decision = evaluate(intent(merchant="evil.example.com"), policy, now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.MERCHANT_DENIED
    assert decision.rule == "agents.research-bot.merchants.deny"


def test_merchant_matching_is_case_insensitive() -> None:
    """EVIL.example.com must not slip past a lowercase denylist entry."""
    decision = evaluate(intent(merchant="EVIL.example.com"), policy_from(LIST_POLICY), now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.MERCHANT_DENIED


def test_empty_allowlist_freezes_the_agent() -> None:
    policy = policy_from(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 100.00
            merchants:
              allow: []
        """
    )
    decision = evaluate(intent(), policy, now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.MERCHANT_NOT_ALLOWED


def test_absent_allowlist_permits_any_undenied_merchant() -> None:
    policy = policy_from(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 100.00
            merchants:
              deny: ["evil.example.com"]
        """
    )
    assert evaluate(intent(merchant="anything.com"), policy, now=NOW).outcome is Outcome.ALLOW
    assert evaluate(intent(merchant="evil.example.com"), policy, now=NOW).outcome is Outcome.DENY


def test_denied_category_denies() -> None:
    policy = policy_from(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 100.00
            categories:
              deny: ["gambling"]
        """
    )
    decision = evaluate(intent(category="gambling"), policy, now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.CATEGORY_DENIED


def test_uncategorized_request_denied_when_categories_are_restricted() -> None:
    policy = policy_from(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 100.00
            categories:
              allow: ["api_credits"]
        """
    )
    decision = evaluate(intent(category=None), policy, now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.CATEGORY_NOT_ALLOWED


# ---------------------------------------------------------------------------
# currency
# ---------------------------------------------------------------------------


def test_currency_mismatch_denies_rather_than_converting() -> None:
    decision = evaluate(intent(currency="EUR"), policy_from(SIMPLE_POLICY), now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.CURRENCY_MISMATCH


# ---------------------------------------------------------------------------
# time windows
# ---------------------------------------------------------------------------

HOURS_POLICY = """
version: 1
agents:
  research-bot:
    per_transaction_cap: 100.00
    time_windows:
      - days: [mon, tue, wed, thu, fri]
        start: "09:00"
        end: "18:00"
        timezone: "UTC"
"""


def test_inside_business_hours_allows() -> None:
    decision = evaluate(intent(), policy_from(HOURS_POLICY), now=NOW)
    assert decision.outcome is Outcome.ALLOW


def test_outside_business_hours_denies() -> None:
    decision = evaluate(intent(), policy_from(HOURS_POLICY), now=NOW.replace(hour=3))
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.OUTSIDE_TIME_WINDOW


def test_weekend_denies() -> None:
    saturday = NOW + timedelta(days=3)
    assert saturday.weekday() == 5
    decision = evaluate(intent(), policy_from(HOURS_POLICY), now=saturday)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.OUTSIDE_TIME_WINDOW


def test_window_boundary_is_inclusive() -> None:
    at_open = NOW.replace(hour=9, minute=0)
    at_close = NOW.replace(hour=18, minute=0)
    assert evaluate(intent(), policy_from(HOURS_POLICY), now=at_open).outcome is Outcome.ALLOW
    assert evaluate(intent(), policy_from(HOURS_POLICY), now=at_close).outcome is Outcome.ALLOW


def test_overnight_window_wraps_past_midnight() -> None:
    policy = policy_from(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 100.00
            time_windows:
              - start: "22:00"
                end: "02:00"
        """
    )
    assert evaluate(intent(), policy, now=NOW.replace(hour=23)).outcome is Outcome.ALLOW
    assert evaluate(intent(), policy, now=NOW.replace(hour=1)).outcome is Outcome.ALLOW
    assert evaluate(intent(), policy, now=NOW.replace(hour=12)).outcome is Outcome.DENY


def test_time_window_respects_its_declared_timezone() -> None:
    """Both cases below flip if the declared timezone is ignored.

    On 2026-03-11 New York is on EDT (UTC-4), so:
      09:30 UTC -> 05:30 EDT: outside the NY window, but *inside* 09:00-17:00 UTC.
      20:00 UTC -> 16:00 EDT: inside the NY window, but *outside* 09:00-17:00 UTC.
    An implementation that evaluated in UTC would get both backwards.
    """
    policy = policy_from(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 100.00
            time_windows:
              - start: "09:00"
                end: "17:00"
                timezone: "America/New_York"
        """
    )
    too_early = evaluate(intent(), policy, now=NOW.replace(hour=9, minute=30))
    assert too_early.outcome is Outcome.DENY
    assert too_early.reason_code is ReasonCode.OUTSIDE_TIME_WINDOW

    late_but_local = evaluate(intent(), policy, now=NOW.replace(hour=20, minute=0))
    assert late_but_local.outcome is Outcome.ALLOW


# ---------------------------------------------------------------------------
# approval threshold and role
# ---------------------------------------------------------------------------

APPROVAL_POLICY = """
version: 1
agents:
  research-bot:
    per_transaction_cap: 500.00
    approval_required_above:
      amount: 50.00
      approver_role: finance
"""


def test_at_threshold_needs_no_approval() -> None:
    decision = evaluate(intent(amount=Decimal("50.00")), policy_from(APPROVAL_POLICY), now=NOW)
    assert decision.outcome is Outcome.ALLOW


def test_above_threshold_requires_approval_and_names_the_role() -> None:
    decision = evaluate(intent(amount=Decimal("50.01")), policy_from(APPROVAL_POLICY), now=NOW)
    assert decision.outcome is Outcome.REQUIRE_APPROVAL
    assert decision.reason_code is ReasonCode.APPROVAL_REQUIRED
    assert decision.approver_role == "finance"
    assert decision.rule == "agents.research-bot.approval_required_above"


def test_a_denied_transaction_is_never_sent_to_an_approver() -> None:
    """Prohibitions outrank the approval step; humans work inside policy."""
    policy = policy_from(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 500.00
            merchants:
              deny: ["evil.example.com"]
            approval_required_above:
              amount: 50.00
              approver_role: finance
        """
    )
    decision = evaluate(intent(amount=Decimal("400.00"), merchant="evil.example.com"), policy, now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.MERCHANT_DENIED


def test_over_cap_denies_rather_than_requesting_approval() -> None:
    decision = evaluate(intent(amount=Decimal("600.00")), policy_from(APPROVAL_POLICY), now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.OVER_PER_TXN_CAP


def test_unreachable_approval_threshold_is_rejected_at_load() -> None:
    """A threshold at or above the cap could never fire, so it is a typo."""
    with pytest.raises(PolicyError, match="approval"):
        Policy.from_yaml(
            """
            version: 1
            agents:
              bot:
                per_transaction_cap: 50.00
                approval_required_above:
                  amount: 100.00
                  approver_role: finance
            """
        )


def test_distinct_roles_per_agent() -> None:
    policy = policy_from(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 500.00
            approval_required_above:
              amount: 50.00
              approver_role: manager
          procurement-bot:
            per_transaction_cap: 20000.00
            approval_required_above:
              amount: 5000.00
              approver_role: cfo
        """
    )
    assert evaluate(intent(amount=Decimal("100.00")), policy, now=NOW).approver_role == "manager"
    big = intent(agent_id="procurement-bot", amount=Decimal("9000.00"))
    assert evaluate(big, policy, now=NOW).approver_role == "cfo"


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


def test_evaluation_is_deterministic() -> None:
    policy = policy_from(WINDOW_POLICY)
    history = [spend("100.00", days_ago=3)]
    first = evaluate(intent(), policy, history, now=NOW)
    second = evaluate(intent(), policy, history, now=NOW)
    assert first.model_dump() == second.model_dump()


def test_naive_now_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate(intent(), policy_from(SIMPLE_POLICY), now=NOW.replace(tzinfo=None))


def test_every_decision_carries_the_policy_hash() -> None:
    policy = policy_from(SIMPLE_POLICY)
    decision = evaluate(intent(), policy, now=NOW)
    assert decision.policy_hash == policy.policy_hash
    assert len(decision.policy_hash) == 64


def test_policy_hash_changes_when_the_policy_changes() -> None:
    a = policy_from(SIMPLE_POLICY)
    b = policy_from(SIMPLE_POLICY.replace("100.00", "200.00"))
    assert a.policy_hash != b.policy_hash


# ---------------------------------------------------------------------------
# CONNECT tunnels
# ---------------------------------------------------------------------------


def test_tunnel_requires_an_explicit_allowlist_entry() -> None:
    """Not-on-the-denylist is not enough for an unenforceable channel."""
    policy = policy_from(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 100.00
            merchants:
              deny: ["evil.example.com"]
        """
    )
    decision = evaluate_tunnel("api.example.com", policy, agent_id="research-bot", now=NOW)
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code is ReasonCode.TUNNEL_NOT_PERMITTED


def test_tunnel_to_allowlisted_host_is_permitted() -> None:
    decision = evaluate_tunnel("api.example.com", policy_from(LIST_POLICY), agent_id="research-bot", now=NOW)
    assert decision.outcome is Outcome.ALLOW
    assert decision.reason_code is ReasonCode.TUNNEL_PERMITTED
    assert "NOT enforced" in decision.reason


def test_tunnel_denylist_beats_allowlist() -> None:
    policy = policy_from(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 100.00
            merchants:
              allow: ["*.example.com"]
              deny: ["evil.example.com"]
        """
    )
    decision = evaluate_tunnel("evil.example.com", policy, agent_id="research-bot", now=NOW)
    assert decision.outcome is Outcome.DENY


def test_tunnel_without_policy_denies() -> None:
    decision = evaluate_tunnel("api.example.com", None, agent_id="research-bot", now=NOW)
    assert decision.outcome is Outcome.DENY


# ---------------------------------------------------------------------------
# a policy must mean exactly what is written, or refuse to load
# ---------------------------------------------------------------------------


def test_agent_keys_colliding_after_strip_are_a_load_error() -> None:
    """'bot' and 'bot ' both normalize to 'bot'.

    A plain dict kept whichever came last, and in practice that was as often
    the looser rule as the stricter one -- so an operator could add a strict
    entry, have it silently discarded, and be told nothing.
    """
    with pytest.raises(PolicyError, match="same agent"):
        policy_from(
            'version: 1\ncurrency: USD\nagents:\n'
            '  "bot":\n    per_transaction_cap: 1.00\n'
            '  "bot ":\n    per_transaction_cap: 9999.00\n'
        )


def test_a_duplicate_yaml_key_is_a_load_error() -> None:
    """YAML allows duplicates and PyYAML keeps the last one silently."""
    with pytest.raises(PolicyError, match="duplicate key"):
        policy_from(
            "version: 1\ncurrency: USD\nagents:\n"
            "  bot:\n    per_transaction_cap: 1.00\n"
            "  bot:\n    per_transaction_cap: 9999.00\n"
        )


def test_a_duplicate_rule_key_is_a_load_error() -> None:
    with pytest.raises(PolicyError, match="duplicate key"):
        policy_from(
            "version: 1\ncurrency: USD\nagents:\n  bot:\n"
            "    per_transaction_cap: 1.00\n    per_transaction_cap: 9999.00\n"
        )


@pytest.mark.parametrize("window", ["999999999999w", "99999999999999999999d", "4000d"])
def test_an_unusable_window_denies_instead_of_crashing(window: str) -> None:
    """parse_duration overflowed timedelta and raised OverflowError.

    That is not a ValueError, so pydantic did not convert it, PolicyError was
    never raised, and the exception escaped LocalFileSource.load() -- which is
    documented as never raising. The decision path crashed instead of denying.
    """
    with pytest.raises(PolicyError):
        policy_from(
            "version: 1\ncurrency: USD\nagents:\n  bot:\n"
            "    per_transaction_cap: 10.00\n    rolling_windows:\n"
            f'      - amount: 5.00\n        window: "{window}"\n'
        )


def test_a_realistic_long_window_still_loads() -> None:
    """The ceiling must not reject an actually plausible budgeting period."""
    policy = policy_from(
        "version: 1\ncurrency: USD\nagents:\n  bot:\n"
        "    per_transaction_cap: 10.00\n    rolling_windows:\n"
        "      - amount: 5.00\n        window: 365d\n"
    )
    assert policy.agents["bot"].rolling_windows[0].duration == timedelta(days=365)
