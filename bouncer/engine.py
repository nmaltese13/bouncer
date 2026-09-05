"""The policy engine: pure, deterministic, no I/O.

Threat model: this is the policy *decision* point. Everything it needs is passed
in — the policy, the spend history, and the current time. It performs no
network calls, reads no clock, touches no disk, and calls no model. The same
inputs always produce the same decision, which is what makes the decision
testable and the audit log meaningful.

Evaluation order is itself a security property and is fixed:

1. Is there a usable policy at all?          -> no: DENY
2. Does this agent appear in the policy?     -> no: DENY
3. Is the request well-formed?               -> no: DENY
4. Do any prohibitions fire?                 -> yes: DENY
5. Do any ceilings fire?                     -> yes: DENY
6. Is a human required?                      -> yes: REQUIRE_APPROVAL
7. Otherwise                                 -> ALLOW

Prohibitions are evaluated before the approval threshold on purpose: a
transaction that policy forbids must never be offered to an approver. A human
holding ``--role finance`` is there to exercise judgment inside policy, not to
override it.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Sequence
from datetime import datetime
from decimal import Decimal

from .models import Decision, Outcome, PaymentIntent, ReasonCode, SpendRecord
from .policy import Policy, RuleSet
from .sources import NO_POLICY_HASH, LoadedPolicy

__all__ = ["evaluate", "evaluate_tunnel", "window_spend"]


def _decide(
    outcome: Outcome,
    reason_code: ReasonCode,
    reason: str,
    *,
    policy_hash: str,
    now: datetime,
    rule: str | None = None,
    approver_role: str | None = None,
) -> Decision:
    return Decision(
        outcome=outcome,
        reason_code=reason_code,
        reason=reason,
        rule=rule,
        approver_role=approver_role,
        policy_hash=policy_hash,
        evaluated_at=now,
    )


def window_spend(
    history: Iterable[SpendRecord],
    *,
    agent_id: str,
    currency: str,
    since: datetime,
    until: datetime,
    merchant_pattern: str | None = None,
) -> Decimal:
    """Total committed spend for one agent in the half-open interval.

    The interval is ``(since, until]`` — a record exactly at the trailing edge
    has aged out. Records for other agents or other currencies are ignored;
    bouncer never converts between currencies, because doing so would require a
    live rate and make the decision non-deterministic.

    Args:
        merchant_pattern: Restrict the total to merchants matching this glob,
            for a ceiling scoped to one vendor. The pattern is matched against
            the record's own merchant, so a limit written as ``*.vendor.example``
            accumulates across every subdomain it covers rather than treating
            each as a separate budget.
    """
    total = Decimal(0)
    for record in history:
        if record.agent_id != agent_id or record.currency != currency:
            continue
        if merchant_pattern is not None and not fnmatch.fnmatchcase(
            record.merchant, merchant_pattern
        ):
            continue
        if since < record.timestamp <= until:
            total += record.amount
    return total


def evaluate(
    request: PaymentIntent,
    policy: Policy | LoadedPolicy | None,
    spend_history: Sequence[SpendRecord] = (),
    *,
    now: datetime,
) -> Decision:
    """Evaluate one payment intent. The only entry point that matters.

    Args:
        request: The normalized intent an adapter produced.
        policy: A :class:`Policy`, a :class:`LoadedPolicy` from a source, or
            ``None``. A missing or invalid policy denies.
        spend_history: Previously committed spends, for rolling-window ceilings.
            Records outside every window are harmless; the caller may over-fetch.
        now: The evaluation instant, injected. Must be timezone-aware.

    Returns:
        A :class:`Decision` naming the exact rule that fired.
    """
    if now.tzinfo is None:
        raise ValueError("`now` must be timezone-aware")

    # --- 1. policy availability ------------------------------------------
    if isinstance(policy, LoadedPolicy):
        if policy.policy is None:
            return _decide(
                Outcome.DENY,
                ReasonCode.POLICY_INVALID,
                policy.error or "policy could not be loaded",
                policy_hash=policy.policy_hash,
                now=now,
                rule="policy",
            )
        resolved = policy.policy
    elif policy is None:
        return _decide(
            Outcome.DENY,
            ReasonCode.POLICY_MISSING,
            "no policy supplied; bouncer denies by default",
            policy_hash=NO_POLICY_HASH,
            now=now,
            rule="policy",
        )
    else:
        resolved = policy

    policy_hash = resolved.policy_hash

    # --- 2. agent scoping -------------------------------------------------
    match = resolved.rules_for(request.agent_id)
    if match is None:
        return _decide(
            Outcome.DENY,
            ReasonCode.AGENT_NOT_IN_POLICY,
            f"agent {request.agent_id!r} is not named in the policy and no "
            f"'*' catch-all is defined",
            policy_hash=policy_hash,
            now=now,
            rule="agents",
        )
    agent_key, rules = match
    scope = f"agents.{agent_key}"

    # --- 3. request well-formedness --------------------------------------
    if request.amount <= 0:
        return _decide(
            Outcome.DENY,
            ReasonCode.INVALID_AMOUNT,
            f"amount must be positive, got {request.amount}",
            policy_hash=policy_hash,
            now=now,
            rule=f"{scope}.per_transaction_cap",
        )

    if request.currency != resolved.currency:
        return _decide(
            Outcome.DENY,
            ReasonCode.CURRENCY_MISMATCH,
            f"request is in {request.currency} but the policy is denominated in "
            f"{resolved.currency}; bouncer does not convert currencies",
            policy_hash=policy_hash,
            now=now,
            rule="currency",
        )

    # --- 4. prohibitions --------------------------------------------------
    prohibition = _check_prohibitions(request, rules, scope, now)
    if prohibition is not None:
        code, reason, rule = prohibition
        return _decide(
            Outcome.DENY, code, reason, policy_hash=policy_hash, now=now, rule=rule
        )

    # --- 5. ceilings ------------------------------------------------------
    if request.amount > rules.per_transaction_cap:
        return _decide(
            Outcome.DENY,
            ReasonCode.OVER_PER_TXN_CAP,
            f"{request.amount} {request.currency} exceeds the per-transaction "
            f"cap of {rules.per_transaction_cap} {resolved.currency}",
            policy_hash=policy_hash,
            now=now,
            rule=f"{scope}.per_transaction_cap",
        )

    for index, window in enumerate(rules.rolling_windows):
        spent = window_spend(
            spend_history,
            agent_id=request.agent_id,
            currency=resolved.currency,
            since=now - window.duration,
            until=now,
        )
        if spent + request.amount > window.amount:
            return _decide(
                Outcome.DENY,
                ReasonCode.OVER_ROLLING_WINDOW,
                f"{request.amount} {request.currency} would bring spend over the "
                f"last {window.window} to {spent + request.amount}, above the "
                f"{window.amount} ceiling (already spent {spent})",
                policy_hash=policy_hash,
                now=now,
                rule=f"{scope}.rolling_windows[{index}]",
            )

    # --- 5b. per-merchant ceilings ---------------------------------------
    #
    # Checked *after* the agent's own limits and never instead of them, so a
    # merchant limit can only tighten. A per-merchant cap written above the
    # agent cap changes nothing: the agent cap has already been applied and the
    # request would not have reached here. Letting a nested rule widen an outer
    # one would make the effective policy depend on reading two places at once.
    merchant_limit = rules.merchants.limit_for(request.merchant)
    if merchant_limit is not None:
        pattern, limit = merchant_limit
        limit_scope = f"{scope}.merchants.limits[{pattern!r}]"

        if limit.per_transaction_cap is not None and request.amount > limit.per_transaction_cap:
            return _decide(
                Outcome.DENY,
                ReasonCode.OVER_MERCHANT_CAP,
                f"{request.amount} {request.currency} exceeds the "
                f"{limit.per_transaction_cap} per-transaction cap for merchants "
                f"matching {pattern!r}",
                policy_hash=policy_hash,
                now=now,
                rule=f"{limit_scope}.per_transaction_cap",
            )

        for index, window in enumerate(limit.rolling_windows):
            spent = window_spend(
                spend_history,
                agent_id=request.agent_id,
                currency=resolved.currency,
                since=now - window.duration,
                until=now,
                merchant_pattern=pattern,
            )
            if spent + request.amount > window.amount:
                return _decide(
                    Outcome.DENY,
                    ReasonCode.OVER_MERCHANT_WINDOW,
                    f"{request.amount} {request.currency} would bring spend at "
                    f"merchants matching {pattern!r} over the last "
                    f"{window.window} to {spent + request.amount}, above the "
                    f"{window.amount} ceiling (already spent {spent})",
                    policy_hash=policy_hash,
                    now=now,
                    rule=f"{limit_scope}.rolling_windows[{index}]",
                )

    # --- 6. human in the loop --------------------------------------------
    approval = rules.approval_required_above
    if approval is not None and request.amount > approval.amount:
        return _decide(
            Outcome.REQUIRE_APPROVAL,
            ReasonCode.APPROVAL_REQUIRED,
            f"{request.amount} {request.currency} is above the "
            f"{approval.amount} approval threshold and needs sign-off from "
            f"{approval.approver_role!r}",
            policy_hash=policy_hash,
            now=now,
            rule=f"{scope}.approval_required_above",
            approver_role=approval.approver_role,
        )

    # --- 7. allow ---------------------------------------------------------
    return _decide(
        Outcome.ALLOW,
        ReasonCode.WITHIN_POLICY,
        f"{request.amount} {request.currency} to {request.merchant} is within "
        f"policy for {request.agent_id}",
        policy_hash=policy_hash,
        now=now,
        rule=scope,
    )


def _check_prohibitions(
    request: PaymentIntent, rules: RuleSet, scope: str, now: datetime
) -> tuple[ReasonCode, str, str] | None:
    """Apply the categorical prohibitions. Denylists always beat allowlists."""
    denied_by = rules.merchants.denied_by(request.merchant)
    if denied_by is not None:
        return (
            ReasonCode.MERCHANT_DENIED,
            f"merchant {request.merchant!r} matches denylist entry {denied_by!r}",
            f"{scope}.merchants.deny",
        )

    if rules.merchants.allow is not None:
        if rules.merchants.allowed_by(request.merchant) is None:
            return (
                ReasonCode.MERCHANT_NOT_ALLOWED,
                f"merchant {request.merchant!r} is not on the allowlist",
                f"{scope}.merchants.allow",
            )

    if request.category is not None:
        category_denied = rules.categories.denied_by(request.category)
        if category_denied is not None:
            return (
                ReasonCode.CATEGORY_DENIED,
                f"category {request.category!r} matches denylist entry "
                f"{category_denied!r}",
                f"{scope}.categories.deny",
            )

    if rules.categories.allow is not None:
        if request.category is None:
            return (
                ReasonCode.CATEGORY_NOT_ALLOWED,
                "request has no category, and the policy restricts categories; "
                "an uncategorized request cannot be shown to satisfy it",
                f"{scope}.categories.allow",
            )
        if rules.categories.allowed_by(request.category) is None:
            return (
                ReasonCode.CATEGORY_NOT_ALLOWED,
                f"category {request.category!r} is not on the allowlist",
                f"{scope}.categories.allow",
            )

    if rules.time_windows:
        if not any(window.contains(now) for window in rules.time_windows):
            return (
                ReasonCode.OUTSIDE_TIME_WINDOW,
                f"{now.isoformat()} falls outside every permitted spending window",
                f"{scope}.time_windows",
            )

    return None


def evaluate_tunnel(
    host: str,
    policy: Policy | LoadedPolicy | None,
    *,
    agent_id: str,
    now: datetime,
) -> Decision:
    """Decide whether to open an opaque CONNECT tunnel to ``host``.

    Threat model: this is a weaker check than :func:`evaluate`, and the weakness
    is structural. A CONNECT tunnel carries TLS, so bouncer sees a hostname and
    nothing else — no amount, no category, no intent. Amount caps, rolling
    windows and approval thresholds *cannot* be enforced on tunneled traffic.

    Because of that, this function grants a tunnel only when the host matches an
    explicit merchant allowlist entry. "Not on the denylist" is not sufficient
    here, unlike in :func:`evaluate`: an unenforceable channel is opened only to
    destinations the operator named. An agent that can reach an allowlisted host
    over TLS can spend any amount there without bouncer seeing it.

    Full enforcement of TLS traffic requires terminating it, which v1 does not
    do. See ROADMAP.md.
    """
    if now.tzinfo is None:
        raise ValueError("`now` must be timezone-aware")

    normalized = host.strip().lower().rstrip(".")

    if isinstance(policy, LoadedPolicy):
        resolved = policy.policy
        load_error = policy.error
        fallback_hash = policy.policy_hash
    else:
        resolved = policy
        load_error = None
        fallback_hash = NO_POLICY_HASH

    if resolved is None:
        return _decide(
            Outcome.DENY,
            ReasonCode.POLICY_INVALID if load_error else ReasonCode.POLICY_MISSING,
            load_error or "no policy supplied; bouncer denies by default",
            policy_hash=fallback_hash,
            now=now,
            rule="policy",
        )

    policy_hash = resolved.policy_hash
    match = resolved.rules_for(agent_id)
    if match is None:
        return _decide(
            Outcome.DENY,
            ReasonCode.AGENT_NOT_IN_POLICY,
            f"agent {agent_id!r} is not named in the policy",
            policy_hash=policy_hash,
            now=now,
            rule="agents",
        )
    agent_key, rules = match
    scope = f"agents.{agent_key}"

    denied_by = rules.merchants.denied_by(normalized)
    if denied_by is not None:
        return _decide(
            Outcome.DENY,
            ReasonCode.TUNNEL_NOT_PERMITTED,
            f"tunnel host {normalized!r} matches denylist entry {denied_by!r}",
            policy_hash=policy_hash,
            now=now,
            rule=f"{scope}.merchants.deny",
        )

    allowed_by = rules.merchants.allowed_by(normalized)
    if allowed_by is None:
        return _decide(
            Outcome.DENY,
            ReasonCode.TUNNEL_NOT_PERMITTED,
            f"tunnel host {normalized!r} is not on the merchant allowlist; "
            "encrypted tunnels are only opened to explicitly named hosts because "
            "their contents cannot be checked against spending rules",
            policy_hash=policy_hash,
            now=now,
            rule=f"{scope}.merchants.allow",
        )

    if rules.time_windows and not any(w.contains(now) for w in rules.time_windows):
        return _decide(
            Outcome.DENY,
            ReasonCode.OUTSIDE_TIME_WINDOW,
            f"{now.isoformat()} falls outside every permitted spending window",
            policy_hash=policy_hash,
            now=now,
            rule=f"{scope}.time_windows",
        )

    return _decide(
        Outcome.ALLOW,
        ReasonCode.TUNNEL_PERMITTED,
        f"tunnel to {normalized!r} permitted by allowlist entry {allowed_by!r}; "
        "contents are NOT enforced",
        policy_hash=policy_hash,
        now=now,
        rule=f"{scope}.merchants.allow",
    )
