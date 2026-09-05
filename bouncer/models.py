"""Core domain models: the normalized payment intent and the decision.

``PaymentIntent`` is the single internal representation every payment rail maps
into. Adding a rail means writing one adapter that produces this model; nothing
downstream of the adapter knows which rail a request came from.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "Decision",
    "Money",
    "Outcome",
    "PaymentIntent",
    "ReasonCode",
    "SpendRecord",
    "new_intent_id",
]


def _to_decimal(value: Any) -> Any:
    """Coerce incoming numbers to ``Decimal`` without going through binary float.

    A YAML or JSON literal like ``100.10`` arrives as a Python float whose exact
    value is not 100.10. Routing it through ``str`` recovers the shortest
    round-trip representation, which is the number the author actually wrote.
    """
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, int) and not isinstance(value, bool):
        return Decimal(value)
    return value


#: A non-negative, finite monetary amount held to at most 2 decimal places of
#: precision beyond the minor unit, and bounded well below any realistic spend.
Money = Annotated[
    Decimal,
    Field(ge=Decimal(0), le=Decimal("1e12"), max_digits=18, decimal_places=6),
]


def new_intent_id() -> str:
    """Generate an opaque intent identifier."""
    return uuid.uuid4().hex


class Outcome(str, Enum):
    """The three terminal states of a policy evaluation."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ReasonCode(str, Enum):
    """Machine-readable reason for a decision.

    These strings are a stable API: they land in the audit log and downstream
    SIEM rules key off them. Add codes; do not repurpose existing ones.
    """

    # --- allow -----------------------------------------------------------
    WITHIN_POLICY = "WITHIN_POLICY"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    TUNNEL_PERMITTED = "TUNNEL_PERMITTED"

    # --- deny: policy availability ---------------------------------------
    POLICY_MISSING = "POLICY_MISSING"
    POLICY_INVALID = "POLICY_INVALID"
    AGENT_NOT_IN_POLICY = "AGENT_NOT_IN_POLICY"

    # --- deny: request well-formedness -----------------------------------
    INVALID_AMOUNT = "INVALID_AMOUNT"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    UNPARSEABLE_INTENT = "UNPARSEABLE_INTENT"

    # --- deny: rule violations -------------------------------------------
    MERCHANT_DENIED = "MERCHANT_DENIED"
    MERCHANT_NOT_ALLOWED = "MERCHANT_NOT_ALLOWED"
    CATEGORY_DENIED = "CATEGORY_DENIED"
    CATEGORY_NOT_ALLOWED = "CATEGORY_NOT_ALLOWED"
    OUTSIDE_TIME_WINDOW = "OUTSIDE_TIME_WINDOW"
    OVER_PER_TXN_CAP = "OVER_PER_TXN_CAP"
    OVER_ROLLING_WINDOW = "OVER_ROLLING_WINDOW"
    OVER_MERCHANT_CAP = "OVER_MERCHANT_CAP"
    OVER_MERCHANT_WINDOW = "OVER_MERCHANT_WINDOW"
    TUNNEL_NOT_PERMITTED = "TUNNEL_NOT_PERMITTED"

    # --- approval lifecycle ----------------------------------------------
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    APPROVAL_TIMEOUT = "APPROVAL_TIMEOUT"


class PaymentIntent(BaseModel):
    """A normalized, rail-agnostic description of a payment about to happen."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    intent_id: str = Field(default_factory=new_intent_id, min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    merchant: str = Field(min_length=1, max_length=253)
    amount: Money
    currency: str = Field(min_length=3, max_length=12)
    category: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=512)
    rail: str = Field(default="generic", min_length=1, max_length=32)
    metadata: dict[str, str] = Field(default_factory=dict)

    _coerce_amount = field_validator("amount", mode="before")(_to_decimal)

    @field_validator("merchant")
    @classmethod
    def _normalize_merchant(cls, value: str) -> str:
        """Merchants are matched case-insensitively, so store them folded.

        Matching a denylist against unnormalized input is a bypass: ``EVIL.com``
        would sail past a rule written as ``evil.com``.
        """
        return value.strip().lower().rstrip(".")

    @field_validator("currency")
    @classmethod
    def _normalize_currency(cls, value: str) -> str:
        """An ISO 4217 code (USD) or a token symbol for crypto rails (USDC).

        Symbols are compared to the policy's currency verbatim. bouncer never
        treats two different symbols as equivalent — not even USDC and USD —
        because deciding they are worth the same requires a live exchange rate,
        and the engine is not allowed to consult one.
        """
        currency = value.strip().upper()
        if not currency.isalnum():
            raise ValueError("currency must be alphanumeric (ISO 4217 code or token symbol)")
        return currency

    @field_validator("category")
    @classmethod
    def _normalize_category(cls, value: str | None) -> str | None:
        return value.strip().lower() if value is not None else None


class Decision(BaseModel):
    """The result of evaluating one intent against one policy.

    Always carries a machine-readable ``reason_code``, the dotted path of the
    specific ``rule`` that fired, and ``approver_role`` when approval is needed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    outcome: Outcome
    reason_code: ReasonCode
    reason: str
    rule: str | None = None
    approver_role: str | None = None
    policy_hash: str
    evaluated_at: datetime

    @property
    def allowed(self) -> bool:
        return self.outcome is Outcome.ALLOW

    def describe(self) -> str:
        """One-line human summary, used by the CLI and the demo."""
        parts = [f"{self.outcome.value}", f"[{self.reason_code.value}]", self.reason]
        if self.rule:
            parts.append(f"(rule: {self.rule})")
        if self.approver_role:
            parts.append(f"(approver: {self.approver_role})")
        return " ".join(parts)


class SpendRecord(BaseModel):
    """One historical committed spend, used to evaluate rolling windows.

    ``merchant`` is carried because ceilings can be scoped to one vendor, not
    only to the agent as a whole. It is normalized the same way
    :attr:`PaymentIntent.merchant` is, so a per-merchant total cannot be split
    across ``API.Example.com`` and ``api.example.com``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str
    amount: Money
    currency: str
    timestamp: datetime
    merchant: str = ""

    _coerce_amount = field_validator("amount", mode="before")(_to_decimal)

    @field_validator("merchant")
    @classmethod
    def _normalize_merchant(cls, value: str) -> str:
        return value.strip().lower().rstrip(".")
