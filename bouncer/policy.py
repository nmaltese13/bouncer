"""The declarative policy schema.

Threat model: this module decides what a policy *means*, so its defaults are
chosen to fail closed.

- Every model sets ``extra="forbid"``. A typo'd rule name is a loud error, not
  a silently-absent restriction. Accepting unknown keys would mean
  ``per_transaciton_cap: 5`` reads as "no cap at all".
- ``per_transaction_cap`` is mandatory on every rule set. There is no way to
  express "this agent may spend without a ceiling".
- An agent absent from ``agents`` is denied. Access is granted by naming, and
  the catch-all key ``"*"`` must be written explicitly to exist.
"""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime, time, timedelta
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any, Self
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .canonical import sha256_hex
from .errors import PolicyError
from .models import Money, _to_decimal

__all__ = [
    "ApprovalRule",
    "CategoryRules",
    "MerchantRules",
    "Policy",
    "RollingWindow",
    "RuleSet",
    "TimeWindow",
    "Weekday",
    "WILDCARD_AGENT",
    "parse_duration",
]

#: The explicit catch-all agent key. Must be written to take effect.
WILDCARD_AGENT = "*"

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)
_DURATION_UNITS: dict[str, timedelta] = {
    "s": timedelta(seconds=1),
    "m": timedelta(minutes=1),
    "h": timedelta(hours=1),
    "d": timedelta(days=1),
    "w": timedelta(weeks=1),
}


#: The longest rolling window a policy may declare. A ceiling is needed for two
#: reasons: ``timedelta`` overflows on absurd multipliers, and the value also
#: sets how far back spend history is read on every decision. Ten years is far
#: past any real budgeting period, so anything beyond it is a typo.
MAX_WINDOW = timedelta(days=3660)


def parse_duration(text: str) -> timedelta:
    """Parse a compact duration such as ``30d``, ``24h``, ``90m``.

    Raises ``ValueError`` on anything unusable. It must never raise anything
    else: pydantic converts ``ValueError`` into a validation error, which
    becomes a :class:`PolicyError` and therefore a deny. An exception of any
    other type escapes the policy source entirely and crashes the decision path
    instead of failing closed.
    """
    match = _DURATION_RE.match(text)
    if match is None:
        raise ValueError(
            f"invalid duration {text!r}; expected a form like '30d', '24h', '90m'"
        )
    count = int(match.group(1))
    if count <= 0:
        raise ValueError(f"duration must be positive: {text!r}")
    try:
        duration = _DURATION_UNITS[match.group(2).lower()] * count
    except OverflowError as exc:
        raise ValueError(f"duration {text!r} is too large to represent") from exc
    if duration > MAX_WINDOW:
        raise ValueError(
            f"duration {text!r} exceeds the {MAX_WINDOW.days}-day maximum; "
            "a window that long is a typo, not a budget"
        )
    return duration


class _Strict(BaseModel):
    """Base for policy models: immutable and intolerant of unknown keys."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class Weekday(str, Enum):
    MON = "mon"
    TUE = "tue"
    WED = "wed"
    THU = "thu"
    FRI = "fri"
    SAT = "sat"
    SUN = "sun"

    @property
    def weekday_number(self) -> int:
        """Match ``datetime.weekday()``, where Monday is 0.

        Not named ``index``: Weekday subclasses ``str``, and shadowing
        ``str.index`` with an incompatible signature is a trap.
        """
        return list(Weekday).index(self)


class RollingWindow(_Strict):
    """A ceiling on total spend across a trailing time window."""

    amount: Money
    window: str

    _coerce_amount = field_validator("amount", mode="before")(_to_decimal)

    @field_validator("window")
    @classmethod
    def _check_window(cls, value: str) -> str:
        parse_duration(value)  # raises on malformed input
        return value.strip().lower()

    @property
    def duration(self) -> timedelta:
        return parse_duration(self.window)


class MerchantLimit(_Strict):
    """A ceiling that applies at one merchant rather than across the agent.

    Threat model: these only ever *tighten*. A merchant limit is checked in
    addition to the agent's own cap and windows, never instead of them, so
    writing a per-merchant cap above the agent cap cannot raise what the agent
    may spend. Letting a nested rule widen an outer one would make the effective
    policy depend on reading two places at once, which is how a policy comes to
    permit something nobody intended.
    """

    per_transaction_cap: Money | None = None
    rolling_windows: list[RollingWindow] = Field(default_factory=list)

    _coerce_cap = field_validator("per_transaction_cap", mode="before")(_to_decimal)

    @model_validator(mode="after")
    def _must_restrict_something(self) -> Self:
        if self.per_transaction_cap is None and not self.rolling_windows:
            raise ValueError(
                "a merchant limit must set per_transaction_cap or at least one "
                "rolling window; an empty one restricts nothing and reads as if "
                "it does"
            )
        return self

    @property
    def longest_window(self) -> timedelta | None:
        if not self.rolling_windows:
            return None
        return max(window.duration for window in self.rolling_windows)


class MerchantRules(_Strict):
    """Merchant allowlist, denylist, and per-merchant ceilings.

    Patterns are shell-style globs matched case-insensitively, so
    ``*.example.com`` covers subdomains. ``deny`` always beats ``allow``.

    If ``allow`` is ``None`` the allowlist is not enforced and any merchant not
    on the denylist passes the merchant check. If ``allow`` is present, a
    merchant must match it. An empty list therefore means "no merchant is
    permitted", which is a usable way to freeze an agent.

    ``limits`` scopes a ceiling to one vendor: an agent may hold a large budget
    that is only spendable in small amounts anywhere in particular.
    """

    allow: list[str] | None = None
    deny: list[str] = Field(default_factory=list)
    limits: dict[str, MerchantLimit] = Field(default_factory=dict)

    @field_validator("allow", "deny")
    @classmethod
    def _normalize(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return [item.strip().lower().rstrip(".") for item in value]

    @field_validator("limits")
    @classmethod
    def _normalize_limits(
        cls, value: dict[str, MerchantLimit]
    ) -> dict[str, MerchantLimit]:
        """Normalize limit patterns, refusing two that collide once normalized.

        Same reasoning as agent keys: ``API.Example.com`` and
        ``api.example.com`` are one pattern, and silently keeping whichever came
        last would enforce a limit the operator did not choose.
        """
        out: dict[str, MerchantLimit] = {}
        seen: dict[str, str] = {}
        for key, limit in value.items():
            pattern = key.strip().lower().rstrip(".")
            if not pattern:
                raise ValueError("a merchant limit pattern must not be blank")
            if pattern in seen:
                raise ValueError(
                    f"merchant limits {seen[pattern]!r} and {key!r} normalize to "
                    f"the same pattern {pattern!r}; one would silently override "
                    "the other"
                )
            seen[pattern] = key
            out[pattern] = limit
        return out

    def denied_by(self, merchant: str) -> str | None:
        """Return the denylist pattern matching ``merchant``, if any."""
        return _first_match(merchant, self.deny)

    def allowed_by(self, merchant: str) -> str | None:
        """Return the allowlist pattern matching ``merchant``, if any."""
        return _first_match(merchant, self.allow or [])

    def limit_for(self, merchant: str) -> tuple[str, MerchantLimit] | None:
        """The first limit whose pattern matches ``merchant``.

        First match wins, in declaration order, so an operator can put a
        specific host above a wildcard and have it take effect.
        """
        for pattern, limit in self.limits.items():
            if fnmatch.fnmatchcase(merchant, pattern):
                return pattern, limit
        return None

    @property
    def longest_limit_window(self) -> timedelta | None:
        """The longest window across every per-merchant limit."""
        windows = [
            limit.longest_window
            for limit in self.limits.values()
            if limit.longest_window is not None
        ]
        return max(windows) if windows else None


class CategoryRules(_Strict):
    """Category allowlist and denylist, with the same precedence as merchants.

    An intent with no category is denied whenever ``allow`` is present: an
    uncategorized request cannot be shown to satisfy a categorical restriction.
    """

    allow: list[str] | None = None
    deny: list[str] = Field(default_factory=list)

    @field_validator("allow", "deny")
    @classmethod
    def _normalize(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return [item.strip().lower() for item in value]

    def denied_by(self, category: str) -> str | None:
        return _first_match(category, self.deny)

    def allowed_by(self, category: str) -> str | None:
        return _first_match(category, self.allow or [])


def _first_match(value: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        if fnmatch.fnmatchcase(value, pattern):
            return pattern
    return None


class TimeWindow(_Strict):
    """An interval during which spending is permitted.

    A window whose ``end`` is not after its ``start`` wraps past midnight, so
    ``22:00``-``02:00`` is a valid overnight window.
    """

    days: list[Weekday] | None = None
    start: time
    end: time
    timezone: str = "UTC"

    @field_validator("timezone")
    @classmethod
    def _check_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown timezone {value!r}") from exc
        return value

    @field_validator("start", "end")
    @classmethod
    def _drop_subminute(cls, value: time) -> time:
        if value.tzinfo is not None:
            raise ValueError("time window bounds must not carry a timezone offset")
        return value

    def contains(self, moment: datetime) -> bool:
        """Is ``moment`` (timezone-aware) inside this window?"""
        local = moment.astimezone(ZoneInfo(self.timezone))
        if self.days is not None and local.weekday() not in {
            day.weekday_number for day in self.days
        }:
            return False
        current = local.time()
        if self.start <= self.end:
            return self.start <= current <= self.end
        # Wrapping window, e.g. 22:00 -> 02:00.
        return current >= self.start or current <= self.end


class ApprovalRule(_Strict):
    """Above ``amount``, a human holding ``approver_role`` must sign off."""

    amount: Money
    approver_role: str = Field(min_length=1, max_length=64)

    _coerce_amount = field_validator("amount", mode="before")(_to_decimal)

    @field_validator("approver_role")
    @classmethod
    def _normalize_role(cls, value: str) -> str:
        role = value.strip().lower()
        if not role:
            raise ValueError("approver_role must not be blank")
        return role


class RuleSet(_Strict):
    """The complete set of restrictions applied to one agent."""

    per_transaction_cap: Money
    rolling_windows: list[RollingWindow] = Field(default_factory=list)
    merchants: MerchantRules = Field(default_factory=MerchantRules)
    categories: CategoryRules = Field(default_factory=CategoryRules)
    time_windows: list[TimeWindow] = Field(default_factory=list)
    approval_required_above: ApprovalRule | None = None

    _coerce_cap = field_validator("per_transaction_cap", mode="before")(_to_decimal)

    @property
    def longest_window(self) -> timedelta | None:
        """The longest rolling window anywhere in this rule set.

        Callers use this to decide how far back spend history must reach. A
        horizon shorter than this would under-count spend and fail open.

        Per-merchant windows are included deliberately. A merchant limit of
        ``500.00 per 90d`` under an agent whose own longest window is ``30d``
        would otherwise be judged against 30 days of history and let the agent
        spend several times its ceiling at that vendor — the exact failure this
        property exists to prevent, reintroduced one level down.
        """
        durations = [window.duration for window in self.rolling_windows]
        merchant_longest = self.merchants.longest_limit_window
        if merchant_longest is not None:
            durations.append(merchant_longest)
        return max(durations) if durations else None

    @model_validator(mode="after")
    def _check_threshold_below_cap(self) -> Self:
        """An approval threshold above the hard cap can never fire.

        That is almost always a typo, and a policy that silently contains an
        unreachable approval step reads as safer than it is.
        """
        rule = self.approval_required_above
        if rule is not None and rule.amount >= self.per_transaction_cap:
            raise ValueError(
                f"approval_required_above.amount ({rule.amount}) is not below "
                f"per_transaction_cap ({self.per_transaction_cap}), so approval "
                "could never be requested; lower the threshold or raise the cap"
            )
        return self


class Policy(_Strict):
    """A complete, validated policy document."""

    version: int = Field(default=1, ge=1, le=1)
    currency: str = Field(default="USD", min_length=3, max_length=12)
    agents: dict[str, RuleSet] = Field(min_length=1)

    @field_validator("currency")
    @classmethod
    def _normalize_currency(cls, value: str) -> str:
        """An ISO 4217 code (USD) or a token symbol for crypto rails (USDC).

        A request in any other currency is denied outright rather than
        converted; see PaymentIntent.currency.
        """
        currency = value.strip().upper()
        if not currency.isalnum():
            raise ValueError("currency must be alphanumeric (ISO 4217 code or token symbol)")
        return currency

    @field_validator("agents")
    @classmethod
    def _normalize_agents(cls, value: dict[str, RuleSet]) -> dict[str, RuleSet]:
        """Strip agent keys, and refuse two that collide once stripped.

        Threat model: ``"bot"`` and ``"bot "`` both normalize to ``bot``, and a
        plain dict would keep whichever came last. In practice the survivor was
        the *looser* rule as often as not, so an operator could add a strict
        entry, have it silently discarded, and be told nothing. A policy that
        quietly means something other than what is written is the failure this
        schema exists to prevent, so a collision is a load error.
        """
        out: dict[str, RuleSet] = {}
        seen: dict[str, str] = {}
        for key, rules in value.items():
            agent = key.strip()
            if not agent:
                raise ValueError("agent id must not be blank")
            if agent in seen:
                raise ValueError(
                    f"agents {seen[agent]!r} and {key!r} are the same agent "
                    f"({agent!r}) once surrounding whitespace is stripped; one "
                    "would silently override the other"
                )
            seen[agent] = key
            out[agent] = rules
        return out

    def rules_for(self, agent_id: str) -> tuple[str, RuleSet] | None:
        """Resolve the rule set governing ``agent_id``.

        Exact identity wins over the ``"*"`` catch-all. Returns the matched key
        alongside the rules so decisions can name the exact rule that fired.
        """
        if agent_id in self.agents:
            return agent_id, self.agents[agent_id]
        if WILDCARD_AGENT in self.agents:
            return WILDCARD_AGENT, self.agents[WILDCARD_AGENT]
        return None

    @property
    def policy_hash(self) -> str:
        """SHA-256 over the canonical form, recorded with every decision.

        This is what lets an auditor prove which policy text produced a given
        verdict, even if the file has since been edited.
        """
        return sha256_hex(self.model_dump(mode="python"))

    @classmethod
    def from_yaml(cls, text: str) -> Policy:
        """Parse and validate a YAML policy document.

        Raises :class:`PolicyError` on anything malformed. Callers that must not
        raise should use a :class:`~bouncer.sources.PolicySource`, which turns
        failures into an explicit deny.
        """
        try:
            raw = yaml.load(text, Loader=_DecimalSafeLoader)
        except yaml.YAMLError as exc:
            raise PolicyError(f"policy is not valid YAML: {exc}") from exc
        if raw is None:
            raise PolicyError("policy file is empty; an empty policy denies everything")
        if not isinstance(raw, dict):
            raise PolicyError(
                f"policy must be a mapping at the top level, got {type(raw).__name__}"
            )
        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            raise PolicyError(f"policy failed validation:\n{exc}") from exc


class _DecimalSafeLoader(yaml.SafeLoader):
    """A YAML loader that produces ``Decimal`` instead of ``float``.

    Threat model: ``per_transaction_cap: 100.10`` loaded as a binary float is
    not 100.10, and a cap that is a hair above or below the number the operator
    wrote is a policy the operator did not author. Parsing straight to Decimal
    keeps the written value exact.

    It also rejects duplicate mapping keys. YAML permits them and PyYAML keeps
    the last silently, so a policy naming an agent or a rule twice would enforce
    only one of the two with no indication which. Written twice, meant once.
    """

    def construct_mapping(
        self, node: yaml.MappingNode, deep: bool = False
    ) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    f"duplicate key {key!r}; the second would silently replace "
                    "the first",
                    key_node.start_mark,
                )
            seen.add(key)
        mapping: dict[Any, Any] = super().construct_mapping(node, deep=deep)
        return mapping


def _construct_decimal(loader: yaml.SafeLoader, node: yaml.Node) -> Decimal:
    value = loader.construct_scalar(node)  # type: ignore[arg-type]
    try:
        parsed = Decimal(str(value))
    except ArithmeticError as exc:
        raise yaml.constructor.ConstructorError(
            None, None, f"invalid decimal value {value!r}", node.start_mark
        ) from exc
    if not parsed.is_finite():
        raise yaml.constructor.ConstructorError(
            None, None, f"non-finite number {value!r} is not allowed in a policy",
            node.start_mark,
        )
    return parsed


_DecimalSafeLoader.add_constructor("tag:yaml.org,2002:float", _construct_decimal)


def load_policy_file(path: str | Path) -> Policy:
    """Read and validate a policy from disk. Raises :class:`PolicyError`."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy at {file_path}: {exc}") from exc
    return Policy.from_yaml(text)
