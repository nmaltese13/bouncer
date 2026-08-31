"""bouncer — a policy enforcement point for agent spending.

bouncer sits between an AI agent and any payment rail, blocks transactions that
violate a declarative policy, and writes a tamper-evident, signed audit log of
every decision.

It never custodies funds. It is a policy *decision* point; the network is the
*enforcement* point. See the Threat Model in README.md for what that does and
does not buy you.
"""

from __future__ import annotations

from .client import (
    ApprovalRequired,
    Authorized,
    Client,
    InvalidSpend,
    SpendDenied,
    SpendRefused,
)
from .engine import evaluate, evaluate_tunnel
from .errors import BouncerError, PolicyError, UnparseableIntent
from .models import Decision, Outcome, PaymentIntent, ReasonCode, SpendRecord
from .policy import Policy, RuleSet
from .sources import LoadedPolicy, LocalFileSource, PolicySource

__version__ = "0.1.2"

__all__ = [
    "ApprovalRequired",
    "Authorized",
    "BouncerError",
    "Client",
    "Decision",
    "InvalidSpend",
    "LoadedPolicy",
    "LocalFileSource",
    "Outcome",
    "PaymentIntent",
    "Policy",
    "PolicyError",
    "PolicySource",
    "ReasonCode",
    "RuleSet",
    "SpendDenied",
    "SpendRecord",
    "SpendRefused",
    "UnparseableIntent",
    "__version__",
    "evaluate",
    "evaluate_tunnel",
]
