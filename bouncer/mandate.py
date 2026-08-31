"""Signed, scoped, short-lived mandates.

A mandate is the artifact a downstream service accepts as proof that bouncer
authorized *this specific payment*. It is deliberately narrow.

Threat model — what a mandate that passes :func:`verify_mandate` proves:

- It was issued by a holder of the operator key and has not been altered. The
  signature covers every claim, so an attacker cannot raise ``max_amount`` or
  swap the merchant.
- It has not expired. Mandates carry a short TTL, so a leaked one is useful for
  minutes rather than forever.
- With a :class:`NonceStore`, it has not been used before. Redemption consumes
  the nonce, so capturing a valid mandate in flight does not let an attacker
  spend it a second time.
- With ``expected_merchant`` / ``amount`` supplied, its scope actually covers
  the transaction being attempted. A mandate for $5 at merchant A is not a
  mandate for $500 at merchant B.

What it does NOT prove:

- Nothing about the *bearer*. A mandate is a bearer token: anyone holding it can
  redeem it once, within its TTL, for its exact scope. Treat it like a
  short-lived secret and move it over TLS.
- Nothing about whether the payment actually settled. bouncer authorizes; it
  never touches funds.
"""

from __future__ import annotations

import base64
import secrets
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import CursorResult, Engine, String, delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from .canonical import canonical_bytes, utc_iso
from .db import Base, SessionFactory, create_session_factory, make_engine
from .errors import (
    MandateExpired,
    MandateMalformed,
    MandateReplayed,
    MandateScopeViolation,
    MandateSignatureInvalid,
)
from .keys import Signer, VerifyKey
from .models import Money, PaymentIntent, _to_decimal

__all__ = [
    "DEFAULT_TTL",
    "MandateClaims",
    "NonceStore",
    "issue_mandate",
    "verify_mandate",
]

#: Default mandate lifetime. Long enough to complete a payment call, short
#: enough that a captured mandate is not a standing authorization.
DEFAULT_TTL = timedelta(minutes=5)

_MANDATE_VERSION = 1


class MandateClaims(BaseModel):
    """The signed payload of a mandate."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    v: int = Field(default=_MANDATE_VERSION, ge=1)
    agent_id: str = Field(min_length=1, max_length=128)
    merchant: str = Field(min_length=1, max_length=253)
    max_amount: Money
    # Matches PaymentIntent.currency: an ISO 4217 code (USD) or a token symbol
    # for crypto rails (USDC, PYUSD). Capping this at 3 made every allow on a
    # token-denominated policy raise instead of minting.
    currency: str = Field(min_length=3, max_length=12)
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(min_length=16, max_length=64)
    intent_id: str = Field(min_length=1, max_length=128)
    policy_hash: str = Field(min_length=64, max_length=64)

    _coerce_amount = field_validator("max_amount", mode="before")(_to_decimal)

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def covers(self, *, merchant: str, amount: Decimal) -> bool:
        """Does this mandate authorize a payment of ``amount`` to ``merchant``?"""
        return (
            merchant.strip().lower().rstrip(".") == self.merchant
            and Decimal(0) < amount <= self.max_amount
        )


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, TypeError) as exc:
        raise MandateMalformed(f"segment is not valid base64url: {exc}") from exc


def issue_mandate(
    intent: PaymentIntent,
    key: Signer,
    *,
    policy_hash: str,
    now: datetime,
    ttl: timedelta = DEFAULT_TTL,
    max_amount: Decimal | None = None,
) -> tuple[str, MandateClaims]:
    """Mint a mandate for an authorized intent.

    The mandate is scoped to one merchant and one ceiling amount, expires after
    ``ttl``, and carries a random nonce so it can be redeemed exactly once.

    Returns the encoded token and the claims it carries.
    """
    if now.tzinfo is None:
        raise ValueError("`now` must be timezone-aware")
    if ttl <= timedelta(0):
        raise ValueError("mandate TTL must be positive")

    claims = MandateClaims(
        agent_id=intent.agent_id,
        merchant=intent.merchant,
        max_amount=max_amount if max_amount is not None else intent.amount,
        currency=intent.currency,
        issued_at=now,
        expires_at=now + ttl,
        nonce=secrets.token_urlsafe(24),
        intent_id=intent.intent_id,
        policy_hash=policy_hash,
    )
    payload = canonical_bytes(claims.model_dump(mode="python"))
    signature = key.sign(payload)
    token = f"{_b64url_encode(payload)}.{_b64url_encode(signature)}"
    return token, claims


def verify_mandate(
    token: str,
    verify_key: VerifyKey | Signer,
    *,
    now: datetime,
    nonce_store: NonceStore | None = None,
    expected_merchant: str | None = None,
    amount: Decimal | None = None,
    expected_agent_id: str | None = None,
    consume: bool = True,
) -> MandateClaims:
    """Verify a mandate. Any downstream service can call this.

    Checks run in this order, and every failure raises rather than returning a
    value, so a caller cannot accidentally treat a rejected mandate as valid:

    1. Structure and signature — is this really ours, and unaltered?
    2. Expiry — is it still live?
    3. Scope — does it cover the payment actually being attempted?
    4. Replay — has it been redeemed before?

    Replay is checked last, and only after every other check passes, so an
    invalid mandate cannot burn a nonce that a legitimate one would need.

    Args:
        consume: When True (the default) and a ``nonce_store`` is given, the
            nonce is recorded, making this the one redemption. Pass False to
            inspect a mandate without spending it.

    Raises:
        MandateMalformed, MandateSignatureInvalid, MandateExpired,
        MandateScopeViolation, MandateReplayed
    """
    if now.tzinfo is None:
        raise ValueError("`now` must be timezone-aware")

    key = verify_key.verify_key if isinstance(verify_key, Signer) else verify_key

    parts = token.strip().split(".")
    if len(parts) != 2:
        raise MandateMalformed(
            f"mandate must have exactly two dot-separated segments, got {len(parts)}"
        )
    payload_raw = _b64url_decode(parts[0])
    signature = _b64url_decode(parts[1])

    # Signature is checked against the raw bytes *before* parsing them, so a
    # malformed-but-unsigned payload never reaches the model validator.
    if not key.verify(signature, payload_raw):
        raise MandateSignatureInvalid(
            "mandate signature does not verify under the supplied key; it was "
            "either altered or issued by someone else"
        )

    try:
        claims = MandateClaims.model_validate_json(payload_raw)
    except ValidationError as exc:
        raise MandateMalformed(f"mandate claims failed validation: {exc}") from exc

    if claims.v != _MANDATE_VERSION:
        raise MandateMalformed(f"unsupported mandate version {claims.v}")

    if claims.is_expired(now):
        raise MandateExpired(
            f"mandate expired at {claims.expires_at.isoformat()} "
            f"(now {now.isoformat()})"
        )

    if expected_agent_id is not None and claims.agent_id != expected_agent_id:
        raise MandateScopeViolation(
            f"mandate was issued to agent {claims.agent_id!r}, not "
            f"{expected_agent_id!r}"
        )

    if expected_merchant is not None:
        normalized = expected_merchant.strip().lower().rstrip(".")
        if normalized != claims.merchant:
            raise MandateScopeViolation(
                f"mandate is scoped to merchant {claims.merchant!r}, not "
                f"{normalized!r}"
            )

    if amount is not None:
        if amount <= 0:
            raise MandateScopeViolation(f"amount must be positive, got {amount}")
        if amount > claims.max_amount:
            raise MandateScopeViolation(
                f"attempted amount {amount} exceeds the mandate ceiling of "
                f"{claims.max_amount}"
            )

    if nonce_store is not None and consume:
        if not nonce_store.consume(claims.nonce, expires_at=claims.expires_at):
            raise MandateReplayed(
                f"mandate nonce {claims.nonce[:12]}... has already been redeemed; "
                "each mandate authorizes exactly one payment"
            )

    return claims


class UsedNonce(Base):
    """A mandate nonce that has been redeemed."""

    __tablename__ = "mandate_nonces"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    consumed_at: Mapped[str] = mapped_column(String(32))
    expires_at: Mapped[str] = mapped_column(String(32), index=True)


class NonceStore:
    """Records redeemed mandate nonces so none can be spent twice.

    Threat model: correctness here rests on the atomicity of the insert, not on
    a read-then-write check. Two concurrent redemptions of the same mandate both
    attempt the insert; SQLite's primary key lets exactly one succeed, and the
    loser is reported as a replay. A check-then-insert would let both through.

    Entries can be purged once past their mandate's expiry, since an expired
    mandate is already rejected on the expiry check.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        engine: Engine | None = None,
    ) -> None:
        self._engine = engine if engine is not None else make_engine(db_path)
        self._sessions: SessionFactory = create_session_factory(self._engine)
        self._lock = threading.Lock()

    @property
    def engine(self) -> Engine:
        return self._engine

    def consume(self, nonce: str, *, expires_at: datetime) -> bool:
        """Claim a nonce. Returns False if it was already used."""
        now = datetime.now(timezone.utc)
        try:
            with self._lock, self._sessions.begin() as session:
                session.add(
                    UsedNonce(
                        nonce=nonce,
                        consumed_at=utc_iso(now),
                        expires_at=utc_iso(expires_at),
                    )
                )
        except IntegrityError:
            return False
        return True

    def seen(self, nonce: str) -> bool:
        with self._sessions() as session:
            found = session.execute(
                select(UsedNonce.nonce).where(UsedNonce.nonce == nonce)
            ).scalar_one_or_none()
            return found is not None

    def purge_expired(self, *, now: datetime) -> int:
        """Delete nonces whose mandates have expired. Returns rows removed."""
        with self._lock, self._sessions.begin() as session:
            result = cast(
                CursorResult[Any],
                session.execute(
                    delete(UsedNonce).where(UsedNonce.expires_at <= utc_iso(now))
                ),
            )
            return int(result.rowcount or 0)

    def count(self) -> int:
        with self._sessions() as session:
            total = session.execute(
                select(func.count()).select_from(UsedNonce)
            ).scalar_one()
            return int(total)


def decode_unverified(token: str) -> dict[str, Any]:
    """Decode a mandate's claims WITHOUT checking the signature.

    For logging and debugging only. Never make an authorization decision on the
    result: the payload is attacker-controlled until :func:`verify_mandate` has
    checked the signature.
    """
    parts = token.strip().split(".")
    if len(parts) != 2:
        raise MandateMalformed("mandate must have exactly two segments")
    import json

    try:
        decoded: dict[str, Any] = json.loads(_b64url_decode(parts[0]))
    except ValueError as exc:
        raise MandateMalformed(f"claims are not valid JSON: {exc}") from exc
    return decoded
