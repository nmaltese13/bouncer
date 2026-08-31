"""The tamper-evident audit log.

Every decision bouncer makes is appended here as a hash-chained, signed row.

Threat model — what a clean ``bouncer verify`` proves:

- No row has been *altered* since it was written. Changing any field changes the
  row's hash, which breaks its link to the next row.
- No row has been *removed* from the middle, and no row has been *inserted*.
  Sequence numbers are contiguous and each row commits to its predecessor.
- Each row was signed by a holder of the operator key.

What it does NOT prove:

- **Truncation of the tail is not detectable from the log alone.** An attacker
  who deletes the most recent N rows leaves a chain that is internally perfect.
  Detecting that requires an external record of the head hash: keep the value
  ``bouncer verify`` prints, and pass it back as ``--expect-head`` to close the
  gap.
- Nothing about whether a decision was *correct*, only that it is the decision
  that was recorded.
- Nothing against an operator whose key was compromised before the write. Such
  an attacker can author a fully consistent history.
"""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import IO, Any

from sqlalchemy import Engine, Index, Integer, String, Text, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from .canonical import canonical_json, sha256_hex, utc_iso
from .db import Base, SessionFactory, create_session_factory, make_engine
from .errors import AuditError
from .keys import Signer, VerifyKey
from .models import Decision, Outcome, PaymentIntent, SpendRecord

__all__ = [
    "AuditEntry",
    "AuditLog",
    "ChainVerification",
    "GENESIS_HASH",
    "export_jsonl",
]

#: The predecessor hash of the first row.
GENESIS_HASH = "0" * 64


class AuditEntry(Base):
    """One immutable row of the decision log."""

    __tablename__ = "audit_entries"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(32), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    merchant: Mapped[str] = mapped_column(String(253))
    amount: Mapped[str] = mapped_column(String(32))
    currency: Mapped[str] = mapped_column(String(3))
    outcome: Mapped[str] = mapped_column(String(24), index=True)
    reason_code: Mapped[str] = mapped_column(String(48))
    policy_hash: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True)
    signature: Mapped[str] = mapped_column(String(128))
    key_id: Mapped[str] = mapped_column(String(32))

    __table_args__ = (Index("ix_audit_agent_outcome_ts", "agent_id", "outcome", "ts"),)

    def to_dict(self) -> dict[str, Any]:
        """The row as a plain dict, with the payload re-expanded."""
        return {
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "agent_id": self.agent_id,
            "merchant": self.merchant,
            "amount": self.amount,
            "currency": self.currency,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "policy_hash": self.policy_hash,
            "payload": json.loads(self.payload),
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
            "key_id": self.key_id,
        }


#: Every column that is covered by the row hash — that is, everything stored
#: except the hash and signature themselves.
#:
#: Threat model: this list must stay exhaustive. The columns beside `payload`
#: are denormalized copies used for querying and, crucially, for
#: `spend_history`, which drives rolling-window enforcement. If `amount` or
#: `outcome` were left outside the hash, an attacker could edit those columns to
#: reset an agent's spent-to-date while `verify` still reported a clean chain.
#: Hashing the whole row closes that gap. Adding a column means adding it here.
_HASHED_FIELDS = (
    "seq",
    "ts",
    "kind",
    "agent_id",
    "merchant",
    "amount",
    "currency",
    "outcome",
    "reason_code",
    "policy_hash",
    "prev_hash",
    "payload",
    "key_id",
)


def _hash_material(row: Mapping[str, Any]) -> dict[str, Any]:
    """The exact structure that gets hashed. Changing this breaks every chain.

    The payload is hashed as the canonical *string* that is stored, so
    verification never depends on re-serializing it identically.
    """
    try:
        return {name: row[name] for name in _HASHED_FIELDS}
    except KeyError as exc:
        raise AuditError(f"audit row is missing hashed field {exc}") from exc


@dataclass(frozen=True)
class ChainVerification:
    """The result of walking the whole chain."""

    ok: bool
    entries_checked: int
    head_hash: str
    broken_seq: int | None = None
    problem: str | None = None

    def describe(self) -> str:
        if self.ok:
            return (
                f"chain intact: {self.entries_checked} entries verified, "
                f"head {self.head_hash}"
            )
        return (
            f"CHAIN BROKEN at entry seq={self.broken_seq}: {self.problem} "
            f"({self.entries_checked} entries verified before the break)"
        )


class AuditLog:
    """Append-only, hash-chained, signed decision log backed by SQLite."""

    def __init__(
        self,
        db_path: str | Path,
        key: Signer,
        *,
        engine: Engine | None = None,
    ) -> None:
        self._key = key
        self._engine = engine if engine is not None else make_engine(db_path)
        self._sessions: SessionFactory = create_session_factory(self._engine)
        # Guards the read-tail/append pair within this process; BEGIN IMMEDIATE
        # guards it across processes.
        self._lock = threading.Lock()

    @property
    def engine(self) -> Engine:
        return self._engine

    @property
    def sessions(self) -> SessionFactory:
        return self._sessions

    @property
    def key_id(self) -> str:
        return self._key.key_id

    # -- writing ----------------------------------------------------------

    def append(
        self,
        intent: PaymentIntent,
        decision: Decision,
        *,
        kind: str = "decision",
        note: str | None = None,
    ) -> AuditEntry:
        """Append one decision. Returns the persisted row.

        The row is hashed over its sequence number, timestamp, predecessor hash
        and canonical payload, then signed. Both values are stored, so a later
        verifier can recompute the hash and check the signature without trusting
        anything already in the row.
        """
        payload = canonical_json(
            {
                "kind": kind,
                "note": note,
                "intent": intent.model_dump(mode="python"),
                "decision": decision.model_dump(mode="python"),
            }
        )
        timestamp = utc_iso(decision.evaluated_at)

        with self._lock, self._sessions.begin() as session:
            tail = session.execute(
                select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)
            ).scalar_one_or_none()
            prev_hash = tail.entry_hash if tail is not None else GENESIS_HASH
            seq = (tail.seq + 1) if tail is not None else 1

            columns: dict[str, Any] = {
                "seq": seq,
                "ts": timestamp,
                "kind": kind,
                "agent_id": intent.agent_id,
                "merchant": intent.merchant,
                "amount": str(intent.amount),
                "currency": intent.currency,
                "outcome": decision.outcome.value,
                "reason_code": decision.reason_code.value,
                "policy_hash": decision.policy_hash,
                "payload": payload,
                "prev_hash": prev_hash,
                "key_id": self._key.key_id,
            }
            entry_hash = sha256_hex(_hash_material(columns))
            signature = base64.b64encode(self._key.sign(entry_hash.encode())).decode()

            entry = AuditEntry(**columns, entry_hash=entry_hash, signature=signature)
            session.add(entry)
        return entry

    # -- reading ----------------------------------------------------------

    def head(self) -> str:
        """Hash of the most recent entry, or the genesis hash if empty."""
        with self._sessions() as session:
            tail = session.execute(
                select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)
            ).scalar_one_or_none()
            return tail.entry_hash if tail is not None else GENESIS_HASH

    def count(self) -> int:
        with self._sessions() as session:
            total = session.execute(
                select(func.count()).select_from(AuditEntry)
            ).scalar_one()
            return int(total)

    def entries(self, *, limit: int | None = None) -> list[AuditEntry]:
        with self._sessions() as session:
            statement = select(AuditEntry).order_by(AuditEntry.seq)
            if limit is not None:
                statement = statement.limit(limit)
            return list(session.execute(statement).scalars().all())

    def iter_entries(self, session: Session) -> Iterator[AuditEntry]:
        """Stream entries in sequence order, for export and verification."""
        yield from session.execute(
            select(AuditEntry).order_by(AuditEntry.seq)
        ).scalars()

    def spend_history(
        self, agent_id: str, *, since: datetime, currency: str | None = None
    ) -> list[SpendRecord]:
        """Committed spend for one agent, for rolling-window evaluation.

        Only ``ALLOW`` outcomes count. A denial costs nothing, and a pending
        approval has not been committed yet — counting either would let a
        rejected request consume an agent's budget.
        """
        with self._sessions() as session:
            statement = (
                select(AuditEntry)
                .where(
                    AuditEntry.agent_id == agent_id,
                    AuditEntry.outcome == Outcome.ALLOW.value,
                    AuditEntry.ts > utc_iso(since),
                )
                .order_by(AuditEntry.seq)
            )
            if currency is not None:
                statement = statement.where(AuditEntry.currency == currency)
            rows = session.execute(statement).scalars().all()

        return [
            SpendRecord(
                agent_id=row.agent_id,
                amount=Decimal(row.amount),
                currency=row.currency,
                timestamp=datetime.strptime(row.ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                    tzinfo=timezone.utc
                ),
            )
            for row in rows
        ]

    # -- integrity --------------------------------------------------------

    def verify(
        self, *, verify_key: VerifyKey | None = None, expect_head: str | None = None
    ) -> ChainVerification:
        """Walk the entire chain and report the first broken link.

        Args:
            verify_key: Public key to check signatures against. Defaults to the
                operator key this log was opened with.
            expect_head: A previously-recorded head hash. Supplying it closes the
                tail-truncation gap described in this module's docstring.
        """
        key = verify_key if verify_key is not None else self._key.verify_key
        checked = 0
        prev_hash = GENESIS_HASH
        expected_seq = 1

        with self._sessions() as session:
            for entry in self.iter_entries(session):
                if entry.seq != expected_seq:
                    return ChainVerification(
                        ok=False,
                        entries_checked=checked,
                        head_hash=prev_hash,
                        broken_seq=entry.seq,
                        problem=(
                            f"sequence gap: expected seq={expected_seq}, found "
                            f"seq={entry.seq}; {entry.seq - expected_seq} "
                            "entries were removed"
                        ),
                    )

                if entry.prev_hash != prev_hash:
                    return ChainVerification(
                        ok=False,
                        entries_checked=checked,
                        head_hash=prev_hash,
                        broken_seq=entry.seq,
                        problem=(
                            f"broken link: entry claims predecessor "
                            f"{entry.prev_hash[:16]}... but the previous entry "
                            f"hashes to {prev_hash[:16]}..."
                        ),
                    )

                recomputed = sha256_hex(
                    _hash_material({name: getattr(entry, name) for name in _HASHED_FIELDS})
                )
                if recomputed != entry.entry_hash:
                    return ChainVerification(
                        ok=False,
                        entries_checked=checked,
                        head_hash=prev_hash,
                        broken_seq=entry.seq,
                        problem=(
                            "content altered: the row hashes to "
                            f"{recomputed[:16]}... but stores "
                            f"{entry.entry_hash[:16]}..."
                        ),
                    )

                try:
                    signature = base64.b64decode(entry.signature, validate=True)
                except (ValueError, TypeError):
                    return ChainVerification(
                        ok=False,
                        entries_checked=checked,
                        head_hash=prev_hash,
                        broken_seq=entry.seq,
                        problem="signature is not valid base64",
                    )

                if not key.verify(signature, entry.entry_hash.encode()):
                    return ChainVerification(
                        ok=False,
                        entries_checked=checked,
                        head_hash=prev_hash,
                        broken_seq=entry.seq,
                        problem=(
                            "signature does not verify under key "
                            f"{key.key_id} (row was signed by {entry.key_id})"
                        ),
                    )

                prev_hash = entry.entry_hash
                expected_seq += 1
                checked += 1

        if expect_head is not None and expect_head != prev_hash:
            return ChainVerification(
                ok=False,
                entries_checked=checked,
                head_hash=prev_hash,
                broken_seq=checked,
                problem=(
                    f"head mismatch: expected the chain to end at "
                    f"{expect_head[:16]}... but it ends at {prev_hash[:16]}...; "
                    "entries were removed from the end of the log"
                ),
            )

        return ChainVerification(ok=True, entries_checked=checked, head_hash=prev_hash)


def export_jsonl(log: AuditLog, destination: IO[str] | str | Path) -> int:
    """Export the audit log as line-delimited JSON. Returns the row count.

    This is a first-class library function, not a script: SIEM ingestion is a
    supported use of bouncer, and the export must be callable from an embedding
    application without shelling out.

    Each line is one complete entry including its hash, predecessor hash and
    signature, so an exported file can be re-verified independently of SQLite.
    """
    if isinstance(destination, (str, Path)):
        path = Path(destination).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            return _write_jsonl(log, handle)
    return _write_jsonl(log, destination)


def _write_jsonl(log: AuditLog, handle: IO[str]) -> int:
    written = 0
    with log.sessions() as session:
        for entry in log.iter_entries(session):
            handle.write(json.dumps(entry.to_dict(), sort_keys=True, default=str))
            handle.write("\n")
            written += 1
    return written


def verify_exported(lines: Sequence[str], verify_key: VerifyKey) -> ChainVerification:
    """Re-verify a JSONL export without touching the database.

    Lets an auditor check a log shipped to them as a file, using only the
    operator's public key.
    """
    prev_hash = GENESIS_HASH
    expected_seq = 1
    checked = 0

    for raw in lines:
        text = raw.strip()
        if not text:
            continue
        try:
            row = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AuditError(f"export line {checked + 1} is not valid JSON: {exc}") from exc

        seq = int(row["seq"])
        if seq != expected_seq:
            return ChainVerification(
                ok=False, entries_checked=checked, head_hash=prev_hash,
                broken_seq=seq, problem=f"sequence gap: expected {expected_seq}",
            )
        if row["prev_hash"] != prev_hash:
            return ChainVerification(
                ok=False, entries_checked=checked, head_hash=prev_hash,
                broken_seq=seq, problem="broken link to previous entry",
            )
        # Re-serialize the payload back to the canonical string that was hashed.
        material = dict(row)
        material["payload"] = json.dumps(
            row["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        recomputed = sha256_hex(_hash_material(material))
        if recomputed != row["entry_hash"]:
            return ChainVerification(
                ok=False, entries_checked=checked, head_hash=prev_hash,
                broken_seq=seq, problem="content altered",
            )
        if not verify_key.verify(base64.b64decode(row["signature"]), row["entry_hash"].encode()):
            return ChainVerification(
                ok=False, entries_checked=checked, head_hash=prev_hash,
                broken_seq=seq, problem="signature does not verify",
            )
        prev_hash = row["entry_hash"]
        expected_seq += 1
        checked += 1

    return ChainVerification(ok=True, entries_checked=checked, head_hash=prev_hash)
