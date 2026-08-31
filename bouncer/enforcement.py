"""The enforcement core: load policy, decide, log, mint.

Both entry points — the REST API and the forward proxy — go through this class,
so there is exactly one path from "a payment was attempted" to "a decision was
recorded". A second path would be a second place for the rules to be wrong.

Threat model: every branch here ends in an audit entry, including the failure
branches. Traffic that cannot be parsed, policy that cannot be loaded, and
approvals that time out are all *logged denials*, never silent pass-throughs.
"""

from __future__ import annotations

import asyncio
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from .approvals import ApprovalQueue, ApprovalStatus, PendingView, to_webhook_payload
from .audit import AuditLog
from .engine import evaluate, evaluate_tunnel
from .errors import UnparseableIntent
from .keys import Signer
from .mandate import DEFAULT_TTL, NonceStore, issue_mandate
from .models import Decision, Outcome, PaymentIntent, ReasonCode
from .sources import LoadedPolicy, PolicySource

__all__ = ["AuthorizationResult", "Enforcer"]

#: Poll interval while a request waits on a human.
_APPROVAL_POLL_SECONDS = 0.25


@dataclass(frozen=True)
class AuthorizationResult:
    """The outcome of an authorization attempt."""

    decision: Decision
    intent: PaymentIntent
    mandate: str | None = None
    pending_id: str | None = None
    audit_seq: int | None = None

    @property
    def allowed(self) -> bool:
        return self.decision.outcome is Outcome.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.model_dump(mode="json"),
            "intent": self.intent.model_dump(mode="json"),
            "mandate": self.mandate,
            "pending_id": self.pending_id,
            "audit_seq": self.audit_seq,
        }


class Enforcer:
    """Ties policy, audit, mandates and approvals into one decision path."""

    def __init__(
        self,
        *,
        source: PolicySource,
        audit: AuditLog,
        key: Signer,
        nonces: NonceStore,
        approvals: ApprovalQueue,
        mandate_ttl: timedelta = DEFAULT_TTL,
        approval_timeout: float = 300.0,
        webhook_url: str | None = None,
        clock: Any = None,
    ) -> None:
        self.source = source
        self.audit = audit
        self.key = key
        self.nonces = nonces
        self.approvals = approvals
        self.mandate_ttl = mandate_ttl
        self.approval_timeout = approval_timeout
        self.webhook_url = webhook_url
        self._clock = clock if clock is not None else (lambda: datetime.now(timezone.utc))
        # Serializes the read-history / decide / record sequence. Lock ordering
        # across the codebase is always: decision -> approvals -> audit.
        self._decision_lock = threading.RLock()

    def now(self) -> datetime:
        moment: datetime = self._clock()
        if moment.tzinfo is None:
            raise ValueError("clock must return timezone-aware datetimes")
        return moment

    # -- the main path ----------------------------------------------------

    def _lookback_for(self, loaded: LoadedPolicy, agent_id: str) -> timedelta:
        """How far back spend history must reach for this agent.

        Threat model: this is derived from the policy's own longest rolling
        window, never from a fixed constant. A hardcoded horizon shorter than a
        declared window would silently drop older spend from the total, and an
        agent that had already exhausted its budget would be waved through — a
        fail-*open*, which is the one failure mode bouncer must not have.
        """
        if loaded.policy is None:
            return timedelta(0)
        match = loaded.policy.rules_for(agent_id)
        if match is None:
            return timedelta(0)
        longest = match[1].longest_window
        return longest if longest is not None else timedelta(0)

    def authorize(
        self, intent: PaymentIntent, *, record: bool = True
    ) -> AuthorizationResult:
        """Evaluate one intent, log the decision, and mint a mandate if allowed.

        Approval-requiring decisions are parked in the queue and returned
        immediately; use :meth:`authorize_blocking` to wait for a human.

        Args:
            record: When False, nothing is written and no mandate is minted —
                the decision is returned for inspection only. See below.

        Threat model: reading spend history, deciding, and recording the result
        happen under one lock. Without it, two concurrent requests would each
        read the same "already spent" total and each be judged against a budget
        the other was about to consume — two $60 charges would both pass a $100
        ceiling. The lock makes the check and the commit one step.
        """
        with self._decision_lock:
            moment = self.now()
            loaded = self.source.load()

            history = self.audit.spend_history(
                intent.agent_id, since=moment - self._lookback_for(loaded, intent.agent_id)
            )
            decision = evaluate(intent, loaded, history, now=moment)

            mandate: str | None = None
            pending_id: str | None = None

            if not record:
                # A mandate is spending authority. Minting one without writing
                # the matching audit row would hand out authority that leaves no
                # trace and does not count against any ceiling, so a dry run
                # returns the verdict and nothing else.
                return AuthorizationResult(decision=decision, intent=intent)

            # The audit row goes first, before anything that can raise. A
            # decision that was reached but not recorded is the one outcome this
            # module promises cannot happen, and minting or enqueueing can fail
            # on malformed input. Recording first means a later failure leaves a
            # logged decision with no mandate — an over-count of spend, which is
            # the conservative direction — rather than silent, unlogged spending
            # authority.
            seq = self.audit.append(intent, decision).seq

            if decision.outcome is Outcome.ALLOW:
                mandate, _ = issue_mandate(
                    intent,
                    self.key,
                    policy_hash=decision.policy_hash,
                    now=moment,
                    ttl=self.mandate_ttl,
                )
            elif decision.outcome is Outcome.REQUIRE_APPROVAL:
                item = self.approvals.enqueue(intent, decision)
                pending_id = item.id

        # Fired outside the lock: a webhook must never hold up a decision.
        if pending_id is not None:
            self._fire_webhook(self.approvals.get(pending_id))

        return AuthorizationResult(
            decision=decision,
            intent=intent,
            mandate=mandate,
            pending_id=pending_id,
            audit_seq=seq,
        )

    def deny_unparseable(
        self, error: UnparseableIntent, intent: PaymentIntent
    ) -> AuthorizationResult:
        """Record a deny for traffic no adapter could read.

        Threat model: an intent bouncer cannot parse is never forwarded. It is
        denied, logged with the parse failure, and surfaced to the operator.
        """
        moment = self.now()
        loaded = self.source.load()
        decision = Decision(
            outcome=Outcome.DENY,
            reason_code=ReasonCode.UNPARSEABLE_INTENT,
            reason=str(error),
            rule="adapters",
            policy_hash=loaded.policy_hash,
            evaluated_at=moment,
        )
        seq = self.audit.append(intent, decision, kind="unparseable").seq
        return AuthorizationResult(decision=decision, intent=intent, audit_seq=seq)

    def authorize_tunnel(self, host: str, agent_id: str) -> AuthorizationResult:
        """Decide on an opaque CONNECT tunnel. See :func:`evaluate_tunnel`."""
        moment = self.now()
        loaded = self.source.load()
        decision = evaluate_tunnel(host, loaded, agent_id=agent_id, now=moment)
        # A tunnel has no amount; record it as zero so the row is well-formed
        # without implying a spend. Tunnels never count toward rolling windows.
        placeholder = PaymentIntent(
            agent_id=agent_id,
            merchant=host,
            amount=Decimal(0),
            currency="XXX",
            rail="connect",
            description=f"CONNECT {host}",
        )
        seq = self.audit.append(placeholder, decision, kind="tunnel").seq
        return AuthorizationResult(decision=decision, intent=placeholder, audit_seq=seq)

    # -- human in the loop ------------------------------------------------

    def resolve(
        self, item_id: str, *, role: str, approve: bool, note: str | None = None
    ) -> AuthorizationResult:
        """Resolve a queued approval and record the final decision.

        The queued item's original decision is superseded by a new one recorded
        here, so the audit log shows both the request for approval and its
        answer. Only an approval mints a mandate.

        Held under the same lock as :meth:`authorize`, because granting an
        approval commits spend and must not interleave with a concurrent
        evaluation reading the pre-approval total.
        """
        with self._decision_lock:
            moment = self.now()
            item = self.approvals.resolve(
                item_id, role=role, approve=approve, note=note, now=moment
            )
            return self._finalize(item, approve=approve, moment=moment, note=note)

    def _finalize(
        self,
        item: PendingView,
        *,
        approve: bool,
        moment: datetime,
        note: str | None,
        timed_out: bool = False,
    ) -> AuthorizationResult:
        """Record the final answer to a queued approval.

        Takes the decision lock because an approval commits spend. The lock is
        reentrant, so calling this from :meth:`resolve` (which already holds it)
        is safe, while the long-polling path in :meth:`authorize_blocking`
        acquires it here.
        """
        with self._decision_lock:
            return self._finalize_locked(
                item, approve=approve, moment=moment, note=note, timed_out=timed_out
            )

    def _finalize_locked(
        self,
        item: PendingView,
        *,
        approve: bool,
        moment: datetime,
        note: str | None,
        timed_out: bool = False,
    ) -> AuthorizationResult:
        # Threat model: a grant is re-evaluated against the policy in force
        # *now*, not the one that queued it. Policy is otherwise checked only
        # when an item enters the queue, so anything that changed while it
        # waited — budget consumed by other spending, a merchant added to the
        # denylist, the policy file becoming unreadable — would be invisible at
        # the moment authority is actually handed out. That is a fail-open, and
        # it contradicts the rule that approvers exercise judgment *inside*
        # policy rather than over it.
        #
        # REQUIRE_APPROVAL is the expected verdict here: it is why the item was
        # queued, and the human has now supplied the judgment it was waiting
        # for. A DENY is a hard rule, and no approval overrides one.
        loaded = self.source.load()
        superseded: Decision | None = None
        if approve and not timed_out:
            history = self.audit.spend_history(
                item.intent.agent_id,
                since=moment - self._lookback_for(loaded, item.intent.agent_id),
            )
            current = evaluate(item.intent, loaded, history, now=moment)
            if current.outcome is Outcome.DENY:
                superseded = current
                approve = False

        if timed_out:
            reason_code = ReasonCode.APPROVAL_TIMEOUT
            reason = (
                f"no {item.required_role!r} approval arrived before the timeout; "
                "bouncer denies on timeout"
            )
        elif superseded is not None:
            reason_code = superseded.reason_code
            reason = (
                f"approval by role {item.resolved_by_role!r} refused: policy no "
                f"longer permits this transaction ({superseded.reason})"
            )
        elif approve:
            reason_code = ReasonCode.APPROVAL_GRANTED
            reason = f"approved by role {item.resolved_by_role!r}"
        else:
            reason_code = ReasonCode.APPROVAL_DENIED
            reason = f"denied by role {item.resolved_by_role!r}"
        if note:
            reason = f"{reason}: {note}"

        decision = Decision(
            outcome=Outcome.ALLOW if approve else Outcome.DENY,
            reason_code=reason_code,
            reason=reason,
            rule=superseded.rule if superseded is not None else item.decision.rule,
            approver_role=item.required_role,
            # The policy in force at the moment authority was granted or
            # refused, not the one that queued the item. Recording the stale
            # hash would attribute the outcome to a policy that may no longer
            # exist, which is exactly what the audit log exists to prevent.
            policy_hash=loaded.policy_hash,
            evaluated_at=moment,
        )

        # Recorded before minting, for the same reason as in authorize().
        seq = self.audit.append(
            item.intent, decision, kind="approval", note=f"approval:{item.id}"
        ).seq

        mandate: str | None = None
        if approve:
            mandate, _ = issue_mandate(
                item.intent,
                self.key,
                policy_hash=decision.policy_hash,
                now=moment,
                ttl=self.mandate_ttl,
            )
        return AuthorizationResult(
            decision=decision,
            intent=item.intent,
            mandate=mandate,
            pending_id=item.id,
            audit_seq=seq,
        )

    async def authorize_blocking(
        self, intent: PaymentIntent, *, timeout: float | None = None
    ) -> AuthorizationResult:
        """Authorize, waiting for a human if the policy requires one.

        Threat model: the wait **times out into a deny**. A request that nobody
        answered is not an approved request, and an operator who is asleep must
        not become an implicit rubber stamp.

        Every synchronous step is pushed to a worker thread. Each one takes the
        decision lock and commits to SQLite, so running them inline would block
        the event loop — and a request parked here waiting on a human would take
        the whole server down with it for the duration. No lock is ever held
        across an ``await``, so moving these off-thread cannot deadlock and does
        not weaken the serialization the lock provides.
        """
        result = await asyncio.to_thread(self.authorize, intent)
        if result.decision.outcome is not Outcome.REQUIRE_APPROVAL:
            return result

        assert result.pending_id is not None
        limit = timeout if timeout is not None else self.approval_timeout
        deadline = asyncio.get_running_loop().time() + limit

        while asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(_APPROVAL_POLL_SECONDS)
            item = await asyncio.to_thread(self.approvals.get, result.pending_id)
            if item.status is ApprovalStatus.APPROVED:
                return await asyncio.to_thread(
                    self._finalize, item, approve=True, moment=self.now(), note=item.note
                )
            if item.status in (ApprovalStatus.DENIED, ApprovalStatus.TIMED_OUT):
                return await asyncio.to_thread(
                    self._finalize, item, approve=False, moment=self.now(), note=item.note
                )

        expired = await asyncio.to_thread(
            self.approvals.expire, result.pending_id, now=self.now()
        )
        if expired is None:
            # Resolved in the gap between the last poll and the timeout.
            item = await asyncio.to_thread(self.approvals.get, result.pending_id)
            approved = item.status is ApprovalStatus.APPROVED
            return await asyncio.to_thread(
                self._finalize, item, approve=approved, moment=self.now(), note=item.note
            )

        return await asyncio.to_thread(
            self._finalize, expired, approve=False, moment=self.now(), note=None, timed_out=True
        )

    # -- notifications ----------------------------------------------------

    def _fire_webhook(self, item: PendingView) -> None:
        """POST a notification about a new pending item, best-effort.

        Runs on a daemon thread and swallows every error: a Slack outage must
        not change an authorization outcome, and must never block the decision
        path. The queue is the source of truth; the webhook is a convenience.
        """
        if not self.webhook_url:
            return

        url = self.webhook_url
        body = to_webhook_payload(item).encode("utf-8")

        def send() -> None:
            request = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "bouncer"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=5):
                    pass
            except (urllib.error.URLError, OSError, ValueError):
                pass

        threading.Thread(target=send, daemon=True, name="bouncer-webhook").start()
