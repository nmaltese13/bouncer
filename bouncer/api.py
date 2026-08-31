"""The authorization API.

``POST /authorize`` takes a payment intent and returns a decision plus, when
allowed, a signed mandate.

Threat model: this service authenticates nobody. It is meant to listen on
loopback for a single operator's agents. The ``agent_id`` in a request is an
assertion by the caller, not a verified identity — an agent that can reach this
endpoint can claim to be any agent in the policy. Binding it to a public
interface would let anyone on the network do the same. See README.md.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal, InvalidOperation
from typing import Any

from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .adapters import RequestContext, parse_intent
from .approvals import ApprovalQueue
from .audit import AuditLog
from .config import BouncerConfig
from .enforcement import AuthorizationResult, Enforcer
from .errors import MandateError, RoleMismatch, UnknownApproval, UnparseableIntent
from .keys import OperatorKey, load_signer
from .mandate import NonceStore, verify_mandate
from .models import Outcome, PaymentIntent
from .sources import LocalFileSource

__all__ = ["build_enforcer", "create_app"]

#: HTTP status per outcome. A denial is a 403 so an agent's HTTP client raises
#: on it by default rather than treating a block as success.
_STATUS = {
    Outcome.ALLOW: 200,
    Outcome.DENY: 403,
    Outcome.REQUIRE_APPROVAL: 202,
}

#: Cap on a single request body. An agent should not be able to exhaust memory
#: by posting an enormous "intent".
#:
#: Enforced in two places, because one is not enough. The middleware refuses a
#: declared ``Content-Length`` over the cap before any body is read, which
#: covers every ordinary client and every route including the ones FastAPI
#: parses into a model. The streaming read in ``/authorize`` then caps what is
#: actually buffered, so a request that lies about its length — or sends none
#: at all, as chunked encoding does — cannot force the allocation either.
MAX_BODY_BYTES = 256 * 1024


def _too_large() -> JSONResponse:
    return JSONResponse(
        status_code=413, content={"error": f"body exceeds {MAX_BODY_BYTES} bytes"}
    )


async def _read_capped(request: Request) -> bytes | None:
    """Read the body, or return None if it exceeds the cap.

    Threat model: ``await request.body()`` buffers the whole payload before its
    length can be checked, so a limit applied afterwards rejects the request but
    does not prevent the allocation — a 24 MB body cost 24 MB of memory before
    being refused. Reading incrementally and stopping at the cap is what makes
    the limit a protection rather than an after-the-fact complaint.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > MAX_BODY_BYTES:
                return None
        except ValueError:
            return None

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


class RawTraffic(BaseModel):
    """A description of intercepted traffic, for adapter-based parsing."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=128)
    method: str = "POST"
    url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    status_code: int | None = None


class VerifyMandateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mandate: str
    merchant: str | None = None
    amount: str | None = None
    agent_id: str | None = None
    consume: bool = True


class ResolveRequest(BaseModel):
    """An approver acting on a queued item."""

    model_config = ConfigDict(extra="forbid")

    role: str = Field(min_length=1, max_length=64)
    approve: bool
    note: str | None = Field(default=None, max_length=512)


def build_enforcer(config: BouncerConfig) -> Enforcer:
    """Wire up an enforcer from on-disk state."""
    config.ensure_home()
    assert config.key_path is not None and config.db_path is not None
    assert config.policy_path is not None
    key = load_signer(
        config.key_path,
        command=config.signer_argv,
        public_key_path=config.public_key_path,
        create=True,
    )
    audit = AuditLog(config.db_path, key)
    # All three share one engine, so they share one SQLite file and one write
    # lock — the CLI and the server stay consistent with each other.
    return Enforcer(
        source=LocalFileSource(config.policy_path),
        audit=audit,
        key=key,
        nonces=NonceStore(config.db_path, engine=audit.engine),
        approvals=ApprovalQueue(config.db_path, engine=audit.engine),
        approval_timeout=config.approval_timeout,
        webhook_url=config.webhook_url,
    )


def _respond(result: AuthorizationResult) -> JSONResponse:
    return JSONResponse(
        status_code=_STATUS[result.decision.outcome], content=result.to_dict()
    )


def create_app(config: BouncerConfig | None = None, *, enforcer: Enforcer | None = None) -> FastAPI:
    """Build the FastAPI application."""
    resolved = config if config is not None else BouncerConfig.from_env()
    engine = enforcer if enforcer is not None else build_enforcer(resolved)

    app = FastAPI(
        title="bouncer",
        version=__version__,
        description=(
            "A policy enforcement point for agent spending. Authorizes payment "
            "intents against a declarative policy and returns signed mandates. "
            "Never custodies funds. Authenticates nobody — bind to loopback."
        ),
    )
    app.state.enforcer = engine
    app.state.config = resolved

    @app.middleware("http")
    async def cap_request_size(request: Request, call_next: Any) -> Response:
        """Refuse an over-large body before any of it is read.

        Routes that FastAPI parses into a model never see the raw body, so they
        cannot cap it themselves; this is the only place that protects them.
        """
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                oversized = int(declared) > MAX_BODY_BYTES
            except ValueError:
                oversized = True
            if oversized:
                return _too_large()
        response: Response = await call_next(request)
        return response

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        loaded = engine.source.load()
        return {
            "status": "ok",
            "policy_ok": loaded.ok,
            "policy_origin": loaded.origin,
            "policy_hash": loaded.policy_hash,
            "policy_error": loaded.error,
            "key_id": engine.key.key_id,
        }

    @app.get("/policy")
    def current_policy() -> JSONResponse:
        loaded = engine.source.load()
        if loaded.policy is None:
            return JSONResponse(
                status_code=503,
                content={"ok": False, "error": loaded.error, "origin": loaded.origin},
            )
        return JSONResponse(
            content={
                "ok": True,
                "origin": loaded.origin,
                "policy_hash": loaded.policy_hash,
                "policy": loaded.policy.model_dump(mode="json"),
            }
        )

    @app.post("/authorize")
    async def authorize(
        request: Request,
        wait: bool = Query(False, description="block until a human resolves it"),
        timeout: float | None = Query(None, gt=0, le=3600),
    ) -> Response:
        """Authorize a payment intent supplied as a JSON body."""
        body = await _read_capped(request)
        if body is None:
            return _too_large()

        ctx = RequestContext(
            method="POST",
            url=request.headers.get("x-bouncer-target-url", ""),
            body=body,
            agent_id=request.headers.get("x-bouncer-agent", "unknown"),
            headers=dict(request.headers),
        )
        return await _authorize_ctx(ctx, wait=wait, timeout=timeout)

    @app.post("/authorize/raw")
    async def authorize_raw(
        traffic: RawTraffic,
        wait: bool = Query(False),
        timeout: float | None = Query(None, gt=0, le=3600),
    ) -> Response:
        """Authorize traffic described explicitly, for rails like Stripe."""
        ctx = RequestContext(
            method=traffic.method,
            url=traffic.url,
            body=traffic.body.encode("utf-8"),
            agent_id=traffic.agent_id,
            status_code=traffic.status_code,
            headers=traffic.headers,
        )
        return await _authorize_ctx(ctx, wait=wait, timeout=timeout)

    async def _authorize_ctx(
        ctx: RequestContext, *, wait: bool, timeout: float | None
    ) -> Response:
        try:
            intent = parse_intent(ctx)
        except UnparseableIntent as exc:
            # Denied and logged — never passed through unexamined.
            placeholder = PaymentIntent(
                agent_id=ctx.agent_id or "unknown",
                merchant=ctx.host or "unknown",
                amount=Decimal(0),
                currency="XXX",
                rail="unparsed",
                description=f"{ctx.method} {ctx.url}"[:512] or None,
            )
            return _respond(await asyncio.to_thread(engine.deny_unparseable, exc, placeholder))

        if wait:
            return _respond(await engine.authorize_blocking(intent, timeout=timeout))
        # Off the event loop: authorize() takes the decision lock and commits
        # under synchronous=FULL, so it blocks for an fsync — and for up to the
        # 30s busy_timeout if another process holds the write lock. Run inline
        # and one authorization would stall every other request, /healthz
        # included. The sibling endpoints are plain `def`, which FastAPI already
        # runs in its threadpool; only the async ones need this.
        return _respond(await asyncio.to_thread(engine.authorize, intent))

    @app.post("/mandates/verify")
    def verify(request: VerifyMandateRequest) -> JSONResponse:
        """Verify a mandate. Any downstream service can call this."""
        amount: Decimal | None = None
        if request.amount is not None:
            try:
                amount = Decimal(request.amount)
            except InvalidOperation:
                return JSONResponse(
                    status_code=400, content={"valid": False, "error": "invalid amount"}
                )
        try:
            claims = verify_mandate(
                request.mandate,
                engine.key.verify_key,
                # The enforcer's clock, not the wall clock: the service must
                # have exactly one notion of "now", or a mandate can be minted
                # and judged against two different times.
                now=engine.now(),
                nonce_store=engine.nonces,
                expected_merchant=request.merchant,
                expected_agent_id=request.agent_id,
                amount=amount,
                consume=request.consume,
            )
        except MandateError as exc:
            return JSONResponse(
                status_code=403,
                content={
                    "valid": False,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            )
        return JSONResponse(
            content={"valid": True, "claims": claims.model_dump(mode="json")}
        )

    @app.get("/pending")
    def pending(role: str | None = None) -> dict[str, Any]:
        """List approvals awaiting a human."""
        items = engine.approvals.list(role=role)
        return {"count": len(items), "items": [item.to_dict() for item in items]}

    @app.post("/approvals/{item_id}/resolve")
    async def resolve_approval(item_id: str, request: ResolveRequest) -> Response:
        """Approve or deny a queued item.

        Threat model: **this endpoint authenticates nobody**, and it is the most
        consequential one in the service for that reason. ``role`` is an
        assertion by the caller exactly as ``--role`` is on the CLI, but where
        the CLI at least requires shell access on the host, this requires only
        reachability. Anyone who can open a socket to this port can approve any
        queued payment.

        That makes the loopback binding load-bearing rather than advisory. Do
        not expose this service on a routable interface.

        The grant is still re-evaluated against current policy, so an approval
        cannot authorize something the rules now forbid — see
        ``Enforcer._finalize_locked``.
        """
        try:
            result = await asyncio.to_thread(
                engine.resolve,
                item_id,
                role=request.role,
                approve=request.approve,
                note=request.note,
            )
        except UnknownApproval as exc:
            return JSONResponse(status_code=404, content={"error": str(exc)})
        except RoleMismatch as exc:
            # Wrong role, or already resolved. Both are refusals to act, not
            # server faults, and both must read as such to a caller.
            return JSONResponse(status_code=403, content={"error": str(exc)})
        return _respond(result)

    @app.get("/audit/verify")
    def audit_verify(expect_head: str | None = None) -> JSONResponse:
        result = engine.audit.verify(expect_head=expect_head)
        return JSONResponse(
            status_code=200 if result.ok else 409,
            content={
                "ok": result.ok,
                "entries_checked": result.entries_checked,
                "head_hash": result.head_hash,
                "broken_seq": result.broken_seq,
                "problem": result.problem,
            },
        )

    return app
