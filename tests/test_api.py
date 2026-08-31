"""M4 — the authorization API."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterator

import pytest
from fastapi.testclient import TestClient

from bouncer.api import create_app
from bouncer.approvals import ApprovalQueue
from bouncer.audit import AuditLog
from bouncer.enforcement import Enforcer
from bouncer.keys import OperatorKey
from bouncer.mandate import NonceStore
from bouncer.policy import Policy
from bouncer.sources import StaticSource

from .conftest import NOW

API_POLICY = """
version: 1
currency: USD
agents:
  research-bot:
    per_transaction_cap: 100.00
    merchants:
      allow: ["api.example.com", "api.weather.example", "acct_123"]
      deny: ["evil.example.com"]
    approval_required_above:
      amount: 50.00
      approver_role: finance
"""


@pytest.fixture()
def enforcer(tmp_path: Path, operator_key: OperatorKey) -> Enforcer:
    audit = AuditLog(tmp_path / "api.db", operator_key)
    return Enforcer(
        source=StaticSource(Policy.from_yaml(API_POLICY)),
        audit=audit,
        key=operator_key,
        nonces=NonceStore(tmp_path / "api.db", engine=audit.engine),
        approvals=ApprovalQueue(tmp_path / "api.db", engine=audit.engine),
        approval_timeout=1.0,
        clock=lambda: NOW,
    )


@pytest.fixture()
def client(enforcer: Enforcer) -> Iterator[TestClient]:
    with TestClient(create_app(enforcer=enforcer)) as test_client:
        yield test_client


def authorize(client: TestClient, **payload: object) -> tuple[int, dict[str, Any]]:
    body: dict[str, object] = {
        "agent_id": "research-bot",
        "merchant": "api.example.com",
        "currency": "USD",
    }
    body.update(payload)
    response = client.post("/authorize", json=body)
    return response.status_code, response.json()


# ---------------------------------------------------------------------------
# authorize
# ---------------------------------------------------------------------------


def test_allowed_intent_returns_200_and_a_mandate(client: TestClient) -> None:
    status, body = authorize(client, amount="10.00")
    assert status == 200
    assert body["decision"]["outcome"] == "ALLOW"
    assert body["mandate"]
    assert body["audit_seq"] == 1


def test_denied_intent_returns_403(client: TestClient) -> None:
    """A block must not look like success to an agent's HTTP client."""
    status, body = authorize(client, amount="500.00")
    assert status == 403
    assert body["decision"]["outcome"] == "DENY"
    assert body["decision"]["reason_code"] == "OVER_PER_TXN_CAP"
    assert body["mandate"] is None


def test_denied_merchant_returns_403(client: TestClient) -> None:
    status, body = authorize(client, amount="10.00", merchant="evil.example.com")
    assert status == 403
    assert body["decision"]["reason_code"] == "MERCHANT_DENIED"


def test_approval_required_returns_202_with_a_pending_id(client: TestClient) -> None:
    status, body = authorize(client, amount="75.00")
    assert status == 202
    assert body["decision"]["outcome"] == "REQUIRE_APPROVAL"
    assert body["decision"]["approver_role"] == "finance"
    assert body["pending_id"]
    assert body["mandate"] is None


def test_unknown_agent_is_denied(client: TestClient) -> None:
    status, body = authorize(client, amount="10.00", agent_id="rogue-bot")
    assert status == 403
    assert body["decision"]["reason_code"] == "AGENT_NOT_IN_POLICY"


def test_unparseable_body_is_denied_and_logged(
    client: TestClient, enforcer: Enforcer
) -> None:
    """Traffic bouncer cannot read is never passed through unexamined."""
    response = client.post(
        "/authorize", content=b"this is not an intent",
        headers={"content-type": "text/plain"},
    )
    assert response.status_code == 403
    body = response.json()
    assert body["decision"]["reason_code"] == "UNPARSEABLE_INTENT"

    entries = enforcer.audit.entries()
    assert len(entries) == 1
    assert entries[0].kind == "unparseable"
    assert enforcer.audit.verify().ok


def test_oversized_body_is_rejected(client: TestClient) -> None:
    response = client.post("/authorize", content=b"x" * (256 * 1024 + 1))
    assert response.status_code == 413


def test_agent_can_come_from_a_header(client: TestClient) -> None:
    response = client.post(
        "/authorize",
        json={"merchant": "api.example.com", "amount": "10.00"},
        headers={"x-bouncer-agent": "research-bot"},
    )
    assert response.status_code == 200


def test_every_decision_reaches_the_audit_log(
    client: TestClient, enforcer: Enforcer
) -> None:
    authorize(client, amount="10.00")
    authorize(client, amount="500.00")
    authorize(client, amount="75.00")

    outcomes = [entry.outcome for entry in enforcer.audit.entries()]
    assert outcomes == ["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    assert enforcer.audit.verify().ok


# ---------------------------------------------------------------------------
# raw traffic (stripe / x402)
# ---------------------------------------------------------------------------


def test_stripe_traffic_via_raw_endpoint(client: TestClient) -> None:
    response = client.post(
        "/authorize/raw",
        json={
            "agent_id": "research-bot",
            "method": "POST",
            "url": "https://api.stripe.com/v1/payment_intents",
            "headers": {"authorization": "Bearer sk_test_x"},
            "body": "amount=1000&currency=usd&transfer_data%5Bdestination%5D=acct_123",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["intent"]["rail"] == "stripe"
    assert body["intent"]["merchant"] == "acct_123"
    assert body["intent"]["amount"] == "10"


def test_x402_challenge_via_raw_endpoint(client: TestClient) -> None:
    challenge = {
        "x402Version": 1,
        "accepts": [
            {
                "scheme": "exact",
                "maxAmountRequired": "10000",
                "resource": "https://api.weather.example/forecast",
                "extra": {"name": "USDC", "decimals": 6},
            }
        ],
    }
    response = client.post(
        "/authorize/raw",
        json={
            "agent_id": "research-bot",
            "status_code": 402,
            "url": "https://api.weather.example/forecast",
            "body": json.dumps(challenge),
        },
    )
    # The policy is denominated in USD; a USDC charge is denied rather than
    # converted at a rate bouncer is not allowed to fetch.
    assert response.status_code == 403
    assert response.json()["decision"]["reason_code"] == "CURRENCY_MISMATCH"


def test_live_stripe_key_is_denied(client: TestClient) -> None:
    response = client.post(
        "/authorize/raw",
        json={
            "agent_id": "research-bot",
            "url": "https://api.stripe.com/v1/payment_intents",
            "headers": {"authorization": "Bearer sk_live_real"},
            "body": "amount=1000&currency=usd",
        },
    )
    assert response.status_code == 403
    assert response.json()["decision"]["reason_code"] == "UNPARSEABLE_INTENT"


# ---------------------------------------------------------------------------
# mandate verification
# ---------------------------------------------------------------------------


def test_mandate_verifies_then_replays_are_rejected(client: TestClient) -> None:
    _, body = authorize(client, amount="10.00")
    mandate = body["mandate"]

    first = client.post("/mandates/verify", json={"mandate": mandate})
    assert first.status_code == 200
    assert first.json()["valid"] is True

    second = client.post("/mandates/verify", json={"mandate": mandate})
    assert second.status_code == 403
    assert second.json()["error_type"] == "MandateReplayed"


def test_mandate_scope_is_checked(client: TestClient) -> None:
    _, body = authorize(client, amount="10.00")
    response = client.post(
        "/mandates/verify",
        json={"mandate": body["mandate"], "merchant": "attacker.example.com"},
    )
    assert response.status_code == 403
    assert response.json()["error_type"] == "MandateScopeViolation"


def test_mandate_amount_ceiling_is_checked(client: TestClient) -> None:
    _, body = authorize(client, amount="10.00")
    response = client.post(
        "/mandates/verify", json={"mandate": body["mandate"], "amount": "99.00"}
    )
    assert response.status_code == 403
    assert response.json()["error_type"] == "MandateScopeViolation"


def test_garbage_mandate_is_rejected(client: TestClient) -> None:
    response = client.post("/mandates/verify", json={"mandate": "not.atoken"})
    assert response.status_code == 403
    assert response.json()["valid"] is False


# ---------------------------------------------------------------------------
# supporting endpoints
# ---------------------------------------------------------------------------


def test_healthz_reports_policy_state(client: TestClient) -> None:
    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    assert body["policy_ok"] is True
    assert len(body["policy_hash"]) == 64


def test_policy_endpoint_returns_the_loaded_policy(client: TestClient) -> None:
    body = client.get("/policy").json()
    assert body["ok"] is True
    assert body["policy"]["agents"]["research-bot"]["per_transaction_cap"] == "100.00"


def test_broken_policy_makes_health_report_it_and_authorize_deny(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    audit = AuditLog(tmp_path / "x.db", operator_key)
    broken = Enforcer(
        source=StaticSource(None, error="policy file unavailable"),
        audit=audit,
        key=operator_key,
        nonces=NonceStore(tmp_path / "x.db", engine=audit.engine),
        approvals=ApprovalQueue(tmp_path / "x.db", engine=audit.engine),
        clock=lambda: NOW,
    )
    with TestClient(create_app(enforcer=broken)) as client:
        assert client.get("/healthz").json()["policy_ok"] is False
        assert client.get("/policy").status_code == 503
        status, body = authorize(client, amount="1.00")

    assert status == 403
    assert body["decision"]["reason_code"] == "POLICY_INVALID"


def test_pending_endpoint_lists_and_filters(client: TestClient) -> None:
    authorize(client, amount="75.00")
    assert client.get("/pending").json()["count"] == 1
    assert client.get("/pending", params={"role": "finance"}).json()["count"] == 1
    assert client.get("/pending", params={"role": "cfo"}).json()["count"] == 0


def test_audit_verify_endpoint(client: TestClient, enforcer: Enforcer) -> None:
    authorize(client, amount="10.00")
    body = client.get("/audit/verify").json()
    assert body["ok"] is True
    assert body["entries_checked"] == 1

    from sqlalchemy import text

    with enforcer.audit.engine.begin() as connection:
        connection.execute(text("UPDATE audit_entries SET amount='9999' WHERE seq=1"))

    response = client.get("/audit/verify")
    assert response.status_code == 409
    assert response.json()["broken_seq"] == 1


def test_blocking_authorize_times_out_into_a_deny(client: TestClient) -> None:
    response = client.post(
        "/authorize",
        json={"agent_id": "research-bot", "merchant": "api.example.com", "amount": "75.00"},
        params={"wait": True, "timeout": 0.5},
    )
    assert response.status_code == 403
    assert response.json()["decision"]["reason_code"] == "APPROVAL_TIMEOUT"


# ---------------------------------------------------------------------------
# POST /approvals/{id}/resolve
# ---------------------------------------------------------------------------


def queue_an_approval(client: TestClient) -> str:
    status, body = authorize(
        client, agent_id="research-bot", merchant="api.example.com", amount="75.00"
    )
    assert status == 202
    pending_id = body["pending_id"]
    assert isinstance(pending_id, str)
    return pending_id


def test_resolve_grants_with_the_required_role(client: TestClient) -> None:
    item_id = queue_an_approval(client)
    response = client.post(
        f"/approvals/{item_id}/resolve", json={"role": "finance", "approve": True}
    )
    assert response.status_code == 200
    assert response.json()["decision"]["reason_code"] == "APPROVAL_GRANTED"
    assert response.json()["mandate"]


def test_resolve_refuses_the_wrong_role(client: TestClient) -> None:
    item_id = queue_an_approval(client)
    response = client.post(
        f"/approvals/{item_id}/resolve", json={"role": "engineering", "approve": True}
    )
    assert response.status_code == 403
    assert "requires role" in response.json()["error"]


def test_resolve_is_once_only(client: TestClient) -> None:
    item_id = queue_an_approval(client)
    assert client.post(
        f"/approvals/{item_id}/resolve", json={"role": "finance", "approve": True}
    ).status_code == 200
    assert client.post(
        f"/approvals/{item_id}/resolve", json={"role": "finance", "approve": True}
    ).status_code == 403


def test_resolve_denying_is_symmetric_with_approving(client: TestClient) -> None:
    """Vetoing must not be easier than approving; both take the same check."""
    item_id = queue_an_approval(client)
    wrong = client.post(
        f"/approvals/{item_id}/resolve", json={"role": "engineering", "approve": False}
    )
    assert wrong.status_code == 403

    right = client.post(
        f"/approvals/{item_id}/resolve", json={"role": "finance", "approve": False}
    )
    assert right.status_code == 403
    assert right.json()["decision"]["reason_code"] == "APPROVAL_DENIED"
    assert right.json()["mandate"] is None


def test_resolve_unknown_id_is_404(client: TestClient) -> None:
    response = client.post(
        "/approvals/nosuchitem/resolve", json={"role": "finance", "approve": True}
    )
    assert response.status_code == 404


def test_resolve_rejects_unknown_fields(client: TestClient) -> None:
    """extra='forbid' -- a misspelled field must not read as a default."""
    item_id = queue_an_approval(client)
    response = client.post(
        f"/approvals/{item_id}/resolve",
        json={"role": "finance", "aprove": True},
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# the body cap has to prevent the allocation, not just report it afterwards
# ---------------------------------------------------------------------------


def test_an_oversized_body_is_refused_without_being_buffered(
    client: TestClient,
) -> None:
    """`await request.body()` read the whole payload before its length could be
    checked, so the limit rejected the request but did not prevent the memory
    being taken. A 24 MB post cost 24 MB.
    """
    import tracemalloc

    oversize = b"x" * (8 * 1024 * 1024)
    tracemalloc.start()
    tracemalloc.reset_peak()
    response = client.post(
        "/authorize", content=oversize, headers={"content-type": "application/json"}
    )
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()

    assert response.status_code == 413
    assert peak < len(oversize) // 4, (
        f"peak was {peak} bytes for an {len(oversize)}-byte body; the cap is "
        "rejecting after buffering rather than instead of it"
    )


def test_the_model_parsing_route_is_capped_too(client: TestClient) -> None:
    """/authorize/raw never sees the raw body, so only middleware protects it."""
    response = client.post(
        "/authorize/raw",
        content=b"x" * (2 * 1024 * 1024),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413


def test_a_body_larger_than_it_claims_is_still_capped(client: TestClient) -> None:
    """A truthful Content-Length is not something a caller has to supply."""
    oversize = b"x" * (2 * 1024 * 1024)
    response = client.post(
        "/authorize",
        content=oversize,
        headers={"content-type": "application/json", "transfer-encoding": "chunked"},
    )
    assert response.status_code == 413


def test_a_malformed_content_length_is_refused(client: TestClient) -> None:
    response = client.post(
        "/authorize",
        content=b'{"agent_id":"research-bot"}',
        headers={"content-type": "application/json", "content-length": "not-a-number"},
    )
    assert response.status_code in (400, 413)


def test_a_normal_sized_body_still_works(client: TestClient) -> None:
    """The cap must not break the ordinary path."""
    status, body = authorize(
        client, agent_id="research-bot", merchant="api.example.com", amount="12.00"
    )
    assert status == 200
    assert body["mandate"]
