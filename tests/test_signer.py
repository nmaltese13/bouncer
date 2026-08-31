"""Signing through something other than an in-process key.

The point of the seam is that the audit log and the mandate issuer never learn
where the private key lives, so a TPM, an HSM or a hardware token can be
substituted without either of them changing.
"""

from __future__ import annotations

import sys
import textwrap
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from bouncer.audit import AuditLog
from bouncer.keys import (
    ExternalSigner,
    KeyError_,
    OperatorKey,
    Signer,
    VerifyKey,
    load_signer,
)
from bouncer.mandate import issue_mandate, verify_mandate
from bouncer.models import Decision, Outcome, PaymentIntent, ReasonCode

NOW = datetime(2026, 3, 11, 14, 30, tzinfo=timezone.utc)

#: A stand-in for whatever a real deployment would put behind the seam -- a
#: pkcs11 wrapper, a YubiKey agent, a TPM helper. It reads the message on stdin
#: and writes the detached signature on stdout, which is the whole contract.
SIGNER_SCRIPT = """
import base64, sys
from cryptography.hazmat.primitives import serialization

pem = open(sys.argv[1], "rb").read()
key = serialization.load_pem_private_key(pem, password=None)
signature = key.sign(sys.stdin.buffer.read())
{emit}
"""

RAW = "sys.stdout.buffer.write(signature)"
B64 = "sys.stdout.buffer.write(base64.b64encode(signature))"
GARBAGE = "sys.stdout.buffer.write(b'x' * 64)"
FAILING = "sys.exit(3)"


@pytest.fixture()
def keypair(tmp_path: Path) -> tuple[Path, Path]:
    """A private key on disk plus its public half, as an operator would have."""
    private = tmp_path / "operator.pem"
    key = OperatorKey.generate(private)
    public = tmp_path / "operator.pub"
    public.write_bytes(key.public_pem())
    return private, public


def signer_command(tmp_path: Path, private: Path, emit: str, name: str) -> list[str]:
    script = tmp_path / f"{name}.py"
    script.write_text(textwrap.dedent(SIGNER_SCRIPT).format(emit=emit), encoding="utf-8")
    return [sys.executable, str(script), str(private)]


def external(tmp_path: Path, keypair: tuple[Path, Path], emit: str, name: str) -> ExternalSigner:
    private, public = keypair
    return ExternalSigner.from_public_pem(
        signer_command(tmp_path, private, emit, name), public
    )


def an_intent() -> PaymentIntent:
    return PaymentIntent(
        agent_id="research-bot",
        merchant="api.example.com",
        amount=Decimal("12.00"),
        currency="USD",
    )


def a_decision() -> Decision:
    return Decision(
        outcome=Outcome.ALLOW,
        reason_code=ReasonCode.WITHIN_POLICY,
        reason="ok",
        policy_hash="0" * 64,
        evaluated_at=NOW,
    )


# ---------------------------------------------------------------------------
# the protocol
# ---------------------------------------------------------------------------


def test_an_operator_key_satisfies_the_signer_protocol() -> None:
    assert isinstance(OperatorKey.generate(), Signer)


def test_a_public_key_alone_does_not(tmp_path: Path) -> None:
    """A VerifyKey must never be mistaken for something that can sign."""
    assert not isinstance(OperatorKey.generate().verify_key, Signer)


def test_an_external_signer_satisfies_it(
    tmp_path: Path, keypair: tuple[Path, Path]
) -> None:
    assert isinstance(external(tmp_path, keypair, RAW, "raw"), Signer)


# ---------------------------------------------------------------------------
# signing through a subprocess
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("emit,name", [(RAW, "raw"), (B64, "b64")])
def test_signatures_verify_under_the_public_key(
    tmp_path: Path, keypair: tuple[Path, Path], emit: str, name: str
) -> None:
    """Raw 64 bytes and base64 are both accepted; they cannot be confused."""
    signer = external(tmp_path, keypair, emit, name)
    signature = signer.sign(b"a message")
    assert signer.verify_key.verify(signature, b"a message")


def test_the_key_id_matches_the_in_process_key(
    tmp_path: Path, keypair: tuple[Path, Path]
) -> None:
    """Audit rows are attributed by key id, so it must not change with backend."""
    private, _ = keypair
    assert (
        external(tmp_path, keypair, RAW, "raw").key_id
        == OperatorKey.load(private).key_id
    )


def test_a_signer_returning_garbage_is_refused(
    tmp_path: Path, keypair: tuple[Path, Path]
) -> None:
    """The check that turns a silent corruption into one loud failure.

    Without it a misconfigured signer would fill the log with rows that never
    verify, and the damage would only surface at the next `bouncer verify` --
    long after the evidence was needed.
    """
    signer = external(tmp_path, keypair, GARBAGE, "garbage")
    with pytest.raises(KeyError_, match="does not verify"):
        signer.sign(b"a message")


def test_a_failing_signer_reports_its_exit_code(
    tmp_path: Path, keypair: tuple[Path, Path]
) -> None:
    signer = external(tmp_path, keypair, FAILING, "failing")
    with pytest.raises(KeyError_, match="exited 3"):
        signer.sign(b"a message")


def test_a_missing_signer_command_is_a_clean_error(tmp_path: Path) -> None:
    _, public = tmp_path / "x", tmp_path / "operator.pub"
    public.write_bytes(OperatorKey.generate().public_pem())
    signer = ExternalSigner(["definitely-not-a-real-command-xyz"], VerifyKey.from_file(public))
    with pytest.raises(KeyError_, match="could not be run"):
        signer.sign(b"a message")


def test_an_empty_command_is_rejected_at_construction(tmp_path: Path) -> None:
    public = tmp_path / "operator.pub"
    public.write_bytes(OperatorKey.generate().public_pem())
    with pytest.raises(KeyError_, match="must not be empty"):
        ExternalSigner([], VerifyKey.from_file(public))


# ---------------------------------------------------------------------------
# the seam actually holds: audit and mandates work through it unchanged
# ---------------------------------------------------------------------------


def test_the_audit_chain_verifies_when_written_by_an_external_signer(
    tmp_path: Path, keypair: tuple[Path, Path]
) -> None:
    signer = external(tmp_path, keypair, RAW, "raw")
    log = AuditLog(tmp_path / "a.db", signer)
    for _ in range(3):
        log.append(an_intent(), a_decision())

    result = log.verify()
    assert result.ok, result.problem
    assert result.entries_checked == 3


def test_a_chain_written_externally_verifies_under_the_public_key_alone(
    tmp_path: Path, keypair: tuple[Path, Path]
) -> None:
    """An auditor with only the public key can still check the log."""
    _, public = keypair
    signer = external(tmp_path, keypair, RAW, "raw")
    log = AuditLog(tmp_path / "a.db", signer)
    log.append(an_intent(), a_decision())

    assert log.verify(verify_key=VerifyKey.from_file(public)).ok


def test_mandates_minted_externally_verify(
    tmp_path: Path, keypair: tuple[Path, Path]
) -> None:
    signer = external(tmp_path, keypair, RAW, "raw")
    token, _ = issue_mandate(an_intent(), signer, policy_hash="0" * 64, now=NOW)

    claims = verify_mandate(
        token, signer, now=NOW, expected_merchant="api.example.com",
        amount=Decimal("12.00"),
    )
    assert claims.agent_id == "research-bot"


# ---------------------------------------------------------------------------
# choosing a signer
# ---------------------------------------------------------------------------


def test_load_signer_defaults_to_an_in_process_key(tmp_path: Path) -> None:
    key = OperatorKey.generate(tmp_path / "operator.pem")
    assert load_signer(tmp_path / "operator.pem").key_id == key.key_id


def test_load_signer_will_not_invent_a_key_by_default(tmp_path: Path) -> None:
    """A missing key usually means the wrong home, not a first run.

    Silently generating one would leave every previously signed row
    unverifiable under the replacement.
    """
    with pytest.raises(KeyError_):
        load_signer(tmp_path / "absent.pem")


def test_load_signer_creates_only_when_asked(tmp_path: Path) -> None:
    signer = load_signer(tmp_path / "new.pem", create=True)
    assert (tmp_path / "new.pem").exists()
    assert signer.key_id


def test_an_external_signer_requires_its_public_key(tmp_path: Path) -> None:
    """Inferring identity from an unverified signature would defeat the check."""
    with pytest.raises(KeyError_, match="needs the matching public key"):
        load_signer(tmp_path / "k.pem", command=["true"])


def test_load_signer_returns_an_external_signer_when_configured(
    tmp_path: Path, keypair: tuple[Path, Path]
) -> None:
    private, public = keypair
    signer = load_signer(
        private,
        command=signer_command(tmp_path, private, RAW, "raw"),
        public_key_path=public,
    )
    assert isinstance(signer, ExternalSigner)
    assert signer.key_id == OperatorKey.load(private).key_id
