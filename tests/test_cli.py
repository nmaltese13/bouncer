"""The command line, end to end against a real home directory."""

from __future__ import annotations

import io
import json
import os
import re
from pathlib import Path

import pytest

from bouncer.cli import EXIT_DENIED, EXIT_ERROR, EXIT_OK, EXIT_TAMPERED, main

POLICY = """
version: 1
currency: USD
agents:
  research-bot:
    per_transaction_cap: 100.00
    merchants:
      deny: ["evil.example.com"]
    approval_required_above:
      amount: 50.00
      approver_role: finance
"""


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    workspace = tmp_path / "home"
    workspace.mkdir()
    (workspace / "policy.yaml").write_text(POLICY)
    return workspace


def run(home: Path, *args: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(["--home", str(home), *args], out=out)
    return code, out.getvalue()


def bootstrap(home: Path) -> None:
    assert run(home, "keygen")[0] == EXIT_OK


# ---------------------------------------------------------------------------


def test_init_creates_key_and_policy(tmp_path: Path) -> None:
    workspace = tmp_path / "fresh"
    code, output = run(workspace, "init")
    assert code == EXIT_OK
    assert (workspace / "operator.pem").exists()
    assert (workspace / "policy.yaml").exists()
    assert "key id:" in output


@pytest.mark.skipif(
    os.name == "nt",
    reason="POSIX mode bits are advisory on Windows; the key is protected by "
    "the directory ACL instead, which bouncer does not set (see keys.py)",
)
def test_key_file_is_owner_only(tmp_path: Path) -> None:
    workspace = tmp_path / "fresh"
    run(workspace, "init")
    mode = (workspace / "operator.pem").stat().st_mode
    assert mode & 0o077 == 0, "operator key must not be group or world readable"


def test_keygen_refuses_to_clobber_an_existing_key(home: Path) -> None:
    bootstrap(home)
    original = (home / "operator.pem").read_bytes()
    code, output = run(home, "keygen")
    assert code == EXIT_ERROR
    assert "refusing to overwrite" in output
    assert (home / "operator.pem").read_bytes() == original


def test_keygen_force_overwrites(home: Path) -> None:
    bootstrap(home)
    original = (home / "operator.pem").read_bytes()
    assert run(home, "keygen", "--force")[0] == EXIT_OK
    assert (home / "operator.pem").read_bytes() != original


def test_policy_validate_reports_the_hash(home: Path) -> None:
    code, output = run(home, "policy")
    assert code == EXIT_OK
    assert "valid. policy hash:" in output
    assert "requires role 'finance'" in output


def test_policy_validate_rejects_a_bad_policy(home: Path) -> None:
    (home / "policy.yaml").write_text("version: 1\nagents:\n  bot:\n    typo: 5\n")
    code, output = run(home, "policy")
    assert code == EXIT_ERROR
    assert "INVALID" in output


def test_check_allows_and_exits_zero(home: Path) -> None:
    bootstrap(home)
    code, output = run(
        home, "check", "--agent", "research-bot", "--merchant", "api.example.com",
        "--amount", "10.00",
    )
    assert code == EXIT_OK
    assert "ALLOW" in output
    assert "mandate:" in output


def test_check_denies_with_its_own_exit_code(home: Path) -> None:
    """A denial is distinguishable from a crash in a shell pipeline."""
    bootstrap(home)
    code, output = run(
        home, "check", "--agent", "research-bot", "--merchant", "evil.example.com",
        "--amount", "10.00",
    )
    assert code == EXIT_DENIED
    assert "MERCHANT_DENIED" in output


def test_check_json_output(home: Path) -> None:
    bootstrap(home)
    code, output = run(
        home, "check", "--agent", "research-bot", "--merchant", "api.example.com",
        "--amount", "10.00", "--json",
    )
    payload = json.loads(output)
    assert payload["decision"]["outcome"] == "ALLOW"
    assert payload["mandate"]


def test_check_dry_run_writes_nothing(home: Path) -> None:
    bootstrap(home)
    run(home, "check", "--agent", "research-bot", "--merchant", "a.example.com",
        "--amount", "1.00", "--dry-run")
    code, output = run(home, "verify")
    assert "0 entries" in output


def test_verify_reports_a_clean_chain(home: Path) -> None:
    bootstrap(home)
    run(home, "check", "--agent", "research-bot", "--merchant", "a.example.com",
        "--amount", "1.00")
    code, output = run(home, "verify")
    assert code == EXIT_OK
    assert "chain intact" in output
    assert "--expect-head" in output


def test_verify_detects_tampering_with_its_own_exit_code(home: Path) -> None:
    bootstrap(home)
    run(home, "check", "--agent", "research-bot", "--merchant", "a.example.com",
        "--amount", "1.00")

    import sqlite3

    connection = sqlite3.connect(home / "bouncer.db")
    connection.execute("UPDATE audit_entries SET amount='999.00' WHERE seq=1")
    connection.commit()
    connection.close()

    code, output = run(home, "verify")
    assert code == EXIT_TAMPERED
    assert "CHAIN BROKEN at entry seq=1" in output


def test_verify_expect_head_catches_truncation(home: Path) -> None:
    bootstrap(home)
    for index in range(3):
        run(home, "check", "--agent", "research-bot", "--merchant",
            f"m{index}.example.com", "--amount", "1.00")

    _, output = run(home, "verify", "--json")
    head = json.loads(output)["head_hash"]

    import sqlite3

    connection = sqlite3.connect(home / "bouncer.db")
    connection.execute("DELETE FROM audit_entries WHERE seq > 1")
    connection.commit()
    connection.close()

    assert run(home, "verify")[0] == EXIT_OK  # internally consistent
    code, output = run(home, "verify", "--expect-head", head)
    assert code == EXIT_TAMPERED
    assert "removed from the end" in output


def test_export_writes_jsonl(home: Path, tmp_path: Path) -> None:
    bootstrap(home)
    run(home, "check", "--agent", "research-bot", "--merchant", "a.example.com",
        "--amount", "1.00")
    target = tmp_path / "audit.jsonl"
    code, output = run(home, "export", "-o", str(target))
    assert code == EXIT_OK
    assert "exported 1 entries" in output
    assert json.loads(target.read_text().strip())["seq"] == 1


# ---------------------------------------------------------------------------
# approvals
# ---------------------------------------------------------------------------


def queue_one(home: Path) -> str:
    code, output = run(
        home, "check", "--agent", "research-bot", "--merchant", "vendor.example.com",
        "--amount", "75.00",
    )
    assert code == EXIT_DENIED
    match = re.search(r"pending approval id: (\w+)", output)
    assert match is not None, output
    return match.group(1)


def test_pending_lists_and_filters_by_role(home: Path) -> None:
    bootstrap(home)
    item_id = queue_one(home)

    code, output = run(home, "pending")
    assert code == EXIT_OK
    assert item_id in output
    assert "requires role: finance" in output

    assert item_id in run(home, "pending", "--role", "finance")[1]
    assert "no pending approvals" in run(home, "pending", "--role", "cfo")[1]


def test_approve_with_the_right_role(home: Path) -> None:
    bootstrap(home)
    item_id = queue_one(home)
    code, output = run(home, "approve", item_id, "--role", "finance")
    assert code == EXIT_OK
    assert "approved" in output
    assert "mandate:" in output
    assert "no pending approvals" in run(home, "pending")[1]


def test_approve_with_the_wrong_role_is_refused(home: Path) -> None:
    bootstrap(home)
    item_id = queue_one(home)
    code, output = run(home, "approve", item_id, "--role", "engineering")
    assert code == EXIT_ERROR
    assert "refused" in output
    assert item_id in run(home, "pending")[1]


def test_deny_requires_the_same_role_as_approve(home: Path) -> None:
    """Symmetric authority: denying is not easier than approving."""
    bootstrap(home)
    item_id = queue_one(home)
    assert run(home, "deny", item_id, "--role", "engineering")[0] == EXIT_ERROR
    assert run(home, "deny", item_id, "--role", "finance")[0] == EXIT_DENIED


def test_resolved_items_cannot_be_resolved_again(home: Path) -> None:
    bootstrap(home)
    item_id = queue_one(home)
    run(home, "approve", item_id, "--role", "finance")
    code, output = run(home, "approve", item_id, "--role", "finance")
    assert code == EXIT_ERROR
    assert "already" in output


def test_unknown_approval_id(home: Path) -> None:
    bootstrap(home)
    code, output = run(home, "approve", "deadbeef", "--role", "finance")
    assert code == EXIT_ERROR
    assert "no pending approval" in output


def test_approval_flow_stays_verifiable(home: Path) -> None:
    bootstrap(home)
    item_id = queue_one(home)
    run(home, "approve", item_id, "--role", "finance")
    code, output = run(home, "verify")
    assert code == EXIT_OK
    assert "2 entries verified" in output


def test_missing_key_is_a_clean_error_not_a_traceback(home: Path) -> None:
    code, output = run(
        home, "check", "--agent", "research-bot", "--merchant", "a.example.com",
        "--amount", "1.00",
    )
    assert code == EXIT_ERROR
    assert "bouncer keygen" in output


def test_purge_removes_expired_nonces_only(home: Path) -> None:
    """Housekeeping must never touch the append-only audit log."""
    bootstrap(home)
    run(home, "check", "--agent", "research-bot", "--merchant", "a.example.com",
        "--amount", "1.00")

    code, output = run(home, "purge")
    assert code == EXIT_OK
    assert "audit log is append-only and was not modified" in output
    assert run(home, "verify")[0] == EXIT_OK
    assert "1 entries verified" in run(home, "verify")[1]


# ---------------------------------------------------------------------------
# `bouncer demo` -- reachable from an installed wheel, and self-contained
# ---------------------------------------------------------------------------


def test_demo_command_runs_and_shows_every_outcome(
    capsys: pytest.CaptureFixture[str], home: Path
) -> None:
    code, _ = run(home, "demo")
    printed = capsys.readouterr().out
    assert code == EXIT_OK
    assert "ALLOW  WITHIN_POLICY" in printed
    assert "DENY  OVER_PER_TXN_CAP" in printed
    assert "APPROVAL  APPROVAL_REQUIRED" in printed
    assert "CHAIN BROKEN" in printed, "the tamper evidence must still fire"


def test_demo_command_does_not_touch_the_operator_home(
    capsys: pytest.CaptureFixture[str], home: Path
) -> None:
    """It builds its own throwaway state; a demo must never spend real budget."""
    bootstrap(home)
    before = sorted(p.name for p in home.iterdir())
    audit_rows_before = (home / "bouncer.db").stat().st_size if (home / "bouncer.db").exists() else 0

    run(home, "demo")
    capsys.readouterr()

    assert sorted(p.name for p in home.iterdir()) == before
    after = (home / "bouncer.db").stat().st_size if (home / "bouncer.db").exists() else 0
    assert after == audit_rows_before


# ---------------------------------------------------------------------------
# `bouncer simulate`
# ---------------------------------------------------------------------------


def test_simulate_reports_what_a_tighter_cap_would_have_blocked(
    home: Path, tmp_path: Path
) -> None:
    bootstrap(home)
    for amount in ("5.00", "15.00", "8.00"):
        run(home, "check", "--agent", "research-bot",
            "--merchant", "api.openai.com", "--amount", amount)

    candidate = tmp_path / "tighter.yaml"
    candidate.write_text(
        "version: 1\ncurrency: USD\nagents:\n  research-bot:\n"
        "    per_transaction_cap: 10.00\n",
        encoding="utf-8",
    )
    code, output = run(home, "simulate", str(candidate))
    assert code == EXIT_OK
    assert "would now be BLOCKED" in output
    assert "OVER_PER_TXN_CAP" in output
    assert "Nothing was written" in output


def test_simulate_writes_nothing_to_the_log(home: Path, tmp_path: Path) -> None:
    bootstrap(home)
    run(home, "check", "--agent", "research-bot",
        "--merchant", "api.openai.com", "--amount", "5.00")
    _, before = run(home, "verify", "--json")

    candidate = tmp_path / "tighter.yaml"
    candidate.write_text(
        "version: 1\ncurrency: USD\nagents:\n  research-bot:\n"
        "    per_transaction_cap: 1.00\n",
        encoding="utf-8",
    )
    run(home, "simulate", str(candidate))

    _, after = run(home, "verify", "--json")
    assert json.loads(before) == json.loads(after), "the chain must be untouched"


def test_simulate_rejects_an_invalid_candidate(home: Path, tmp_path: Path) -> None:
    bootstrap(home)
    bad = tmp_path / "bad.yaml"
    bad.write_text("this is not: [valid yaml\n", encoding="utf-8")
    code, output = run(home, "simulate", str(bad))
    assert code == EXIT_ERROR
    assert "INVALID" in output


def test_simulate_json_output_is_machine_readable(home: Path, tmp_path: Path) -> None:
    bootstrap(home)
    run(home, "check", "--agent", "research-bot",
        "--merchant", "api.openai.com", "--amount", "5.00")
    candidate = tmp_path / "c.yaml"
    candidate.write_text(
        "version: 1\ncurrency: USD\nagents:\n  research-bot:\n"
        "    per_transaction_cap: 1.00\n",
        encoding="utf-8",
    )
    code, output = run(home, "simulate", str(candidate), "--json")
    assert code == EXIT_OK
    report = json.loads(output)
    assert report["newly_blocked"] == 1
    assert report["changes"][0]["would_be"] == "DENY"
    assert report["changes"][0]["was"] == "ALLOW"
