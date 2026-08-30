"""The bouncer command line.

Threat model: none of these commands authenticate anybody. ``--role finance`` is
an assertion by whoever holds shell access, not a login. v1 assumes a single
trusted operator on a trusted machine; anyone who can run this CLI can approve
anything. See the Threat Model in README.md.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Sequence, TextIO

from . import __version__
from .approvals import ApprovalQueue, ApprovalStatus
from .audit import AuditLog, export_jsonl
from .config import BouncerConfig
from .enforcement import Enforcer
from .errors import BouncerError, PolicyError, RoleMismatch, UnknownApproval
from .keys import OperatorKey, VerifyKey
from .mandate import NonceStore
from .models import Outcome, PaymentIntent
from .policy import Policy
from .sources import LocalFileSource

__all__ = ["main"]

EXIT_OK = 0
EXIT_ERROR = 1
#: A policy denial is not a crash, but it must be distinguishable in a shell
#: pipeline, so it gets its own status.
EXIT_DENIED = 2
#: Reserved for `verify` when the chain is broken. An operator's monitoring
#: should page on this specifically.
EXIT_TAMPERED = 3

STARTER_POLICY = """\
# bouncer policy. Every rule here is enforced deny-by-default:
# an agent not named below cannot spend at all.
version: 1
currency: USD

agents:
  research-bot:
    per_transaction_cap: 25.00
    rolling_windows:
      - amount: 200.00
        window: 30d
    merchants:
      allow: ["api.openai.com", "api.anthropic.com", "*.trusted-vendor.com"]
      deny: ["*.casino.example"]
    approval_required_above:
      amount: 10.00
      approver_role: finance
"""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _config(args: argparse.Namespace) -> BouncerConfig:
    """Resolve config from flags, then environment, then defaults.

    Sub-paths are only carried over when they were set *explicitly* — by flag or
    by environment variable. Inheriting them from an already-resolved config
    would pin them to the default home and silently ignore ``--home``.
    """
    env = BouncerConfig.from_env()

    def pick(flag: Path | None, variable: str) -> Path | None:
        if flag is not None:
            return flag
        raw = os.environ.get(variable)
        return Path(raw).expanduser() if raw else None

    return BouncerConfig(
        home=args.home or env.home,
        policy_path=pick(args.policy, "BOUNCER_POLICY"),
        db_path=pick(args.db, "BOUNCER_DB"),
        key_path=pick(args.key, "BOUNCER_KEY"),
        approval_timeout=env.approval_timeout,
        webhook_url=env.webhook_url,
    )


def _enforcer(config: BouncerConfig) -> Enforcer:
    config.ensure_home()
    assert config.key_path is not None and config.db_path is not None
    assert config.policy_path is not None
    key = OperatorKey.load(config.key_path)
    audit = AuditLog(config.db_path, key)
    return Enforcer(
        source=LocalFileSource(config.policy_path),
        audit=audit,
        key=key,
        nonces=NonceStore(config.db_path, engine=audit.engine),
        approvals=ApprovalQueue(config.db_path, engine=audit.engine),
        webhook_url=config.webhook_url,
    )


def _amount(raw: str) -> Decimal:
    try:
        value = Decimal(raw)
    except InvalidOperation as exc:
        raise argparse.ArgumentTypeError(f"not a valid amount: {raw!r}") from exc
    if not value.is_finite():
        raise argparse.ArgumentTypeError(f"amount must be finite: {raw!r}")
    return value


def _emit(data: object, out: TextIO, *, as_json: bool, human: str) -> None:
    if as_json:
        out.write(json.dumps(data, indent=2, default=str) + "\n")
    else:
        out.write(human + "\n")


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace, out: TextIO) -> int:
    config = _config(args)
    home = config.ensure_home()
    assert config.key_path is not None and config.policy_path is not None

    if config.key_path.exists():
        out.write(f"operator key already present at {config.key_path}\n")
        key = OperatorKey.load(config.key_path)
    else:
        key = OperatorKey.generate(config.key_path)
        # Claim only the protection actually applied. os.open's mode argument is
        # ignored on Windows, so printing "mode 0600" there would advertise a
        # restriction that is not in force — the one kind of inaccuracy this
        # tool must never print about its own signing key.
        if os.name == "nt":
            protection = "inherits the directory ACL; Windows ignores POSIX modes"
        else:
            protection = "mode 0600"
        out.write(f"generated operator key at {config.key_path} ({protection})\n")

    if config.policy_path.exists():
        out.write(f"policy already present at {config.policy_path}\n")
    else:
        config.policy_path.write_text(STARTER_POLICY, encoding="utf-8")
        out.write(f"wrote a starter policy to {config.policy_path}\n")

    out.write(f"\nbouncer home: {home}\nkey id: {key.key_id}\n")
    out.write("\nNext: edit the policy, then run `bouncer serve`.\n")
    return EXIT_OK


def cmd_keygen(args: argparse.Namespace, out: TextIO) -> int:
    config = _config(args)
    config.ensure_home()
    assert config.key_path is not None
    if config.key_path.exists() and not args.force:
        out.write(
            f"refusing to overwrite existing key at {config.key_path}\n"
            "Re-keying makes every previously signed audit entry unverifiable "
            "under the new key. Pass --force if that is what you want.\n"
        )
        return EXIT_ERROR
    key = OperatorKey.generate(config.key_path)
    out.write(f"generated operator key at {config.key_path}\nkey id: {key.key_id}\n")
    if args.public_out:
        Path(args.public_out).write_bytes(key.public_pem())
        out.write(f"public key written to {args.public_out}\n")
    return EXIT_OK


def cmd_policy(args: argparse.Namespace, out: TextIO) -> int:
    config = _config(args)
    assert config.policy_path is not None
    path = args.path or config.policy_path
    try:
        policy = Policy.from_yaml(Path(path).read_text(encoding="utf-8"))
    except (PolicyError, OSError) as exc:
        out.write(f"INVALID: {exc}\n")
        return EXIT_ERROR

    if args.json:
        _emit(policy.model_dump(mode="json"), out, as_json=True, human="")
        return EXIT_OK

    out.write(f"valid. policy hash: {policy.policy_hash}\n")
    out.write(f"currency: {policy.currency}\n")
    for name, rules in policy.agents.items():
        out.write(f"\nagent {name!r}\n")
        out.write(f"  per-transaction cap: {rules.per_transaction_cap}\n")
        for rolling in rules.rolling_windows:
            out.write(f"  rolling ceiling: {rolling.amount} per {rolling.window}\n")
        if rules.merchants.allow is not None:
            out.write(f"  merchants allowed: {', '.join(rules.merchants.allow) or '(none)'}\n")
        if rules.merchants.deny:
            out.write(f"  merchants denied: {', '.join(rules.merchants.deny)}\n")
        for schedule in rules.time_windows:
            days = ",".join(d.value for d in schedule.days) if schedule.days else "all days"
            out.write(
                f"  spending window: {schedule.start}-{schedule.end} "
                f"{schedule.timezone} ({days})\n"
            )
        if rules.approval_required_above is not None:
            approval = rules.approval_required_above
            out.write(
                f"  above {approval.amount}: requires role "
                f"{approval.approver_role!r}\n"
            )
    return EXIT_OK


def cmd_check(args: argparse.Namespace, out: TextIO) -> int:
    """Evaluate one intent from the command line."""
    config = _config(args)
    enforcer = _enforcer(config)
    request = PaymentIntent(
        agent_id=args.agent,
        merchant=args.merchant,
        amount=args.amount,
        currency=args.currency,
        category=args.category,
        description=args.description,
        rail="cli",
    )
    result = enforcer.authorize(request, record=not args.dry_run)

    if args.json:
        _emit(result.to_dict(), out, as_json=True, human="")
    else:
        out.write(result.decision.describe() + "\n")
        if result.mandate:
            out.write(f"mandate: {result.mandate}\n")
        if result.pending_id:
            out.write(
                f"pending approval id: {result.pending_id}\n"
                f"resolve with: bouncer approve {result.pending_id} "
                f"--role {result.decision.approver_role}\n"
            )
    return EXIT_OK if result.decision.outcome is Outcome.ALLOW else EXIT_DENIED


def cmd_verify(args: argparse.Namespace, out: TextIO) -> int:
    config = _config(args)
    assert config.key_path is not None and config.db_path is not None
    key = OperatorKey.load(config.key_path)
    log = AuditLog(config.db_path, key)

    verify_key: VerifyKey | None = None
    if args.public_key:
        verify_key = VerifyKey.from_file(args.public_key)

    result = log.verify(verify_key=verify_key, expect_head=args.expect_head)

    if args.json:
        _emit(
            {
                "ok": result.ok,
                "entries_checked": result.entries_checked,
                "head_hash": result.head_hash,
                "broken_seq": result.broken_seq,
                "problem": result.problem,
            },
            out,
            as_json=True,
            human="",
        )
    else:
        out.write(result.describe() + "\n")
        if result.ok and result.entries_checked:
            out.write(
                "\nRecord this head hash externally. A chain with entries removed "
                "from the end verifies clean unless you can compare against a "
                "head you saved earlier:\n"
                f"  bouncer verify --expect-head {result.head_hash}\n"
            )
    return EXIT_OK if result.ok else EXIT_TAMPERED


def cmd_export(args: argparse.Namespace, out: TextIO) -> int:
    config = _config(args)
    assert config.key_path is not None and config.db_path is not None
    log = AuditLog(config.db_path, OperatorKey.load(config.key_path))

    if args.output:
        count = export_jsonl(log, args.output)
        out.write(f"exported {count} entries to {args.output}\n")
    else:
        export_jsonl(log, sys.stdout)
    return EXIT_OK


def cmd_purge(args: argparse.Namespace, out: TextIO) -> int:
    """Drop spent nonces whose mandates have expired.

    Safe by construction: an expired mandate is already rejected on the expiry
    check, so forgetting that it was spent cannot enable a replay. The audit log
    is append-only and is never touched by this command.
    """
    config = _config(args)
    config.ensure_home()
    assert config.db_path is not None
    store = NonceStore(config.db_path)
    before = store.count()
    removed = store.purge_expired(now=datetime.now(timezone.utc))
    out.write(
        f"purged {removed} expired nonce(s); {before - removed} still live\n"
        "the audit log is append-only and was not modified\n"
    )
    return EXIT_OK


def cmd_pending(args: argparse.Namespace, out: TextIO) -> int:
    config = _config(args)
    config.ensure_home()
    assert config.db_path is not None
    queue = ApprovalQueue(config.db_path)
    items = queue.list(role=args.role, status=ApprovalStatus.PENDING)

    if args.json:
        _emit([item.to_dict() for item in items], out, as_json=True, human="")
        return EXIT_OK

    if not items:
        scope = f" for role {args.role!r}" if args.role else ""
        out.write(f"no pending approvals{scope}\n")
        return EXIT_OK

    out.write(f"{len(items)} pending approval(s):\n\n")
    for item in items:
        out.write(
            f"  {item.id}\n"
            f"    {item.amount} {item.currency} to {item.merchant}\n"
            f"    agent: {item.agent_id}\n"
            f"    requires role: {item.required_role}\n"
            f"    requested: {item.created_at}\n"
            f"    resolve: bouncer approve {item.id} --role {item.required_role}\n\n"
        )
    return EXIT_OK


def _resolve(args: argparse.Namespace, out: TextIO, *, approve: bool) -> int:
    config = _config(args)
    enforcer = _enforcer(config)
    verb = "approved" if approve else "denied"
    try:
        result = enforcer.resolve(
            args.id, role=args.role, approve=approve, note=args.note
        )
    except UnknownApproval as exc:
        out.write(f"error: {exc}\n")
        return EXIT_ERROR
    except RoleMismatch as exc:
        out.write(f"refused: {exc}\n")
        return EXIT_ERROR

    if args.json:
        _emit(result.to_dict(), out, as_json=True, human="")
    else:
        out.write(f"{args.id} {verb} by role {args.role!r}\n")
        out.write(result.decision.describe() + "\n")
        if result.mandate:
            out.write(f"mandate: {result.mandate}\n")
    return EXIT_OK if approve else EXIT_DENIED


def cmd_approve(args: argparse.Namespace, out: TextIO) -> int:
    return _resolve(args, out, approve=True)


def cmd_deny(args: argparse.Namespace, out: TextIO) -> int:
    return _resolve(args, out, approve=False)


def cmd_simulate(args: argparse.Namespace, out: TextIO) -> int:
    """Replay a candidate policy against the decisions already recorded.

    Writes nothing. It answers what a rule change would have done to traffic
    already seen, so a cap can be tightened knowing what it would have cost.
    """
    from .simulate import replay

    config = _config(args)
    assert config.key_path is not None and config.db_path is not None
    try:
        candidate = Policy.from_yaml(Path(args.path).read_text(encoding="utf-8"))
    except (PolicyError, OSError) as exc:
        out.write(f"INVALID: {exc}\n")
        return EXIT_ERROR

    log = AuditLog(config.db_path, OperatorKey.load(config.key_path))
    result = replay(log, candidate, agent_id=args.agent)

    if args.json:
        _emit(
            {
                "replayed": len(result.attempts),
                "newly_blocked": len(result.newly_blocked),
                "newly_allowed": len(result.newly_allowed),
                "unchanged": len(result.unchanged),
                "skipped": result.skipped,
                "blocked_value": str(result.blocked_value),
                "released_value": str(result.released_value),
                "changes": [
                    {
                        "at": item.at.isoformat(),
                        "agent_id": item.intent.agent_id,
                        "merchant": item.intent.merchant,
                        "amount": str(item.intent.amount),
                        "was": item.recorded.value,
                        "would_be": item.outcome.value,
                        "reason_code": item.decision.reason_code.value,
                        "reason": item.decision.reason,
                        "rule": item.decision.rule,
                    }
                    for item in result.newly_blocked + result.newly_allowed
                ],
            },
            out,
            as_json=True,
            human="",
        )
        return EXIT_OK

    out.write(f"candidate policy: {args.path}\n")
    out.write(f"policy hash:      {candidate.policy_hash}\n\n")
    out.write(result.describe() + "\n")
    if result.skipped:
        out.write(f"({result.skipped} row(s) carried no payment to re-judge)\n")

    if result.newly_blocked:
        out.write(f"\nwould now be BLOCKED ({result.blocked_value} total):\n")
        for item in result.newly_blocked:
            out.write(
                f"  {item.at:%Y-%m-%d %H:%M}  {item.intent.amount:>10} "
                f"{item.intent.currency} to {item.intent.merchant}\n"
                f"      {item.decision.reason_code.value}: {item.decision.reason}\n"
            )

    if result.newly_allowed:
        out.write(f"\nwould now be ALLOWED ({result.released_value} total):\n")
        for item in result.newly_allowed:
            out.write(
                f"  {item.at:%Y-%m-%d %H:%M}  {item.intent.amount:>10} "
                f"{item.intent.currency} to {item.intent.merchant}\n"
                f"      was {item.recorded.value}\n"
            )

    if not result.newly_blocked and not result.newly_allowed and result.attempts:
        out.write("\nnothing would change.\n")

    out.write("\nNothing was written. This was a simulation.\n")
    return EXIT_OK


def cmd_demo(args: argparse.Namespace, out: TextIO) -> int:
    """Run the bundled demonstration.

    Deliberately independent of the operator's real state: it builds its own
    key, policy and database in a temporary directory and removes them on the
    way out, so running it can never touch or spend against ~/.bouncer.
    """
    from .demo import main as run_demo

    return int(run_demo())


def cmd_serve(args: argparse.Namespace, out: TextIO) -> int:
    import uvicorn

    from .api import create_app

    config = _config(args)
    app = create_app(config)
    base = f"http://{args.host}:{args.port}"
    out.write(
        f"bouncer API on {base}\n"
        f"interactive console: {base}/docs\n"
        f"\npolicy: {config.policy_path}\ndatabase: {config.db_path}\n"
        "\nThis stays in the foreground. Leave it running and use another\n"
        "terminal or a browser; stopping it closes the port.\n\n"
    )
    out.flush()
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)
    return EXIT_OK


def cmd_proxy(args: argparse.Namespace, out: TextIO) -> int:
    import asyncio

    from .forward_proxy import serve_forever

    config = _config(args)
    out.write(
        f"bouncer forward proxy on {args.host}:{args.port}\n"
        f"point your agent at it:  export HTTP_PROXY=http://{args.host}:{args.port}\n"
    )
    if not args.allow_connect:
        out.write(
            "\nCONNECT (HTTPS) tunnels are DENIED. bouncer cannot read intent "
            "inside TLS, so it will not open a channel it cannot police.\n"
            "Pass --allow-connect to permit tunnels to allowlisted hosts only; "
            "their contents are then unenforced.\n"
        )
    asyncio.run(
        serve_forever(
            config,
            host=args.host,
            port=args.port,
            allow_connect=args.allow_connect,
        )
    )
    return EXIT_OK


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bouncer",
        description=(
            "A policy enforcement point for agent spending. bouncer decides; "
            "your network enforces. It never holds funds."
        ),
    )
    parser.add_argument("--version", action="version", version=f"bouncer {__version__}")
    parser.add_argument("--home", type=Path, help="bouncer state directory (~/.bouncer)")
    parser.add_argument("--policy", type=Path, help="path to the policy YAML")
    parser.add_argument("--db", type=Path, help="path to the SQLite database")
    parser.add_argument("--key", type=Path, help="path to the operator key PEM")

    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="create the home dir, key, and a policy")
    init.set_defaults(handler=cmd_init)

    keygen = subparsers.add_parser("keygen", help="generate a new operator key")
    keygen.add_argument("--force", action="store_true", help="overwrite an existing key")
    keygen.add_argument("--public-out", help="also write the public key here")
    keygen.set_defaults(handler=cmd_keygen)

    policy = subparsers.add_parser("policy", help="validate and summarize a policy")
    policy.add_argument("path", nargs="?", type=Path)
    policy.add_argument("--json", action="store_true")
    policy.set_defaults(handler=cmd_policy)

    check = subparsers.add_parser("check", help="evaluate one payment intent")
    check.add_argument("--agent", required=True)
    check.add_argument("--merchant", required=True)
    check.add_argument("--amount", required=True, type=_amount)
    check.add_argument("--currency", default="USD")
    check.add_argument("--category")
    check.add_argument("--description")
    check.add_argument(
        "--dry-run", action="store_true", help="do not write to the audit log"
    )
    check.add_argument("--json", action="store_true")
    check.set_defaults(handler=cmd_check)

    verify = subparsers.add_parser("verify", help="walk the audit chain for tampering")
    verify.add_argument("--expect-head", help="head hash recorded from an earlier run")
    verify.add_argument("--public-key", help="verify signatures against this PEM")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(handler=cmd_verify)

    export = subparsers.add_parser("export", help="export the audit log as JSONL")
    export.add_argument("-o", "--output", help="write here instead of stdout")
    export.set_defaults(handler=cmd_export)

    purge = subparsers.add_parser(
        "purge", help="drop spent nonces for mandates that have expired"
    )
    purge.set_defaults(handler=cmd_purge)

    pending = subparsers.add_parser("pending", help="list approvals awaiting a human")
    pending.add_argument("--role", help="only show items requiring this role")
    pending.add_argument("--json", action="store_true")
    pending.set_defaults(handler=cmd_pending)

    approve = subparsers.add_parser("approve", help="approve a pending item")
    approve.add_argument("id")
    approve.add_argument("--role", required=True, help="the role you are acting as")
    approve.add_argument("--note")
    approve.add_argument("--json", action="store_true")
    approve.set_defaults(handler=cmd_approve)

    deny = subparsers.add_parser("deny", help="deny a pending item")
    deny.add_argument("id")
    deny.add_argument("--role", required=True, help="the role you are acting as")
    deny.add_argument("--note")
    deny.add_argument("--json", action="store_true")
    deny.set_defaults(handler=cmd_deny)

    simulate = subparsers.add_parser(
        "simulate",
        help="replay a candidate policy against the recorded log; writes nothing",
    )
    simulate.add_argument("path", type=Path, help="the candidate policy YAML")
    simulate.add_argument("--agent", help="only replay this agent's payments")
    simulate.add_argument("--json", action="store_true")
    simulate.set_defaults(handler=cmd_simulate)

    demo = subparsers.add_parser(
        "demo", help="watch six purchases judged, then the audit chain checked"
    )
    demo.set_defaults(handler=cmd_demo)

    serve = subparsers.add_parser("serve", help="run the authorization API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--log-level", default="info")
    serve.set_defaults(handler=cmd_serve)

    proxy = subparsers.add_parser("proxy", help="run the HTTP forward proxy")
    proxy.add_argument("--host", default="127.0.0.1")
    proxy.add_argument("--port", type=int, default=8081)
    proxy.add_argument(
        "--allow-connect",
        action="store_true",
        help="permit CONNECT tunnels to allowlisted hosts (contents unenforced)",
    )
    proxy.set_defaults(handler=cmd_proxy)

    return parser


def main(argv: Sequence[str] | None = None, out: TextIO | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    stream = out if out is not None else sys.stdout
    handler: Any = args.handler
    try:
        return int(handler(args, stream))
    except BouncerError as exc:
        stream.write(f"error: {exc}\n")
        return EXIT_ERROR
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        stream.write("\ninterrupted\n")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
