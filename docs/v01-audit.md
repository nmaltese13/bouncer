# v0.1 Audit

Assessment of the repository as it stands against the seven-item v0.1 scope.

**Verified state:** 322 tests (321 pass, 1 skipped on Windows), 90% coverage
enforced in CI, `mypy --strict` clean across 46 source files, CLI and API both
run.

---

## Resolved since this audit was written

The findings below are kept as written, because the reasoning is the useful
part. What has changed:

| Finding | Status |
| --- | --- |
| §3.1 — crash on currencies longer than 3 characters | **Fixed.** `MandateClaims.currency` now matches `PaymentIntent.currency` (3–12). |
| §3.1 — decision reached but never logged | **Fixed.** `audit.append()` now runs before minting in both `authorize()` and `_finalize_locked()`, so a later failure cannot erase the record. |
| §4.1 — client library missing entirely | **Built.** `bouncer/client.py` — `Client.spend()` is a context manager where a denial raises and the guarded block never runs. 18 tests. |
| §3.8 — uncommitted working tree | **Committed.** History is now clean. |
| Build brief committed at repo root | **Removed.** It was the internal spec, not documentation of the result. |
| Approval grants never re-evaluated policy | **Fixed.** A grant now re-runs `evaluate()` against current policy and spend history; a hard `DENY` overrides the approver, and the audit row records the policy hash in force at grant time. |
| `LocalFileSource` cached on `(mtime, size)` | **Fixed.** Keyed on a content hash, so a same-size edit with a preserved timestamp can no longer leave a stale, looser policy in force. |
| §3.7 — proxy blocked the asyncio event loop | **Fixed.** `_authorize` and both tunnel decisions now run via `asyncio.to_thread`. |
| §3.8 — dead assignment in `cmd_export` | **Fixed.** |
| §3.5 — `POST /approvals/{id}/resolve` missing | **Built.** 403 on the wrong role or a second resolve, 404 on an unknown id. |
| Item 7 — toy agent example | **Built.** `examples/agent.py` spends through a $50 budget until it is stopped. |
| Agent keys colliding after `strip()`, and duplicate YAML keys | **Fixed.** Both silently kept the looser rule; both are now load errors. |
| `parse_duration` raised `OverflowError` out of the policy source | **Fixed.** Durations are bounded, and an unusable one denies rather than crashing the decision path. |
| Key material was pinned to an in-process `OperatorKey` | **Widened.** Audit and mandates depend on a `Signer` protocol; `ExternalSigner` puts the key behind a TPM, HSM or token. |
| No way to try a policy before adopting it | **Added.** `bouncer simulate` replays a candidate against the recorded log and writes nothing. |

Still open: the four decisions in §7, and item 1's `AuditEntry` model, which
is a SQLAlchemy row rather than a pydantic schema. §5's scope deletions are
untouched pending §7.

---

## 0. Read this first: the repo was built to a different spec

The build brief this code was originally written against (since removed from the
repo) specifies **six milestones M1-M6**. The v0.1 scope is a **different,
narrower seven-item list**. They agree on most things and contradict each other
on three, and one of those contradictions is expensive.

| Topic | Blueprint (what was built) | v0.1 scope (what is asked) | Cost to reconcile |
| --- | --- | --- | --- |
| Audit storage | SQLite, hash-chained | **append-only JSONL**, hash-chained | High - see 7.1 |
| JSONL export | "first-class library function... for SIEM ingestion" (M2) | "build no exporters"; SIEM exporters explicitly out of scope | Low (delete) |
| Forward proxy | M4, and the blueprint's *definition of done* is `HTTP_PROXY`-based | not mentioned at all | High - see 7.2 |

Nothing below is actionable until you resolve these. I have flagged the two
that change the shape of the codebase in section 7 rather than guessing.

---

## 1. Scope reconciliation

| # | v0.1 requirement | Status |
| --- | --- | --- |
| 1 | pydantic: Policy, Transaction, Decision, AuditEntry | Partial - 2 of 4 as specified |
| 2 | Pure `evaluate()`, fully unit-tested | Done, exceeds spec |
| 3 | Audit log: append-only JSONL, hash-chained, ed25519, `bouncer verify` | Works, wrong storage medium |
| 4 | Approval queue in SQLite, by approver_role | Works, role unconstrained |
| 5 | FastAPI: `POST /authorize`, `POST /approvals/{id}/resolve` | Done - both endpoints exist |
| 6 | Client lib: context manager wrapping an agent's spend call | Done - see "Resolved" above |
| 7 | Example: toy agent, $50 budget, overspends, blocked | Done - `examples/agent.py` |

---

## 2. What already exists and works

Blunt assessment: **the code quality here is high, and higher than most
codebases at this stage.** This is not a half-finished skeleton. Type hints are
complete, `mypy --strict` passes, security-relevant functions carry threat-model
docstrings, and there are no `TODO`s (deferred work is written down in
`ROADMAP.md` instead). Where I criticise below, it is about scope mismatch and
two real defects - not about sloppiness, because there is very little.

### 2.1 The policy engine - `bouncer/engine.py` (item 2) - DONE

Genuinely pure and genuinely correct. No I/O, no clock reads (`now` is
injected), no network, no model calls. Evaluation order is fixed and documented
as a security property:

```
policy availability -> agent scoping -> well-formedness -> prohibitions
-> ceilings -> approval -> allow
```

Prohibitions run **before** the approval threshold, so a forbidden transaction
is never offered to a human. That is the right call and it is deliberate.

Deny-by-default holds everywhere I probed: unknown agent denies, missing policy
denies, invalid policy denies, unknown rule name is a load error rather than a
silently-absent restriction (`extra="forbid"`), `per_transaction_cap` is
mandatory, empty allowlist freezes an agent, uncategorized requests fail a
category allowlist.

**52 engine tests.** The spec asks for 20 including boundary cases. Boundaries
are covered: exactly-at-cap, window rollover, denylist beating allowlist,
overnight window wrap, timezone handling, empty policy.

Two details worth calling out as correct-and-non-obvious:

- YAML is parsed through a `Decimal`-safe loader, so `100.10` in a policy is
  exactly 100.10 and never a binary float.
- `_lookback_for()` derives the spend-history horizon from the policy's own
  longest rolling window rather than a constant. A fixed horizon shorter than a
  declared window would under-count spend and fail *open*.

### 2.2 Hash-chained, signed audit log - `bouncer/audit.py` (item 3, mechanism) - DONE

The tamper-evidence mechanism is sound. Each row is SHA-256 hashed over
canonical JSON, chained via `prev_hash`, and Ed25519-signed. `verify()` walks
the chain and names the first broken row, distinguishing four failure modes:
sequence gap, broken link, altered content, bad signature.

The append is correctly atomic - it reads the tail hash and inserts inside one
`BEGIN IMMEDIATE` transaction under a lock, so the chain cannot fork.

`_HASHED_FIELDS` covers every stored column except the hash and signature, with
a docstring explaining why that must stay exhaustive: `amount` and `outcome` are
denormalized for `spend_history`, so leaving them outside the hash would let an
attacker reset an agent's spent-to-date while `verify` still reported clean.
That is exactly the right reasoning.

Tail truncation is honestly documented as undetectable, with `--expect-head` as
the mitigation. The `verify` command prints the head hash and tells the operator
to record it externally.

### 2.3 Approval queue - `bouncer/approvals.py` (item 4, mechanism) - DONE

SQLite-backed, filtered by role, resolved by role. Two properties are enforced
and both matter:

- **Symmetric authority** - approve and deny run the identical role check.
  Asymmetry would let anyone veto spending, which is its own denial of service.
- **Once-only resolution** - resolving takes the row under a write lock and
  refuses if it is no longer `PENDING`.

Timeouts resolve to `TIMED_OUT`, never to approved. Roles are normalized to
lowercase at policy-load time (`ApprovalRule._normalize_role`), so the
case-mismatch bug I went looking for between `enqueue` and `resolve` is not
present.

### 2.4 Supporting machinery that works

- **Canonical serialization** (`canonical.py`) - rejects `float` outright,
  emits `Decimal` as normalized strings, fixed-width UTC timestamps via
  `strftime`. The fixed width is load-bearing: `spend_history` round-trips
  timestamps through `strptime`, which would crash on a zero-microsecond value
  if `isoformat()` had been used.
- **Mandates** (`mandate.py`) - scoped, TTL'd, replay-protected. Nonce
  uniqueness rests on an atomic primary-key insert, not a check-then-write.
  Signature is verified against raw bytes *before* parsing them.
- **Deny-by-default policy sourcing** (`sources.py`) - a source never raises;
  it returns a policy carrying an error, which the engine turns into a deny.
- **CLI** - 12 commands, distinct exit codes (`2` denied, `3` tampered) so
  monitoring can page on tamper specifically.

---

## 3. What exists but is incomplete, stubbed, or wrong

### 3.1 CONFIRMED CRASH: any currency symbol longer than 3 characters

**This is a real bug and the most serious finding in this audit.** Verified by
execution, not by reading.

`PaymentIntent.currency` accepts 3-12 characters, and the docstring explicitly
supports token symbols: *"An ISO 4217 code (USD) or a token symbol for crypto
rails (USDC)."* `Policy.currency` accepts the same range. The x402 adapter ships
a decimals table keyed on `USDC`, `USDT`, `DAI`, `PYUSD`.

But `MandateClaims.currency` is `Field(min_length=3, max_length=3)`.

So a USDC-denominated policy validates, the engine returns `ALLOW`, and then
mandate issuance raises:

```
ISSUE_MANDATE FAILED: ValidationError
  currency: String should have at most 3 characters
  [input_value='USDC']
```

Two consequences, the second worse than the first:

1. `ValidationError` is not a `BouncerError`, so `cli.main()`'s handler does not
   catch it. The CLI tracebacks; the API returns 500.
2. In `Enforcer.authorize()`, `issue_mandate()` is called **before**
   `audit.append()`. The crash therefore happens *after* a decision is made and
   *before* it is recorded. **The decision is never logged.** That directly
   contradicts `enforcement.py`'s own stated threat model: *"every branch here
   ends in an audit entry, including the failure branches."*

No test covers a non-USD currency end-to-end, which is why 223 green tests did
not catch it.

### 3.2 Item 1 - models are 2 of 4 as specified

| Spec name | Reality |
| --- | --- |
| `Policy` | pydantic, `bouncer/policy.py` |
| `Decision` | pydantic, `bouncer/models.py` |
| `Transaction` | does not exist - the model is `PaymentIntent` |
| `AuditEntry` | exists but is a **SQLAlchemy ORM model**, not pydantic |

`PaymentIntent` vs `Transaction` is a naming difference only; the fields are
what you would want. I would keep `PaymentIntent` - it is the more accurate name
(bouncer authorizes an *intent*; it never sees a settled transaction) and it is
referenced across 15 files. Renaming buys nothing.

`AuditEntry` not being pydantic is a genuine structural gap if you want the
schema to be export-ready, since the shape currently lives in a `to_dict()`
method rather than a declared model.

### 3.3 Item 3 - right mechanism, wrong storage

Spec says **append-only JSONL**. Implementation is SQLite. Hash-chaining and
signing are correct either way; the medium is what differs. See 7.1 for why
this is not a small change.

### 3.4 Item 4 - `approver_role` is unconstrained free text

Spec names three roles: `manager | finance | cfo`. `ApprovalRule.approver_role`
is `str(min_length=1, max_length=64)` - any string is accepted.

I would push back on constraining this. An enum means a fourth role requires a
code change and a release, whereas the current design lets an operator write
`approver_role: head_of_eng` in YAML. The role is explicitly documented as a
workflow guardrail rather than a security control, so an open set costs nothing
in safety. **Flagging as a spec deviation, recommending you keep the deviation.**

### 3.5 Item 5 - `POST /approvals/{id}/resolve` does not exist

`api.py:251` is explicit: *"List approvals awaiting a human. Resolution happens
via the CLI."* There is `GET /pending` and nothing else. `Enforcer.resolve()`
already exists and is exercised by the CLI, so this is an endpoint wrapper, not
new logic.

### 3.6 Item 7 - the example is adjacent to what was asked

`examples/demo.py` (362 lines) is a polished six-scenario walkthrough that ends
by tampering with a row to show the chain break. It runs, and it is genuinely
good demo material.

It is not what item 7 asks for. It is a **scripted sequence of six unrelated
purchases**, not *"a toy agent with a $50 budget that tries to overspend and
gets blocked."* Specifically:

- There is no budget. `examples/policy.yaml` sets a $50 *per-transaction cap*
  and a separate $100/30d rolling ceiling. A "$50 budget" is a cumulative
  ceiling - that is `rolling_windows: [{amount: 50.00, window: 30d}]`.
- It calls `Enforcer` directly. It cannot demonstrate item 6's client lib,
  because item 6 does not exist.

### 3.7 The forward proxy blocks the event loop

`ProxyServer._handle` is `async def` but calls `self._authorize(...)`
synchronously at `forward_proxy.py:233`. That call takes the decision lock and
commits to SQLite under `synchronous=FULL` (an fsync), and can wait up to the
30s `busy_timeout`. Every other proxied connection stalls behind it.

This is the same defect class already fixed in `api.py` (which now uses
`asyncio.to_thread`); the proxy never got the same treatment. Only worth fixing
if the proxy survives the section 7 scope decision.

### 3.8 Minor

- `cli.py:298` - `count = export_jsonl(log, sys.stdout)` assigns a variable that
  is never read. Dead assignment.
- 7 files have uncommitted changes (Windows portability fixes, the event-loop
  fix, docs). Commit before starting v0.1 work so the baseline is clean.

---

## 4. What's missing entirely

### 4.1 Item 6 - the client library. Nothing exists.

`grep` for `__enter__`, `__exit__`, `contextmanager` across `bouncer/` and
`examples/` returns **nothing**. There is no client library and no context
manager. This is the single largest missing piece of v0.1, and it is the piece
that determines whether the library is pleasant to use, because it is the only
part an application developer actually touches.

It is also the reason item 7 cannot be built as specified - the toy agent is
supposed to *use* this.

Design question you need to answer, since it changes the implementation: on
`DENY`, should the context manager **raise** or **return a decision object**?
Raising composes better with agent code (`try/except` around a spend), and it
makes it impossible to ignore a denial by forgetting to check a return value -
which matters here, since an ignored denial is an unenforced policy. That is my
recommendation, but it is your call.

There is a second question: does the context manager call the **HTTP API** or
the **in-process `Enforcer`**? The API is the sidecar story; in-process is the
library story. The scope line says "Client lib... wrapping an agent's spend
call", and the project is described as "library + local sidecar", so I would
support in-process first and leave an HTTP transport as a swappable backend.

### 4.2 Item 5 - the resolve endpoint (see 3.5)

---

## 5. Present but out of scope for v0.1

Ordered by how confident I am that it should go.

### 5.1 JSONL exporters - delete, but read 7.1 first

Spec: *"Keep the audit schema export-ready but build no exporters."* SIEM
exporters are named as out of scope.

Present: `export_jsonl()`, `verify_exported()`, `_write_jsonl()`
(`audit.py:418-496`), the `bouncer export` CLI command, and its tests.

**Caveat:** if you switch the audit log to JSONL per item 3, these do not get
deleted - they collapse into the storage layer, and `verify_exported()` becomes
the primary `verify` implementation. Do not delete this until 7.1 is decided.

### 5.2 Forward proxy - 786 lines, not in the v0.1 list

`bouncer/forward_proxy.py` (445 lines) + `tests/test_proxy.py` (341 lines),
plus `evaluate_tunnel()` in `engine.py` (~100 lines), the `TUNNEL_PERMITTED` /
`TUNNEL_NOT_PERMITTED` reason codes, `Enforcer.authorize_tunnel()`, and the
`bouncer proxy` CLI command.

The v0.1 scope lists a FastAPI sidecar with two endpoints. It does not mention a
proxy. **But the blueprint's definition of done is entirely proxy-based**
("points their agent's `HTTP_PROXY` at bouncer"), and the README's quickstart
and architecture diagram both lead with it. Deleting it is a strategic change,
not a cleanup. See 7.2.

### 5.3 x402 adapter - delete

Scope: *"Payment rail integration = Stripe test mode only."* `adapters/x402.py`
(129 lines) is a second rail. The adapter seam is the valuable part and it
should stay; x402 is the thing that is out of scope.

Keep `generic.py` regardless - it is what `POST /authorize` uses to parse an
explicit JSON intent, so it is load-bearing for item 5.

### 5.4 Mandates - not in the v0.1 list at all. Decide explicitly.

`mandate.py` (345 lines) + `tests/test_mandate.py` (310 lines) +
`POST /mandates/verify` + the `NonceStore` + `bouncer purge`.

Mandates appear nowhere in the seven items. But they are the artifact
`POST /authorize` returns on allow, they are in the README's architecture
diagram, and "signed mandate" is in the one-sentence pitch. Deleting them would
reduce `/authorize` to returning a bare verdict.

I do not think you mean to delete this - I think item 5 assumes it. Confirming
in 7.3.

---

## 6. Cost summary

| Action | Lines affected |
| --- | --- |
| Fix currency crash | ~5 |
| Add resolve endpoint | ~30 |
| Add client lib + context manager | ~150 new |
| Rewrite item 7 as a budget-driven toy agent | ~120 rewrite |
| Make `AuditEntry` pydantic | ~60 |
| Convert audit store to JSONL | ~300 rewrite + knock-on (7.1) |
| Delete proxy + tunnel support | -900 |
| Delete x402 | -250 (incl. tests) |
| Delete exporters | -150 (unless 7.1 says JSONL) |

---

## 7. Decisions I need from you before touching anything

These are blocking because each one changes what the checklist in section 8
says.

### 7.1 Audit log: JSONL or SQLite?

Item 3 says append-only JSONL. The repo uses SQLite. **This is not a drop-in
swap, and the reason is not obvious:**

`Enforcer.authorize()` calls `audit.spend_history()` on **every single
authorization** to evaluate rolling windows. That is an indexed SQL query today
(`ix_audit_agent_outcome_ts` on `agent_id, outcome, ts`). If the audit log
becomes a flat JSONL file, every authorization must either scan the whole file
or be served from a separate index you now have to build and keep consistent
with the file.

So "switch to JSONL" actually means one of:

- **(a)** JSONL is the log, and rolling-window spend history moves to its own
  SQLite table - two stores, and they must not disagree;
- **(b)** JSONL is the log and is scanned per authorization - simple and
  correct, but O(n) per decision and it degrades as the log grows;
- **(c)** keep SQLite, and treat "append-only JSONL" as satisfied by the
  existing `export_jsonl()` - which is what the blueprint originally intended.

I recommend **(c)**, and if not (c) then (b) for v0.1 with (a) deferred. SQLite
*is* an append-only store here - nothing in the codebase issues an UPDATE or
DELETE against `audit_entries` - and it gives you the spend-history index for
free. But this is your architectural call, not mine.

### 7.2 Forward proxy: delete, or keep?

It is 786 lines outside your v0.1 list, but it is the blueprint's entire
definition of done and the README's headline usage. Deleting it makes bouncer an
API you call deliberately rather than an interception point - a real change to
what the product *is*.

### 7.3 Mandates: keep? (I assume yes)

Confirm they are simply implied by item 5 rather than dropped.

### 7.4 `approver_role`: constrain to three, or leave open?

Recommend leaving open (3.4).

---

## 8. Checklist to v0.1

Ordered so each item leaves the tree compiling, `mypy --strict` clean, and the
suite green. Items marked LOCKED are blocked on a section 7 decision.

### Phase 0 - clean baseline

- [x] Commit the 7 uncommitted working-tree changes so v0.1 work starts from a
      known state
- [x] Confirm baseline: `pytest` green, `mypy --strict` clean

### Phase 1 - correctness (no scope change, do this regardless of section 7)

- [x] Fix the currency-width crash (3.1): widen `MandateClaims.currency` to
      match `PaymentIntent.currency` (3-12)
- [x] Add a regression test issuing and verifying a `USDC` mandate end to end
- [x] Reorder `Enforcer.authorize()` so the audit row is written before any
      branch that can raise, honouring "every branch ends in an audit entry"
- [x] Add a test asserting a decision is logged even when mandate minting fails
- [ ] Remove the dead `count` assignment at `cli.py:298`

### Phase 2 - close the item-5 gap

- [ ] Add `POST /approvals/{id}/resolve` taking `{role, approve, note}`,
      delegating to the existing `Enforcer.resolve()`
- [ ] Map `RoleMismatch` to 403, `UnknownApproval` to 404
- [ ] Tests: right role approves, wrong role is refused, resolving twice fails,
      deny path is symmetric with approve

### Phase 3 - item 6, the client library (largest new build)

- [x] Decide raise-vs-return and in-process-vs-HTTP (4.1)
- [x] Add `bouncer/client.py` with a `spend()` context manager wrapping
      `Enforcer.authorize()`
- [x] Handle all three outcomes: allow yields the mandate, deny raises,
      `REQUIRE_APPROVAL` either blocks to the timeout or raises immediately
      depending on a `wait=` flag
- [x] Guarantee the context manager cannot silently swallow a denial
- [x] Export it from `bouncer/__init__.py`
- [x] Tests for each outcome, including the approval-timeout-denies path

### Phase 4 - item 7, the toy agent

- [ ] Change the example policy to a genuine cumulative budget:
      `rolling_windows: [{amount: 50.00, window: 30d}]`
- [ ] Write a toy agent that loops purchases through the Phase-3 context manager
      until the $50 budget blocks it
- [ ] Assert in a test that it is blocked at the right cumulative point, not
      merely that it prints something

### Phase 5 - item 1, model conformance

- [ ] Add a pydantic `AuditEntry` model as the declared wire schema; keep the
      SQLAlchemy row as storage and map between them
- [ ] Point `to_dict()` / export at the pydantic model so the schema has one
      definition
- [ ] Decide `Transaction` vs `PaymentIntent` (recommend keeping
      `PaymentIntent`; if renaming, it touches 15 files)

### Phase 6 - LOCKED scope deletions (blocked on section 7)

- [ ] LOCKED 7.2: delete `forward_proxy.py`, `tests/test_proxy.py`,
      `evaluate_tunnel()`, `authorize_tunnel()`, the two `TUNNEL_*` reason
      codes, and the `bouncer proxy` command - or keep and fix its event-loop
      blocking (3.7)
- [ ] Delete `adapters/x402.py`, its tests, and its `DEFAULT_ADAPTERS` entry
- [ ] LOCKED 7.1: delete the exporters - **only if** the audit log stays SQLite
- [ ] LOCKED 7.1: if JSONL wins, rewrite the audit store and re-home
      `spend_history`
- [ ] Prune README, ROADMAP, and the architecture diagram to match whatever
      survives

### Phase 7 - final gate

- [ ] Full suite green, `mypy --strict` clean
- [ ] `bouncer init && bouncer check` works from a clean home
- [ ] Toy agent demo runs and is blocked at $50
- [ ] README's stated test count and quickstart match reality
