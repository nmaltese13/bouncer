# Roadmap

Deliberately deferred work. This file exists so that no `TODO` comment ever
ships in committed code.

Nothing here is a commitment. Several items are listed specifically so that the
reasoning against building them now is written down.

## Known gaps in v1

**TLS enforcement.** The forward proxy can only apply spending rules to
plaintext HTTP. A CONNECT tunnel is opaque, so it is denied by default and, with
`--allow-connect`, gated only on an explicit host allowlist. Enforcing HTTPS
payment traffic properly means terminating TLS with a locally-trusted CA and
re-originating the connection. That is a meaningful increase in what a
compromise of bouncer would cost — it would hold a CA key that the agent's
runtime trusts — so it needs a threat model of its own before it is worth
building.

**Tail truncation.** The hash chain cannot detect deletion of the most recent
rows on its own; `--expect-head` shifts that burden to the operator. Closing it
properly means periodically publishing the head hash somewhere bouncer cannot
write — a second machine, a log service, a printed receipt. Anchoring to a
blockchain would also work and is explicitly out of scope.

**Single-process assumption.** Appends serialize through `BEGIN IMMEDIATE` on
one SQLite file, which is correct across threads and processes on one machine
but does not survive being put on a shared filesystem. If bouncer ever needs to
run on two hosts, the audit log needs a real backend and the chain needs a
defined merge rule.

**Key rotation.** Rows record the `key_id` that signed them, so a rotated log is
attributable, but `bouncer verify` checks the whole chain under a single key.
Verifying across a rotation needs a key history and a rotation record in the
chain itself.

**Clock trust.** Decisions and mandate expiry use the local clock. An operator
who can move the clock backwards can revive expired mandates. Fixing this means
a trusted time source, which conflicts with the no-network constraint.

**x402 payment requests carry no asset scale.** The `X-PAYMENT` header an agent
sends after a 402 gives an amount in atomic units but names no decimals, so the
proxy cannot price it and denies it. Resolving this needs an asset registry
mapping contract addresses to decimals — a lookup table that has to be kept
current, which is why it is not in v1. The `/authorize` path is unaffected: a
402 challenge states its own scale.

**Decision throughput.** Read-history / decide / record runs under one process
lock so concurrent requests cannot each spend the same budget. That makes
authorization serial. It is the right trade for a local single-operator tool,
but it is a ceiling, and a per-agent lock would lift it if it ever mattered.

## Wanted, not yet built

- **More rails.** ACP, AP2, UCP and Visa TAP adapters, once any of them has
  enough adoption to be worth the maintenance. The adapter seam exists so this
  is a one-file change.
- **Live-mode Stripe.** Gated on an actual security audit. The adapter refuses
  live keys today, on purpose.
- **Richer categories.** Merchant category codes (MCC) rather than free-text
  categories, so policies can be written against a standard vocabulary.
- **Spend forecasting in `bouncer pending`.** Showing an approver how much
  budget remains in the window would make the approve/deny call better informed.
- **Slack and Teams integrations**, built on the existing webhook rather than
  inside bouncer.

## Explicitly not building

Kept here so the decisions do not get relitigated.

| Not building | Why |
| --- | --- |
| Any blockchain, chain client, or token | Hash-chained SQLite gives tamper-evidence. |
| Fund custody, wallets, balances | The moment we hold money we need licensing. |
| A new wire protocol or spec | We adapt to existing ones. We do not create a fifth. |
| Agent-to-agent negotiation | bouncer authorizes; it does not haggle. |
| A web dashboard | CLI and REST only. |
| Multi-tenant SaaS, auth, billing | Single-operator local process. |
| Authentication for CLI roles | v1 assumes one trusted operator. Adding auth here would imply a guarantee the rest of the model cannot back. |
| LLM calls anywhere in the decision path | Policy decisions must be deterministic, fast, and testable. |
