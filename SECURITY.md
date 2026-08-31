# Security Policy

bouncer decides whether an AI agent is allowed to spend money, and signs the
record of that decision. A flaw in it is a flaw in someone's spending controls,
so vulnerability reports are welcome and taken seriously.

**bouncer has not been independently security audited.** Treat it accordingly:
see [Limits of the guarantee](#limits-of-the-guarantee) below and the threat
model in [README.md](README.md).

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes — current development line |
| < 0.1 | No |

This is pre-1.0 software. Fixes land on `main`; there is no backport branch.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report privately through GitHub:

1. Go to the [Security tab](https://github.com/nmaltese13/bouncer/security/advisories/new).
2. Click **Report a vulnerability**.
3. Describe the issue and how to reproduce it.

That channel is private between you and the maintainer, and it needs no email
address from either side.

If GitHub is unavailable to you, open a public issue titled *"security contact
request"* containing **no details of the vulnerability**, and you will be given
a private channel.

### What to include

The more of this you can supply, the faster it gets fixed:

- A description of the flaw and what an attacker gains from it.
- Steps to reproduce, ideally a failing test or a short script.
- The commit or version you tested.
- Your assessment of severity, and any suggested fix.

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | 3 working days |
| Initial assessment and severity call | 10 working days |
| Fix or documented mitigation for confirmed high-severity issues | 30 days |

This is a single-maintainer project, not a funded security team; these are
good-faith targets rather than a contractual SLA. You will be told if something
is going to take longer.

Credit is given in the advisory and release notes unless you ask otherwise.

## What counts as a vulnerability

Squarely in scope — these break a stated guarantee:

- **Policy bypass.** Any way to get an `ALLOW` decision, or a valid mandate,
  for a transaction the policy denies.
- **Audit forgery.** Altering, reordering, inserting or removing log entries
  without `bouncer verify` detecting it.
- **Mandate abuse.** Replaying a spent mandate, using one outside its merchant
  or amount scope, or using one past its expiry.
- **Approval bypass.** Resolving a queued approval without the required role,
  resolving one twice, or a timeout resolving to allow rather than deny.
- **Fail-open behaviour.** Any input — malformed policy, unparseable traffic,
  a crash mid-decision — that results in spending being permitted or a decision
  going unrecorded.

Fail-open bugs are the highest severity class in this project, above anything
that merely fails loudly.

## What does not count

These are documented properties, not defects. Reporting them is not useful.

- **An agent that ignores bouncer.** It is a policy *decision* point, not a
  sandbox. An agent with unrestricted network egress can route around it
  entirely. Containment requires egress control at the network or container
  layer.
- **CLI roles are not authenticated.** `--role finance` is an assertion by
  whoever holds shell access. v1 assumes one trusted operator on a trusted
  machine; anyone who can run the CLI can approve anything. This is a workflow
  guardrail, not an access control.
- **The API authenticates nobody.** `agent_id` is an assertion by the caller.
  Bind to loopback and treat network reachability as the boundary.
- **Tail truncation of the audit log.** Deleting the most recent N rows leaves
  an internally consistent chain. Mitigate by recording the head hash
  externally and passing it back with `bouncer verify --expect-head`.
- **A compromised operator key.** The signature proves a record was not altered
  after writing. It proves nothing about an operator who was already
  compromised at write time.
- **Unenforced CONNECT tunnels.** With `--allow-connect`, traffic inside a TLS
  tunnel is explicitly not policed.

## Key management: the writer holds the signing key

This is the most important limitation in the project, so it gets its own
section rather than a bullet.

**The process that writes the audit log is the same process that signs it.**
`Enforcer` loads `operator.pem` at startup and signs every row it appends. There
is no separation between the component that makes a decision and the component
that attests to it.

What that means precisely:

- A signature proves a row was produced by *something holding the key*. It does
  **not** prove the row is honest.
- Anyone who can read `operator.pem` can author a complete, internally
  consistent, correctly-signed history that never happened — and `bouncer
  verify` will report it as intact, because it *is* intact. Verification proves
  the log was not altered after writing; it cannot reach behind the writer.
- Compromise of the host is therefore compromise of the evidence. The audit log
  defends against later tampering, not against a bad writer at write time.

Anyone evaluating this as an audit control should understand that the security
of the whole log reduces to the security of one file on one machine.

### What reduces the exposure today

- **Anchor the head hash externally.** `bouncer verify` prints the head; record
  it somewhere bouncer cannot write, and pass it back with `--expect-head`. A
  forged history will not match an anchor taken before the forgery. This is the
  only mitigation that works against a writer who already holds the key, and it
  is worth automating into whatever you already trust — a monitoring system, a
  second host, a chat channel, a printout.
- **Protect the key file.** `0600` on POSIX. On Windows the mode is advisory and
  the key inherits the directory ACL — see the hardening checklist.
- **Keep the blast radius small.** Loopback binding, egress control, and a host
  that runs bouncer and little else.

### The paths out, and why they are not built

Named so the gap is a decision rather than an oversight:

| Approach | What it buys | Status |
| --- | --- | --- |
| **Hardware-backed key** (TPM, HSM, YubiKey) | The key cannot be copied off the host. An attacker with code execution can still *use* it as a signing oracle while they retain access, but cannot walk away with the ability to forge history offline or after eviction. | **Available** — see below. |
| **Separate signing service** | The enforcer submits rows to a signer it cannot read the key from. Compromising the decision path no longer yields forging power. | Adds a second process and an IPC boundary to a tool whose whole premise is a single local process. Worth it only alongside a multi-host deployment. |
| **Append to an external collector** | Rows leave the host as they are written, so a later local forgery contradicts a copy the attacker never controlled. | This is the tail-truncation fix as well, and it is the strongest option. It requires a network dependency in the decision path, which v1 deliberately does not have. |
| **Transparency-log anchoring** | Third parties can detect a rewritten history. | Meaningful only with an external witness, which reduces to the option above. |

The remaining three are absent because v1 assumes a single trusted operator on a
trusted machine, and adding them without that assumption changing would be
security theatre.

### Keeping the key out of this process

The audit log and the mandate issuer depend on a `Signer` protocol — `key_id`,
`verify_key`, `sign` — not on a key object. Point bouncer at a command and the
private key never enters the process:

```bash
export BOUNCER_SIGNER_COMMAND="/usr/local/bin/sign-with-yubikey"
export BOUNCER_PUBLIC_KEY="$HOME/.bouncer/operator.pub"
bouncer serve
```

The command reads the message to sign on stdin and writes the detached Ed25519
signature to stdout, as 64 raw bytes or as base64. That contract is small enough
to wrap `pkcs11-tool`, a TPM helper, a hardware-token agent, or a signing
service on a socket.

Two properties worth knowing:

- **The public key is required, not inferred.** bouncer needs it to attribute
  audit rows and to check what comes back. Deriving it from the signer's first
  response would mean trusting an unverified signature to establish the identity
  every later signature is checked against.
- **Every signature is verified before it is recorded.** A misconfigured signer
  that emits garbage fails loudly on the first attempt rather than filling the
  log with rows that will never verify — damage that would otherwise surface
  only at the next `bouncer verify`, long after the evidence was needed.

This narrows the blast radius; it does not eliminate it. An attacker with code
execution on the host can still ask the signer to sign anything for as long as
they keep that access. What they cannot do is take the key with them.

## Limits of the guarantee

Stated plainly, because security software that overclaims is worse than none:

- **bouncer never custodies funds.** It emits a signed authorization; something
  else settles the payment. It cannot claw back, freeze, or reverse anything.
- **bouncer cannot stop an agent that bypasses it.** Enforcement lives in your
  network, not in this process.
- **bouncer does not replace your payment provider's controls.** It is a layer
  in front of them, not a substitute for card limits, provider-side fraud
  rules, or spending caps configured with your processor. Run both.
- **The Stripe adapter refuses live-mode keys on purpose**, because this code
  has not been audited and should not stand between an agent and real money.

## Hardening checklist for operators

- Bind the API and proxy to loopback only.
- Put bouncer behind egress control so it is the only route out.
- Record `bouncer verify --expect-head` output somewhere bouncer cannot write.
- Back up `operator.pem`, and protect it — on POSIX it is written `0600`; on
  Windows it inherits the directory ACL and mode bits do not apply.
- Keep provider-side limits configured independently.
