# Rafter Secrets — product vision

> Rafter Secrets is a **local app that manages the secret-bearing files on your
> computer — never the secrets themselves.** It finds the secrets already living
> in your `.env` and config files, tells you which are exposed, helps you secure
> them in place or move them to a proper store, tracks their lifecycle, and
> brokers how your apps and AI agents use them — all without Rafter ever taking
> custody of a single secret value.

This file is the north star. When a feature decision is ambiguous, it should be
resolved in favour of the three load-bearing properties below.

## Three load-bearing properties

1. **It ships and runs locally.** A signed app you install on Mac/Windows/Linux
   (or `brew`). Opening it scans your machine and serves a local web UI
   (`127.0.0.1`, behind a session token), with a CLI for agents/power users. No
   server, no account, nothing leaves the device. It is **not** a SaaS vault.

2. **It manages files and links, not secrets.** Rafter's domain is the
   `.env`/config files and the *references* that point to where a secret really
   belongs. It edits those files; it never copies their values into a
   Rafter-owned datastore.

3. **It handles values transiently, but never holds them.** `rafter-secrets run`
   reads a value to inject it into a subprocess — but that is **read → inject →
   forget**, never persist. *Never owns secrets* = never stores them, never
   keeps them after use.

## What it's for: respect the workflow, flag the leak vectors

Plaintext secrets in `.env` are **not a bug to eradicate** — they're how local
dev and deployment work. Your app needs `STRIPE_KEY` at runtime; `.env` is the
standard mechanism; docker-compose and your deploy read it. "Get the plaintext
off disk" fights the workflow. And `chmod 0600` is marginal: it only stops
*other user accounts*, never the apps and AI agents you run **as yourself** —
those are you.

So Rafter's job is **not** "remove your secrets." It's three things that don't
require eliminating `.env`:

1. **Inventory + hygiene.** See every secret across your files; spot duplicates,
   staleness, what expires when. Valuable on its own, no remediation implied.
2. **Leak vectors** — the specific ways a *legitimately-local* secret escapes the
   device, ranked by real danger:
   - **Committed to git → pushed.** #1. A `.gitignore`'d `.env` is *correct*; a
     committed one is the leak. Rafter flags committed, *proactively* flags
     in-a-repo-but-not-ignored ("one `git add` away"), and green-lights the
     properly-ignored common case. *(shipped)*
   - **Cloud-synced** (`~/Dropbox`, iCloud, OneDrive, …) — a "local" secret
     silently leaving the device. *(planned)*
   - **Agent/tool readable** — the honest fix isn't `chmod`, it's *don't hand raw
     files to the agent*: `run` injection + the skill's never-reveal stance.
   - **Shared / server / backup** — the `chmod` case; real on multi-user boxes,
     marginal on a laptop.
3. **Lifecycle** — expiry, scope, rotation, staleness.

The product is **".env manager + leak radar + lifecycle"**, not "vault nag." The
move-to-a-store path (rung 2 below) is an **opt-in for the subset of secrets you
decide shouldn't sit in plaintext** (CI, prod-adjacent, a key too sensitive to
leave loose) — *not* the default goal for every `.env`.

## What "never own the vault" means in practice

This is the **auditor-that-hands-off** model. When a secret needs a safer home,
Rafter moves it to the **user's own** store — their macOS Keychain, their
1Password — and rewrites the `.env` to a reference. The keychain/1Password is the
custodian; Rafter is the *mover* and the *manager of the pointer*. "Move it
somewhere safe" never violates "never own secrets" because the destination is
always the user's, never Rafter's.

## The remediation ladder

Ordered by how much it actually helps — and **none of it is mandatory.** Most
secrets are fine where they are (a git-ignored local `.env`).

1. **Lock it down** — `chmod 0600` (owner-only). *Shipped, and the least
   important rung:* it only stops *other user accounts*, not the programs (or
   agents) you run as yourself.
2. **Move it somewhere safe** — *opt-in*, for the subset you choose not to keep
   in plaintext. Relocate the canonical value into the user's store (OS keychain
   default; 1Password/others as adapters), rewrite the file to a reference,
   access via the `run` broker. *Designed; see docs/design/move-to-keychain.md.*

## The honesty rule for file edits

Rafter may **add / remove / rewrite / rotate** any entry in a secrets file — but
**only ever on explicit user action, shown before it happens, and reversible.**
Never autonomously, never silently. The `internal/edit` engine enforces the
machinery (preview, backup, atomic write, verify, audit, undo); the UI enforces
the "previewed + confirmed" gesture.

> Nuance: removing a raw value and replacing it with a reference is only safe if
> the app is then run through the broker — otherwise you've broken it. So
> "remove raw value" and "set up `rafter-secrets run`" are **one flow**, not two
> independent buttons.

## Agents & MCP — the standing decision

Reaffirms commit `22ad73b` ("no MCP/agent API, by design") and the agent skill's
deliberate **never-reveal** stance.

- **No value-read channel for agents.** A local MCP (or any endpoint) that lets
  an agent read secret *values* reopens exactly the risk this product exists to
  flag — *handing your secrets to an AI agent.* Opt-in-per-secret doesn't fix
  that a nontechnical user clicking "allow" doesn't understand they're piping a
  key into a model's context (which may be logged or sent to an API).
- **The agent channel is metadata + actions, never values:** *which secrets
  exist, which are exposed, help me lock these down, walk me through rotating
  this* — which the existing skill already does safely.
- **The elegant resolution is `rafter-secrets run`:** agents (and humans) *use*
  secrets via injection into a subprocess, without the value ever entering
  anything readable or loggable. "Opt-in at the secret level" becomes "which
  programs/agents may have which secrets injected" — an authorization model, not
  a read-the-value endpoint.
- **Do not** put an MCP screen in onboarding (a nontechnical user doesn't know
  what an MCP is, and it contradicts the stance above). Reopen the values
  question only as a deliberate, separate team decision — never via onboarding.

## Status snapshot (2026-06-12)

Shipped toward this vision: local web UI + CLI; first-run walkthrough; classifier
(Secrets vs Environment); exposure detection + in-app **Lock it down** / **Lock
them all down** (rung 1, previewed + reversible); git-committed leak signal +
not-git-ignored detection; **value edits** (rotate / add / remove) with preview,
backup, atomic write, verify, and undo — **CLI and agent only; the web app never
changes a secret's value**, only its permissions; `rafter-secrets run` broker
(inject a secret into a child process's environment, never printing it);
lifecycle annotations (project tags, source/rotate links, expiry, scope); agent
skill (audit-and-fix, never reveal); release pipeline + `npx skills add`; install
via one-line script or Homebrew (`brew install raftersecurity/tap/rafter-secrets`).

Not yet built (beaded): Windows ACL path; move-to-keychain / rewrite-to-reference
(rung 2); signed native installer (.pkg/.dmg). Rung 2 is the higher-trust-tier
work that needs a `rafter-secure-design` walk before any code.
