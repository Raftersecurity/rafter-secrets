# Agent skill (`npx skills add Raftersecurity/rafter-secrets`)

Secure-design notes for shipping a `SKILL.md` (the [vercel-labs/skills][skills]
format) that lets an AI coding agent install, run, and act on a user's
plaintext-secret inventory.

The skill is **markdown instructions, not executable code** — but it grants an
agent a *capability* over the most sensitive thing on the machine, so it gets
the same design scrutiny as an API surface.

[skills]: https://github.com/vercel-labs/skills

## The one rule this skill inherits

Rafter Secrets has **no agent API, by design** (see README). The reason is the
tool's entire thesis: plaintext secrets are dangerous precisely because
*everything you run can read them* — and an AI agent is one of those things. A
skill that pulled secret **values** into the agent's context would *be* the
harvesting path the product warns about.

So the skill is **audit-and-fix, never reveal**:

| Agent may | Agent must NOT |
|---|---|
| `rafter-secrets list --json` (keys, paths, projects, stale — **no values**) | `rafter-secrets reveal …` (returns the value) — forbidden |
| `rafter-secrets show <key>` (record metadata — no value) | `cat`/read the secret file contents to "see the value" |
| `chmod 600 <path>` to fix an exposure (with user confirm) | accept, echo, or store a secret value (rotation is stdin-only, user-typed) |
| build the `rafter-secrets rotate KEY` command with a **placeholder** | put a secret value in argv (`--value`, here-strings) — leaks to `ps`/history |

`list`/`show` are safe because the JSON they emit never contains values (AGENTS.md
contract). `reveal` is the only value-bearing command, and the skill names it as
off-limits for autonomous use.

## Data-flow & trust boundaries

```
[scanned secret files] ──(paths, key names; NEVER values)──▶ rafter-secrets CLI
        │                                                          │
        │                                              --json (no values)
        ▼                                                          ▼
   the value lives here ─────── X (boundary: never crossed) ──▶ [AI agent context]
                                                                   │
                                              constructs commands; runs chmod
                                                                   ▼
                                                          [user's shell / vendor site]
```

Boundaries and the control at each:

- **secret value ↔ agent context** — the load-bearing boundary. Control: the
  skill never invokes a value-bearing command; rotation values are entered by
  the user via stdin, never seen by the agent.
- **inventory data ↔ agent reasoning** — key names, paths, and user notes are
  *untrusted input*, not instructions. Control: the skill tells the agent to
  treat them as data (prompt-injection guard; a file named
  `IGNORE_PREVIOUS.env` is not a command).
- **agent ↔ user's filesystem** — `chmod` and any state change require explicit
  user confirmation and echo the exact path first.

## STRIDE (the productive subset)

- **Information disclosure (primary).** A secret value reaching the agent =
  the bug. Mitigated by the audit-and-fix rule above. Residual: a user can still
  run `reveal` themselves — the skill declines to do it *for* them and explains
  why, but can't stop a human. Accepted.
- **Elevation / excessive agency.** The capability the skill grants is the blast
  radius. Tools it leans on: read-only `list`/`show` (low stakes) and two write
  actions — `chmod` (perms only, never contents) and *guiding* `rotate` (value
  never handled by the agent). Both writes are confirm-gated. No `rm`, no broad
  `chmod -R`, no edits to file contents.
- **Tampering / prompt injection.** Scanned content (key names, note fields)
  could carry injection. Mitigation: the agent consumes only structured `--json`
  fields and treats every string in it as inert data.
- **Repudiation.** rafter-secrets keeps an append-only audit log of its own
  edits; `chmod` run by the agent is captured in the agent transcript. Adequate
  for a local single-user tool.

## Supply chain — distributing the skill

`npx skills add Raftersecurity/rafter-secrets` clones the repo and copies the
`SKILL.md` into the user's agent dir. Key properties:

- **No install-time execution.** The skill is markdown; there is no
  `postinstall`/`prepare` hook and no code runs at "add" time. (The npm-launcher
  for the *binary*, if we add one later, is a separate decision with its own
  postinstall scrutiny — out of scope here.)
- **Pin the binary's origin.** The skill's install steps must point only at the
  canonical source — `github.com/Raftersecurity/rafter-secrets` /
  `go install …@latest` / official Releases — never an LLM-suggested package
  name (slopsquat bait). The skill says so explicitly.
- **Least-trust install.** Prefer `go install` from the pinned module path or a
  checksummed release binary; the skill does not pipe `curl | sh` from an
  unpinned URL.

## Residual risks (accepted, in writing)

1. A user who *wants* their value can run `reveal` by hand. The skill won't, and
   warns. Accepted — the threat model is accidental/agentic leakage, not a user
   exfiltrating their own secret.
2. `chmod` on a confirmed path could, if the user blind-approves, touch an
   unintended file. Mitigated by echoing the exact rafter-provided command and
   path. Accepted.

## Exit / follow-ups

- SKILL.md authored against these rules → `skills/rafter-secrets/SKILL.md`.
- Ran through `rafter-skill-review` before shipping.
- The "doing walls" (chmod / rotation legibility) are *also* fixed in the
  read-only web UI for non-agent users — guidance only, no server-side mutation,
  so the read-only invariant holds.
