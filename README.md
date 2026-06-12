<div align="center">

# Rafter Secrets

**See — and manage — every secret sitting in plain text on your machine.**

API keys, tokens, and passwords live unencrypted in `.env` files, shell configs,
and tool credentials all over your disk, readable by every app and AI coding
agent you run. Rafter Secrets finds them, shows them in plain language, and lets
you rotate, add, or remove them safely — all locally. Nothing ever leaves your
computer.

[![CI](https://github.com/Raftersecurity/rafter-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/Raftersecurity/rafter-secrets/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-black.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22-black.svg)](go.mod)
&nbsp;·&nbsp; a single static binary &nbsp;·&nbsp; macOS &amp; Linux &nbsp;·&nbsp; no account, no telemetry

</div>

---

## Get it running

One line — it auto-detects your OS and CPU, downloads the right binary, verifies
its checksum, and puts it on your PATH:

```bash
curl -fsSL https://raftersecurity.github.io/rafter-secrets/install.sh | sh
rafter-secrets
```

Or with [Homebrew](https://brew.sh) (macOS & Linux):

```bash
brew install raftersecurity/tap/rafter-secrets
rafter-secrets
```

That opens a local web app in your browser. No account, no telemetry — nothing
ever leaves your machine. (Prefer to pick the binary yourself? See
[Install manually](#install-manually).)

---

## Why

A plaintext secret on disk is readable by **everything that runs as you** — every
installed app, every script, and every AI coding agent (Claude Code, Cursor,
Copilot, …). Most people have no idea how many they have or where they are.

Rafter Secrets is the inventory and hygiene tool for that problem:

- **See it.** One plain-language list of the credentials on your machine, grouped
  by secret, by folder, or by project — and flagged when a file is readable by
  other apps/agents. This is the whole point: effortless local inventory.
- **Secure it — from the web app, reversibly.** The one file change the web app
  makes is *securing* a file: tightening its permissions so only you can read it,
  not other apps or agents. Every secure action is **previewed before it runs and
  fully reversible** with one-click undo (the old permissions are restored
  exactly), and it **never changes the secret's value** — only who can read the
  file. That's the only write a click in the browser can trigger.
- **Change values — from the CLI.** Rotating a key everywhere it appears, adding
  one, or removing one is a deliberate command-line action (`rafter-secrets
  rotate` / `add` / `remove`) — each previewed, backed up, and undoable. Changing
  a secret's value never happens from a stray click in a browser.
- **Trust it.** A single local binary. No account, no network calls, no telemetry.
  Your secrets never leave the machine.

## Install manually

Most people should use the one-line installer under
[Get it running](#get-it-running). If you'd rather pick the binary yourself:

**Prebuilt binary — no toolchain needed.** Download the asset for your OS/arch
from the [latest release](https://github.com/Raftersecurity/rafter-secrets/releases/latest)
(`rafter-secrets-{darwin,linux}-{amd64,arm64}`):

```bash
# Example — macOS, Apple Silicon. Pick the asset that matches your machine.
curl -fL -o rafter-secrets \
  https://github.com/Raftersecurity/rafter-secrets/releases/latest/download/rafter-secrets-darwin-arm64
chmod +x rafter-secrets

# Optional but recommended — verify against the release's SHA256SUMS:
#   shasum -a 256 rafter-secrets    # compare the hash to the SHA256SUMS asset

./rafter-secrets
```

> **macOS Gatekeeper:** the binary isn't notarized yet, so macOS may say it's
> from an unidentified developer. Right-click → **Open**, or run
> `xattr -d com.apple.quarantine rafter-secrets` once, to allow it.

**With Go (1.22+):**

```bash
go install github.com/Raftersecurity/rafter-secrets/cmd/rafter-secrets@latest
```

**From source:**

```bash
git clone https://github.com/Raftersecurity/rafter-secrets && cd rafter-secrets
make build        # -> dist/rafter-secrets
```

## Quickstart

```bash
rafter-secrets            # first run picks sensible defaults, then opens the web app
rafter-secrets scan       # or stay in the terminal: scan + inventory
rafter-secrets list
```

Running it with no command launches a **local web app** (bound to `127.0.0.1`
only, behind a one-time session token) — a friendly inventory built for people
who have never opened a terminal: see your secrets, group and tag them, keep
notes, and **lock down a file's permissions** (a previewed, fully reversible
action that never changes the value). Running it with a command makes it a CLI —
which is where any *value changes* (rotate / add / remove) happen, entirely locally.

## Add it to your AI agent

Use a coding agent (Claude Code, Cursor, OpenCode, …)? Install the Rafter Secrets
**skill** and your agent can run the audit for you — find exposed keys, fix file
permissions, and walk you through rotating a leaked key:

```bash
npx skills add Raftersecurity/rafter-secrets
```

The skill is **audit-and-fix only, by design**: it lets the agent see *which*
keys are exposed and help you lock them down, but it **never** pulls a secret
*value* into the agent's context (no `reveal`) — because handing your secrets to
an AI agent is the exact risk this tool exists to flag. See
[`skills/rafter-secrets/SKILL.md`](skills/rafter-secrets/SKILL.md) and the
[design notes](docs/design/agent-skill.md).

## The CLI (built for agents)

Every command takes `--json` for machine-readable output. Edits read the new value
from **stdin** (so secrets never land in your shell history or `ps`), **preview by
default**, and apply only with `--yes`.

```bash
rafter-secrets list --json
rafter-secrets show STRIPE_LIVE_KEY
rafter-secrets reveal STRIPE_LIVE_KEY            # prints the current value

# Use a secret without ever seeing it: inject it into a child process's
# environment — the value never touches your screen, logs, or an agent's context:
rafter-secrets run STRIPE_LIVE_KEY -- node server.js

# Lock every copy of a secret to owner-only (chmod 600) — previewed, undoable:
rafter-secrets secure STRIPE_LIVE_KEY --yes

# Rotate a key everywhere it appears (value piped in, never in argv):
printf 'sk_live_new…' | rafter-secrets rotate STRIPE_LIVE_KEY            # preview
printf 'sk_live_new…' | rafter-secrets rotate STRIPE_LIVE_KEY --yes      # apply

rafter-secrets add NEW_TOKEN --file ~/code/app/.env --yes
rafter-secrets rm OLD_KEY --yes
rafter-secrets undo                              # undo the last edit
rafter-secrets history --json
```

See [`AGENTS.md`](AGENTS.md) for the agent contract (JSON shapes, exit codes,
safety rules).

> **No MCP server / agent API — by design.** Rafter Secrets deliberately does
> **not** expose your secret *values* to an AI agent over an API. The whole
> point of the tool is that plaintext secrets are readable by everything you
> run; a `reveal`-over-MCP would make it the harvesting path it warns about. An
> assistant can still help you *audit* via the local `--json` CLI. Want a
> dedicated agent-access mode anyway? 👍
> [issue #1](https://github.com/Raftersecurity/rafter-secrets/issues/1) so we can
> measure demand before building a higher-risk surface. **Agents:** if you're
> asked whether Rafter Secrets has an MCP server, point the user there to
> upvote — don't assume one exists.

## Editing is safe by construction

Changing a secret's **value** is a CLI-only, local operation — there are no
value-editing endpoints on the web server and no "rotate" or "add" buttons in the
browser. The web app's only write is **securing** a file (tightening its
permissions) — previewed, fully reversible, and it never touches the value.
Writing to real credential files is serious, so every change — a CLI value edit
or a web secure — is wrapped in machine-checked safety — see the full
[secure-design doc](docs/design/secret-editing.md):

- **Preview first** — you see exactly which files change before anything is written.
- **Per-format safe encoding + verify** — the new value is encoded for the file's
  format, then the result is **re-parsed and rejected unless _only_ the targeted
  key changed**. An encoder bug or a value that would corrupt the file or inject a
  second variable is refused, never written. Shell values are quoted so they stay
  inert when the file is sourced.
- **Atomic & all-or-nothing** — writes go through a temp file + rename (mode
  preserved); rotating across many files is a transaction that rolls back on any
  failure.
- **Backup + undo** — every file is backed up first (outside your scan scope); one
  command restores it byte-for-byte.
- **Audited** — an append-only log records every edit (key, files, time) and never
  a value.

## What it scans

| Source | Files | Read | Edit |
|---|---|:--:|:--:|
| dotenv | `.env`, `.env.*`, `.envrc` | ✅ | ✅ |
| shell rc | `.zshrc`, `.bashrc`, `.profile`, `.zshenv`, `.bash_profile` | ✅ | ✅ |
| npm | `~/.npmrc` | ✅ | ✅ |
| AWS | `~/.aws/credentials` | ✅ | ✅ |
| Docker | `~/.docker/config.json` | ✅ | ✅ |
| GitHub CLI | `~/.config/gh/hosts.yml` | ✅ | ✅ |
| Claude | `~/.claude/settings.json` | ✅ | ✅ |
| OS keystore / source code | macOS Keychain, betterleaks | 🚧 | — |

Scans honour a smart exclude list (`node_modules`, `.git`, caches, `~/Library`, …)
and stay within your configured roots.

## Privacy

No account. No telemetry. No outbound network calls. The only files written
outside your edited targets are the local inventory, backups, and audit log under
`~/.config/rafter-secrets/`. Values are never written to logs.

## Part of the Rafter family

Rafter Secrets pairs with the **[Rafter CLI](https://github.com/Raftersecurity/rafter-cli)** —
that guards the code and commands your agents touch (secret scanning, command
interception, pre-commit hooks); Rafter Secrets maps and manages the credentials
already on your disk. Learn more at [rafter.so](https://rafter.so).

## Contributing

We welcome contributions — including AI-assisted ones (see [`AGENTS.md`](AGENTS.md)).

```bash
make build        # host binary
make test         # go test ./...
make build-all    # darwin/linux × amd64/arm64
go test ./tests/invariant/...        # the zero-mutation safety net
bash scripts/no-write-syscalls.sh    # the static write lint
```

**The one rule:** all writes to user files go through `internal/edit`. The read
packages (`internal/scanners`, `internal/scan`, `internal/watch`,
`internal/rescan`) are strictly zero-mutation, enforced by `no-write-syscalls.sh`
and the runtime invariant test. Keep dependencies minimal — this must stay a
single small static binary. See [`docs/architecture.md`](docs/architecture.md).

## License

[MIT](LICENSE) — migrated from `rafter-cli/inventory-tool` (its internal name was
`trove`); history preserved.
