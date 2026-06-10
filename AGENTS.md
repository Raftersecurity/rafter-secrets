# AGENTS.md

Guidance for AI agents **using** the Rafter Secrets CLI, and for agents
**contributing** to this repo.

## Using the CLI

The binary is agent-first. Prefer it over the web UI.

- **Always pass `--json`.** Every command emits a single JSON object on stdout.
  A top-level `"ok": true|false` tells you success; `"error"` carries the message.
- **Exit codes:** `0` success · `1` error · `2` bad usage / not found.
- **Never put a secret value in argv.** Edit commands read the value from
  **stdin**. `printf '%s' "$VALUE" | rafter-secrets rotate KEY --yes`. (A
  `--value` flag exists but leaks into `ps`/history — avoid it.)
- **Edits preview by default.** Without `--yes` you get the list of files that
  *would* change and nothing is written. Add `--yes` to apply.
- **Edits are reversible.** Every applied edit prints / returns an `op_id`;
  `rafter-secrets undo [op_id]` restores byte-for-byte (defaults to the last op).

### Command summary

| Command | JSON result (keys) |
|---|---|
| `scan` | `files_scanned`, `secrets` |
| `list` | `secrets[]` = `{id, key, files[], projects[], stale}` |
| `show <key>` | `secret` (full record) |
| `reveal <key>` | `key`, `value` |
| `run <key>… -- cmd` | runs `cmd` with the secret(s) injected into its env; value never printed (no JSON) |
| `rotate <key> [--yes]` | `op`, `key`, `op_id`, `applied`, `files[]` |
| `add <key> --file <p> [--yes]` | same shape |
| `rm <key> [--yes]` | same shape |
| `undo [op_id]` | `undone` |
| `history` | `history[]` (audit records — no values) |

Disambiguate a key that matches multiple secrets with `--id <secret-id>`.

> The CLI never returns full file contents in `--json` (that would leak other
> secrets in the same file) — only the affected file paths.

## Contributing to this repo

AI-assisted contributions are welcome. Add a `Co-Authored-By` trailer to commits
and note AI involvement in the PR.

### The one rule

**All writes to a user's files go through `internal/edit` and nowhere else.** The
read packages — `internal/scanners`, `internal/scan`, `internal/watch`,
`internal/rescan` — are strictly zero-mutation. Two checks enforce this and must
stay green:

```bash
bash scripts/no-write-syscalls.sh     # static: no write syscalls in read pkgs
go test ./tests/invariant/...         # runtime: fixture files are never mutated
```

### Before you open a PR

```bash
go build ./...
go vet ./...
go test ./...          # add -race when touching internal/edit
gofmt -l .             # must be empty
```

- **Keep dependencies minimal.** This ships as a single small static binary. Don't
  add a dependency you could write in a few lines; reuse what's in `go.mod`.
- **Editing a file format?** Add the editor in `internal/edit`, route it in
  `editor.go`, and rely on the `verifyChange` round-trip — then add a test that
  rotates/adds/deletes and asserts undo restores byte-for-byte.
- **Touching the write path, auth, or paths?** It's security-sensitive — see
  [`docs/design/secret-editing.md`](docs/design/secret-editing.md) and run a
  security review.

### Layout

See [`docs/architecture.md`](docs/architecture.md) for the package map.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
