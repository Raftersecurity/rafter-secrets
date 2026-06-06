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
