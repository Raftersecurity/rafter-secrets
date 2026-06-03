# Architecture

A single Go binary. Run with no command it serves a localhost web app; run with a
subcommand it's a CLI (see [`AGENTS.md`](../AGENTS.md)). Everything is stdlib +
three small deps (`blake3`, `fsnotify`, `ini`/`yaml`).

## Package map

```
cmd/rafter-secrets/        # entry point: CLI dispatch + web-UI launcher + rlimit
internal/
├── server/                # localhost HTTP: token auth + Host/Origin guard, SSE,
│   │                      #   inventory API, embedded UI
│   └── static/            # the browser UI (HTML/JS, no build step)
├── edit/                  # THE ONLY WRITER of user files — see below
├── scan/                  # walk orchestrator + scanner dispatch + ResolveValue +
│                          #   ScanFile / SourceKind (single-file scan, format kind)
├── scanners/              # per-source readers (strictly read-only, O_RDONLY)
│   ├── file/              #   .env / .env.* / .envrc
│   ├── config/            #   ~/.aws/credentials, .npmrc, docker, gh, claude
│   └── shellrc/           #   .zshrc / .bashrc / .profile / .zshenv / .bash_profile
├── storage/               # ~/.config/rafter-secrets/global.json schema + atomic
│                          #   Load/Save + Upsert (BLAKE3 dedup / drift) + AddManual
├── docstore/              # single-mutex wrapper shared by rescanner + HTTP handlers
├── fingerprint/           # BLAKE3 dedup ids + value previews
├── watch/                 # fsnotify drift watcher (excludes + cap + EMFILE backstop)
├── rescan/                # watch + scan + event-bus glue for live updates
├── eventbus/              # in-process pub/sub for drift → SSE
└── wizard/                # first-run scope prompt
```

## The zero-mutation boundary

The defining invariant: **the read side never writes.** `internal/scanners`,
`internal/scan`, `internal/watch`, and `internal/rescan` open files `O_RDONLY` and
never rename/delete/chmod. Two layers enforce it:

- `scripts/no-write-syscalls.sh` — static lint: banned write symbols in those
  packages.
- `tests/invariant/` — runtime: drives the full HTTP API + the real fsnotify
  rescan pipeline against a fixture filesystem and asserts it stays byte-identical.

The **only** package allowed to write user files is `internal/edit`.

## `internal/edit` — the editing engine

The single writer. Per the [secure-design doc](design/secret-editing.md), every
edit is backup → produce candidate → re-parse-verify → atomic write → audit, with
one-click undo:

- `lineedit.go` — line-surgical editors for dotenv / shell rc / npmrc (byte-
  preserving) + the value encoders (pick quoting that round-trips the scanner;
  shell values single-quoted/inert).
- `structured.go` — AWS INI (line-surgical) and docker/claude JSON + gh YAML
  (parse → modify → re-emit).
- `verify.go` — `scanCandidate` (scan a candidate via a correctly-named temp copy,
  so the real file only ever receives verified content) + `verifyChange` (assert
  the result differs from baseline in *exactly* the intended way — the backstop
  against corruption / injection).
- `atomic.go` — temp + fsync + chmod + rename; symlink-boundary resolution.
- `engine.go` — orchestration, multi-file transaction + rollback, backups + manifest
  + append-only audit + retention, optimistic concurrency.

## Drift & live updates

The watcher registers directories under each scan root (minus the same excludes the
scanner uses, capped, with an `EMFILE`/`ENOSPC` backstop so a `$HOME`-wide watch
can't exhaust file descriptors). Edits land on disk → the watcher fires a debounced
rescan → `eventbus` → the UI updates over SSE.

## Forward-compatibility

`global.json` is the wire contract (`schema_compat: kp-v0.9`). Field renames or
removals are schema-breaking — bump `storage.SchemaVersion`.
