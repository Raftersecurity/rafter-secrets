# Secure design — editing secrets on disk

> **Status: decided 2026-06-03.** Output of a `rafter-secure-design` walk
> (ingestion + STRIDE) before any write-path code. This is the contract the
> implementation and `rafter-code-review` are held to.

Until now Rafter Secrets was **read + annotate only**, with a zero-mutation
invariant enforced by a static lint and a runtime invariant test. This adds a
bounded write capability. The bar is high: the user is non-technical and the
files hold real, possibly irreplaceable credentials.

## Scope (decided)

- **Full lifecycle, bounded:** rotate a value *everywhere it appears*, add a
  value to a file, delete a secret from a file — **only** in the file formats
  the read side already parses (matrix below).
- **On by default** (no opt-in gate). The per-action safety rails carry the
  weight instead.
- Every write: **timestamped backup → preview diff → atomic write → append-only
  audit → one-click undo.**

## What changes about the zero-mutation invariant

It narrows; it does not disappear.

- The **read packages stay strictly zero-mutation**: `internal/scanners`,
  `internal/scan`, `internal/watch`, `internal/rescan`. The static
  `no-write-syscalls.sh` lint keeps covering them unchanged.
- **All writes to user files go through one package, `internal/edit`, and
  nowhere else.** The lint is extended to assert no write syscalls leak into
  any other package (the only writers are `internal/edit` and the existing
  config-dir saver in `internal/storage`).
- The **runtime invariant test** changes from "the fixture is byte-identical
  after driving the whole API" to: the fixture is byte-identical *unless* an
  edit endpoint was explicitly called; and after an edit, **only the targeted
  key in the targeted file changed**, a backup exists, and **undo restores the
  file byte-for-byte**.

## Trust boundary / data flow

```
[browser UI]  ┐                              ┌─→ secret files on disk
[agent CLI]   ┘→ (token + Host + Origin) → internal/edit ┤
                  ^already hardened^         │  └─→ backup store + audit log
                                             │      (~/.config/rafter-secrets/, 0600,
                                             │       OUTSIDE every scan root)
```

The client↔server boundary is already controlled (127.0.0.1 bind, 256-bit
session token, Host allowlist + Origin check vs. DNS-rebinding/CSRF). **The new
boundary is server↔disk** — that is where this design concentrates.

## Ingestion — the core hazard

Writing a user-controlled value into a structured file can **corrupt its
syntax** or **inject a second entry** (`FOO=bar\nADMIN=true`), and in a shell rc
a crafted value is *executed* when the file is sourced (`$(...)`, backticks).

Decisions:

1. **The client never supplies a target path.** It sends `{secret_id, value}`;
   the server resolves the real file paths from the secret's `found_in` in the
   store. Removes path-traversal / arbitrary-write entirely.
2. **Input schema + limits:** `value` ≤ 64 KB (secrets are short — reject
   giants); key name matches `^[A-Za-z_][A-Za-z0-9_.-]*$`, ≤ 256; target file
   ≤ 10 MB. Unknown request fields ignored.
3. **Per-format safe encoder** (no value is ever concatenated raw):
   - dotenv / `.envrc`: `KEY="…"` with `"` `\` `$` and newlines escaped.
   - shell rc: `export KEY='…'` single-quote encoded (`'` → `'\''`); newlines
     rejected. Single quotes make the value inert when sourced.
   - INI (`aws/credentials`, `.npmrc`): `key = value`; reject newlines and
     `[`-leading values (would forge a section).
   - JSON (`docker/config.json`, `claude/settings.json`): `encoding/json`
     (stdlib, safe escaping).
4. **Write → re-parse → verify (load-bearing).** After producing the new file
   bytes, re-run the *same read-only scanner* over them in memory and assert:
   (a) it still parses, (b) the target key now equals the intended value, and
   (c) every *other* key→value pair is unchanged. Any mismatch → abort, write
   nothing. This catches encoder bugs and injection generically.
5. **Un-representable values are rejected, not forced.** If a value can't be
   safely expressed in a format, the edit fails with a clear message and the old
   value stays. Correctness over coverage.

## Atomicity & transactions

- **Single file:** write a temp file in the *same directory*, `fsync`, copy the
  original mode (and uid/gid where possible), then `rename` over the target
  (atomic on POSIX).
- **Rotate-everywhere is a transaction:** back up *all* target files, apply all,
  verify each; if any step fails, **restore every already-applied file from its
  backup** — all-or-nothing, no partial rotation.
- **Symlinks:** resolve; edit the real file only if it's within a scan root;
  refuse a symlink pointing outside (mirrors the read-side boundary).

## Backup, undo, retention

- Before touching a file, copy its bytes to
  `~/.config/rafter-secrets/backups/<op-id>/…` plus a manifest (op-id, files,
  original modes, fingerprints). Backups live **outside scan roots** so they're
  never scanned, watched, or edited.
- **Undo = restore the backed-up bytes** atomically, then verify byte-equality.
  Undo is itself audited and backed up (so it's redoable).
- **Retention cap** (total size / age); prune oldest. Repeated edits can't fill
  the disk.

## Concurrency

- Edits take the **docstore lock** (serialized with rescans).
- **Optimistic concurrency:** before writing, re-read the file; the secret's
  current on-disk fingerprint must match what the store/client last saw.
  Mismatch → `409 file changed — re-check`. Never clobber an unseen change.
- Our own write fires one debounced rescan (desired: it re-observes the new
  value as drift). Backups are outside the watched tree, so no loop.

## STRIDE (per boundary)

- **Spoofing** — client auth already token + Host + Origin; CLI is the local
  user acting on their own files.
- **Tampering** — encoder + reparse-verify + atomic + backup make corruption
  detectable *and* reversible; audit log is append-only.
- **Repudiation** — append-only JSONL audit names actor (`ui`/`cli`), op, key,
  files, backup ref, time.
- **Information disclosure** — **never log plaintext values** (key names +
  fingerprints only); backups + audit are `0600` in the config dir; the preview
  diff masks values the user hasn't revealed.
- **DoS** — value/file size caps, backup retention cap.
- **Elevation** — the client can't name a path; the server only ever writes
  files already in the inventory, owned by the running user.

## Abuse twins → control

- Rotate with a crafted value that injects a second var → **per-format encoder +
  reparse-verify**.
- Delete that clobbers the wrong / many files → **server resolves targets from
  the store; per-op preview; backup + undo; transaction**.
- Repeated edits fill the disk with backups → **retention cap**.
- An external process edits the file mid-operation → **optimistic concurrency
  check**.

## Residual risks (accepted in writing)

- **On-by-default editing** (no read-only gate): accepted per product decision;
  mitigated by preview + backup + undo on *every* action.
- **Un-representable values rejected**: a legitimate value that can't be encoded
  in a format is refused rather than forced. Accepted.
- **YAML writes unsupported in v1** (`gh/hosts.yml`): excluded to avoid a YAML
  dependency and round-trip ambiguity; stays read-only. Accepted.

## Format support matrix (v1)

| Format | Files | rotate | add | delete |
|---|---|:--:|:--:|:--:|
| dotenv | `.env`, `.env.*`, `.envrc` | ✅ | ✅ | ✅ |
| shell rc | `.zshrc`, `.bashrc`, `.profile`, `.zshenv`, `.bash_profile` | ✅ | ✅ | ✅ |
| INI | `~/.aws/credentials`, `~/.npmrc` | ✅ | ✅ | ✅ |
| JSON | `~/.docker/config.json`, `~/.claude/settings.json` | ✅ | ✅ | ✅ |
| YAML | `~/.config/gh/hosts.yml` | ❌ read-only | ❌ | ❌ |
| keystore / source code | — | ❌ | ❌ | ❌ |

## Implementation surface (no new heavy deps)

- `internal/edit`: a per-format `Editor` (`Encode` / `Apply` / re-`Verify`), the
  transaction runner, the backup store, undo, and the audit log. Reuses the
  existing scanners for the verify round-trip. Stdlib only.
- API (all preview-first; `{apply:true}` or a two-step preview→apply):
  `POST /api/secrets/{id}/rotate`, `POST /api/secrets/{id}/delete`,
  `POST /api/secrets/{id}/write` (add into a file), `GET /api/edits` (history),
  `POST /api/edits/{op}/undo`. State-changing → covered by the Origin guard.
- CLI: `rafter-secrets rotate|add|rm|undo|history`, each with `--dry-run`
  (prints the diff; the default) and `--yes` (apply). JSON output for agents.

## Gate

`rafter-code-review` + `rafter run` on the implementation PR; the runtime
invariant test (rewritten per above) and the extended write-lint are the
machine-checked floor.

## rafter-code-review findings (2026-06-03)

Independent review of the implemented engine + CLI (CWE Top 25 walk, adversarial).
`go test -race` clean; `rafter secrets` clean; the verify backstop confirmed sound
(re-scans the candidate with the real scanner and rejects unless exactly the target
secret changed; encoders reject newlines / un-round-trippable quoting; shell values
are single-quoted and inert when sourced; atomic rename is TOCTOU-safe).

Fixed:
- **[Medium, CWE-200] `--json` edit output leaked sibling secrets.** The CLI emitted
  the engine's `Change` records, which carry full before/after file text — so rotating
  one key in a multi-secret file returned every other secret in that file. Now emits
  only the changed file paths (+ op + key). The engine still carries full text for a
  future masked diff UI; callers must not echo it raw.

Accepted / documented residual risks:
- **Backups retain rotated-away plaintext values** under `~/.config/rafter-secrets/backups/`
  (0600, pruned at 200 ops). The value was already plaintext on disk and is invalid once
  the user rotates at the vendor; the cap bounds accumulation. A future option could
  shorten retention or scrub on prune.
- **Structured (JSON/YAML) edits parse-reemit**, which reformats the file and drops YAML
  comments; `verifyChange` only checks secret keys, so non-secret content changes aren't
  caught. The common formats (dotenv/shell/npmrc/AWS) use byte-preserving line editors;
  `gh/hosts.yml` is tool-managed and rarely hand-commented.
- **CLI rotate/rm pass `expectOld=""`** (no optimistic-concurrency guard) — a concurrent
  external edit could be clobbered; undo recovers. Single-user local tool. The web API
  will pass the seen value.
