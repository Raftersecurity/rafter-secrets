# In-app fixes (the web UI can now write — deliberately)

Secure-design notes for letting the web UI perform a previewed, undoable fix —
starting with **secure** (lock a world-readable file to owner-only). This
reverses the old "the web server literally cannot write user files" property.
That property is intentionally given up; every *real* safeguard stays.

## Why the trade

The product's audience is "people who have never opened a terminal," yet the
only way to *act* on a finding was a copy-paste command. A fix that requires a
terminal isn't a fix for that audience. So the fix becomes an in-app button.

## What replaces "it can't write" as the guarantee

The durable promise is **not** immutability — it's:

1. **Nothing leaves the device.** Bind is 127.0.0.1 only; no outbound calls.
2. **It only looks unless you ask it to fix something.** Reads/annotations are
   the default; a write happens only on an explicit, per-action click.
3. **Every change is previewed, then undoable.** Edits route through
   `internal/edit` — the same engine the CLI uses — which previews by default,
   backs up first, writes atomically, verifies, audits, and supports `undo`.

The messaging everywhere is updated to lead with (1)–(3), not "never edits."

## Endpoints (this slice)

- `POST /api/secrets/{id}/secure` — body `{ "apply": bool }`.
  - `apply:false` → **preview**: returns the files that *would* change with
    `old_mode → new_mode`. No write.
  - `apply:true` → performs `chmod 0600` on the secret's exposed files via
    `edit.Engine.Secure` (mode bits only, never contents), then triggers a
    re-scan. Returns the `op_id` for undo.
- `POST /api/undo` — body `{ "op_id": "..." }` → `edit.Engine.Undo`, then
  re-scan. (Rotate-over-API, with a value-entry popup, is the next slice.)

The engine is built per-request bound to the **current** scan roots (scope can
change at runtime), so its symlink/root boundary is always live.

## Threat model

- **AuthN / CSRF.** These register in the same mux wrapped by
  `guard(requireToken(...))`: loopback-Host guard + Origin allowlist on
  state-changing methods + SameSite=Strict session cookie + CSP
  `connect-src 'self'`. A cross-site page cannot drive them (SameSite withholds
  the cookie; a JSON `POST` is a non-simple request that always carries Origin,
  which the guard rejects). Same boundary that already protects the
  config/annotate writes — now guarding a higher-stakes write, consciously.
- **Path safety.** Targets come from the scanned inventory and are re-validated
  by `resolveTarget` (EvalSymlinks + inside-roots) before any `chmod`. No
  caller-supplied path reaches the filesystem.
- **Blast radius.** `secure` only *reduces* access (0600) and never touches
  contents; worst case is over-tightening an already-private file, fully
  reversible via `undo`.
- **Confirmation.** The UI always previews (`apply:false`) and shows the exact
  before/after in a confirmation popup before sending `apply:true`. No silent
  writes.

## Invariant test

`tests/invariant` still asserts the read/annotate/scan/scan-config endpoints
never mutate a fixture (driven + fuzzed). The new edit endpoints are **excluded
from that no-mutation set** — they are *supposed* to write — and are covered
instead by positive endpoint tests (preview doesn't write; apply writes only the
target; undo restores) plus the existing `edit` engine tests. The guarantee is
now precisely: *the server never mutates a user file except via an explicit
`apply:true` edit you asked for.*

## Out of scope here (next slices)

- Rotate/rm as in-app buttons (rotate needs a value-entry popup).
- `--no-reveal` server flag (also a natural gate to consider for writes).
