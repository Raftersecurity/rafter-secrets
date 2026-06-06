# Move-to-keychain / rewrite-to-reference — secure design

Remediation **rung 2** (rung 1 = "Lock it down", shipped). The missing *right
place*: when a secret shouldn't sit in plaintext, move its canonical value into
the **user's own** store and replace the file with a pointer.

Status: **design only** — implementation is gated on this walk (higher trust
tier) and on a platform with a working keystore daemon to verify against.

## The one invariant (from docs/vision.md)

Rafter **never owns the vault.** The destination is always the *user's* store —
macOS Keychain, Windows Credential Manager, Linux Secret Service, or 1Password.
Rafter is the **mover** and the **manager of the pointer**, never the custodian.
Values are handled transiently (read → write-to-user-store → forget), never
persisted in a Rafter datastore.

## Data-flow & trust boundaries

```
.env (plaintext value)
   │  read once (engine, previewed)
   ▼
[user store: OS keychain / 1Password]   ← custodian (NOT Rafter)
   │
.env rewritten to a reference:  KEY=rafter://<name>   (or op://…)
   │
rafter-secrets run -- cmd  ──resolve ref ── inject into child env (read→inject→forget)
```

Boundaries:
- **plaintext value → user store.** The value crosses once, on explicit user
  action, via the store's API. Rafter never writes it anywhere else.
- **file → reference.** `internal/edit` gains a *rewrite-to-reference* mode:
  replace the value with `rafter://<name>`, verified by the same re-parse round
  trip (only the targeted key changed), backed up, undoable.
- **reference → runtime.** The `run` broker resolves `rafter://<name>` from the
  user store and injects it; the value never returns to disk or stdout.

## Components & where they live

1. **`internal/secretstore` — a vault-adapter interface** (NEW):
   ```
   type Store interface {
       Put(name string, value []byte) error
       Get(name string) ([]byte, error)
       Delete(name string) error
       Available() bool          // daemon present?
   }
   ```
   Adapters, in order of "credible for a nontechnical user":
   - **OS keychain (default, zero-install):** macOS Keychain (`security` CLI or
     `Security.framework` via cgo behind a build tag — matches the planned
     keystore *reads*), Windows Credential Manager (`wincred`/Win32), Linux
     Secret Service (`secret-tool`/libsecret over D-Bus).
   - **1Password** adapter (`op://` refs + `op run`) — already solves broker.
   - (Rafter's own encrypted store is explicitly **out of scope** — that would
     make Rafter the custodian.)
2. **`internal/edit` rewrite-to-reference** — a new op alongside rotate/secure;
   inherits preview/backup/verify/undo.
3. **`run` broker** — extend `resolveAnyFileValue` to detect a `rafter://` /
   `op://` reference and resolve it through the Store instead of reading the file.
4. **One-flow UI** — "Move it somewhere safe": preview (move value → store,
   rewrite file → reference, set up `run`) → confirm → apply → undo. **Move +
   set-up-run is a single flow**, never two buttons: a file left holding a
   reference with no broker wired up is a broken app.

## STRIDE (the higher-trust-tier risks)

- **Information disclosure / custody.** The value is in memory during the move.
  Mitigation: zero the buffer after `Put`; never log it; never write it to any
  Rafter file (only the user store). Residual: the OS keychain itself is the
  trust root — acceptable, it's the user's and OS-protected.
- **Tampering / integrity.** A reference must resolve to the *right* value. Name
  the store entry deterministically (e.g. `rafter:<fingerprint-or-key>@<path>`),
  and verify on resolve. A wrong/missing entry must fail closed (the app errors,
  not runs with an empty secret).
- **Elevation / broker abuse.** `run` resolving references is a value-bearing
  path — keep it CLI/user-initiated only, never an HTTP endpoint, never an
  agent-readable channel (agents `run`, they don't read). Same stance as the
  vision's MCP decision.
- **Availability.** If the keystore daemon is down (headless Linux, locked
  keychain), the move must refuse cleanly and the `run` must error — never
  silently fall back to plaintext.
- **Repudiation.** Audit the move (key, file, store name, time — never the
  value), like every other edit.

## The strategic fork (decided)

Auditor-that-hands-off, **confirmed**: integrate with the user's store, never
become the vault. OS keychain is the default destination (zero-install, on every
Mac/Windows box, reuses planned keystore work); 1Password/others are adapters;
`rafter-secrets run` is the universal access primitive on top.

## Why design-only for now

- Higher trust tier → this walk is the required gate (per CLAUDE.md +
  docs/vision.md). ✔ done here.
- Verification needs a live keystore daemon (a Mac, a Windows box, or a Linux
  desktop with gnome-keyring) — not available in the headless build env, so
  shipping the adapters now would be unverifiable. Build + verify per platform.

## Build order when greenlit

1. `internal/secretstore` interface + the Linux `secret-tool` adapter (most
   testable), behind `Available()`.
2. `internal/edit` rewrite-to-reference op + tests.
3. `run` reference resolution.
4. The one-flow "Move it somewhere safe" UI (CLI first, then web button).
5. macOS + Windows adapters, each verified on-platform.
