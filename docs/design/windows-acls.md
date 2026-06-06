# Windows support — ACL detection + icacls fix

Status: **design / build-ready** — not implemented, because it can't be verified
in the (Linux) build env. Mac + Linux are POSIX and shipped; Windows is its own
milestone, not a flag, because the whole exposure model is POSIX-specific.

## Why it's a separate implementation, not a flag

The current model reads **POSIX mode bits**: `parsePerm` (app.js) checks the
group/other read bits, and the fix is `chmod 0600`. On Windows those bits are
meaningless — access is governed by **ACLs**. So both halves need a Windows path:

| | POSIX (shipped) | Windows (this milestone) |
|---|---|---|
| Detect "exposed" | group/other read bit set | inspect the file's DACL: does any principal beyond the owner / SYSTEM / Administrators have read? |
| Fix ("lock it down") | `chmod 0600` | `icacls <file> /inheritance:r /grant:r "<user>:F"` (or the Win32 security API) |
| Undo | restore prior mode | re-enable inheritance: `icacls <file> /inheritance:e` (capture prior ACL first) |
| Ownership (`ownedByUs`) | `Stat_t.Uid == Geteuid()` | compare the file owner SID to the current user SID |

> Note: Windows user-profile files are often already user-restricted by
> inherited ACLs, so the exposure story there genuinely differs — many files a
> POSIX box would flag are already private on Windows.

## Components

1. **Detection** — a Windows build-tagged scanner helper that reads the DACL
   (`golang.org/x/sys/windows` `GetNamedSecurityInfo` → DACL ACEs) and produces
   an "exposed?" verdict + a human label, replacing the `parsePerm` path. The
   stored `FoundIn.Permissions` becomes an ACL summary on Windows; the UI's
   `parsePerm`/`exposure` need a Windows-aware branch (or the server normalises
   to an `exposed: bool` the UI trusts cross-platform — cleaner long-term).
2. **Fix** — `internal/edit` gains a platform-split `tightenPerms(path)`:
   POSIX `os.Chmod(0o600)` (today) vs Windows `icacls /inheritance:r /grant:r`.
   The engine's manifest stores enough to undo (prior ACL on Windows, prior mode
   on POSIX).
3. **Ownership** — `owner_windows.go` replaces today's fail-closed
   `ownedByUs → false` with a real owner-SID comparison (so the batch lock-down
   can act on Windows too).

## Cross-cutting

- **Reuse `golang.org/x/sys/windows`** (already an indirect dep) rather than
  shelling out where the Win32 API is clean; `icacls` is acceptable for the fix
  (matches the `git`/CLI-shell pattern) but the security API is preferable for
  *reading* the DACL.
- **Keep CGO off** — `x/sys/windows` is pure-Go, preserving the single static
  binary.
- **Verification gate:** every piece must be exercised on a real Windows host
  (a file with a permissive ACL → detected → fixed → undone). Until then this
  stays design-only; `owner_other.go` fails closed (treats every file as
  not-owned, so the batch fix is a safe no-op on Windows).

## Build order when a Windows host is available

1. `owner_windows.go` — owner-SID check (replaces the fail-closed stub).
2. Windows DACL read → `exposed` verdict; normalise detection to a cross-platform
   `exposed` boolean so the UI stops parsing POSIX strings.
3. `icacls` tighten + ACL-capture undo in `internal/edit`.
4. End-to-end test on Windows; then drop the "POSIX only" caveats from the UI.
