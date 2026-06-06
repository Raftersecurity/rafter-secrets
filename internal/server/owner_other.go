//go:build windows

package server

// ownedByUs is the non-POSIX fallback. Windows access is governed by ACLs, not
// Unix ownership/mode bits, and the lock-down fix there is a separate milestone
// (owner-SID check + icacls) — see docs/design/windows-acls.md. Until then this
// fails closed (treats every file as not-owned), so the batch lock-down is a
// safe no-op on Windows rather than doing something unverified.
func ownedByUs(path string) bool { return false }
