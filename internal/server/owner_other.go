//go:build windows

package server

// ownedByUs is the non-POSIX fallback. Windows access is governed by ACLs, not
// Unix ownership/mode bits, and the lock-down fix there is a separate milestone
// (icacls). Until then, don't claim ownership we can't verify.
func ownedByUs(path string) bool { return false }
