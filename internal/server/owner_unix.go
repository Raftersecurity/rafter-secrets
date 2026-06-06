//go:build !windows

package server

import (
	"os"
	"syscall"
)

// ownedByUs reports whether the current user owns path — chmod only works on
// files you own, so the batch lock-down skips (and flags) the rest rather than
// failing. On a single-user laptop everything is owned by you; this matters on
// shared/server boxes. Windows ACLs are a separate milestone; see owner_other.go.
func ownedByUs(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true // unknown platform shape — don't over-skip
	}
	return int(st.Uid) == os.Geteuid()
}
