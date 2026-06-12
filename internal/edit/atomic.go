// Package edit is the ONLY package in Rafter Secrets permitted to modify a
// user's secret files. Every write goes through here, and every write is:
// backed up first, applied atomically, verified by re-scanning the result,
// audited, and undoable. The read packages (scanners, scan, watch, rescan)
// remain strictly zero-mutation.
//
// See docs/design/secret-editing.md for the full secure-design walk.
package edit

import (
	"fmt"
	"os"
	"path/filepath"
)

// atomicWrite replaces the file at path with data without changing its
// permissions: it writes a temp file in the SAME directory, fsyncs it,
// chmods it to mode, then renames over path (atomic on POSIX). The caller
// must have backed up the original first.
func atomicWrite(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".rs-edit-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err = os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename over %s: %w", path, err)
	}
	// fsync the directory so the rename itself is durable: without it a crash
	// just after a "successful" edit can revert the file to its old contents.
	syncDir(dir)
	return nil
}

// syncDir fsyncs a directory so a create/rename within it is durable. Best
// effort — some filesystems don't support directory fsync, and a failure here
// only weakens the crash-durability guarantee, never correctness.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// resolveTarget resolves a (possibly symlinked) path to the real regular
// file to edit, refusing to follow a symlink whose target escapes the
// allowed roots — the same boundary the scanner enforces on reads. roots
// must be absolute + symlink-resolved; an empty roots list disables the
// boundary check (used by tests).
func resolveTarget(path string, roots []string) (string, os.FileInfo, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil, fmt.Errorf("resolve %s: %w", path, err)
	}
	if len(roots) > 0 && !insideAnyRoot(real, roots) {
		return "", nil, fmt.Errorf("refusing to edit %s: it resolves outside your scan locations", path)
	}
	info, err := os.Lstat(real)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("refusing to edit %s: not a regular file", real)
	}
	return real, info, nil
}

func insideAnyRoot(p string, roots []string) bool {
	sep := string(filepath.Separator)
	for _, r := range roots {
		if p == r || (len(p) > len(r) && p[:len(r)] == r && string(p[len(r)]) == sep) {
			return true
		}
	}
	return false
}
