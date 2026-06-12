package edit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Raftersecurity/rafter-secrets/internal/scan"
	"github.com/Raftersecurity/rafter-secrets/internal/scanners"
)

// maxValueLen bounds a value the engine will write. Secrets are short; a
// giant value is more likely an error than a credential.
const maxValueLen = 64 * 1024

// maxFileLen bounds the size of a file the engine will edit.
const maxFileLen = 10 * 1024 * 1024

// Target is one file location of a secret. Line is the 1-based line the
// secret was observed on (0 if unknown); it disambiguates duplicate keys in
// line-based formats.
type Target struct {
	Path string
	Line int
}

// Change is one file's before/after for a preview or an applied edit. The
// engine returns full text; the caller is responsible for masking values it
// shouldn't surface.
type Change struct {
	Path string `json:"path"`
	Old  string `json:"old"`
	New  string `json:"new"`
}

// Result describes a previewed or applied operation.
type Result struct {
	OpID    string   `json:"op_id"`
	Op      string   `json:"op"`
	Key     string   `json:"key"`
	Applied bool     `json:"applied"`
	Changes []Change `json:"changes"`
	// Warning is a non-fatal caveat about an applied operation — e.g. the
	// edit succeeded but its undo record couldn't be saved, so it can't be
	// auto-undone. Empty on success and on previews. Callers should surface
	// it instead of unconditionally promising "undo with ...".
	Warning string `json:"warning,omitempty"`
}

// Engine performs the only writes Rafter Secrets ever makes to user files.
// configDir is the app's config directory (backups + audit live under it,
// OUTSIDE every scan root). roots is the scan-root allowlist for the symlink
// boundary; an empty roots disables it (tests).
type Engine struct {
	configDir string
	roots     []string
	now       func() time.Time
}

// New returns an Engine. now defaults to time.Now.
func New(configDir string, roots []string) *Engine {
	return &Engine{configDir: configDir, roots: roots, now: time.Now}
}

type manifestEntry struct {
	Path   string      `json:"path"`
	Backup string      `json:"backup"`
	Mode   os.FileMode `json:"mode"`
}

type manifest struct {
	OpID    string          `json:"op_id"`
	Op      string          `json:"op"`
	Key     string          `json:"key"`
	Time    time.Time       `json:"time"`
	Entries []manifestEntry `json:"entries"`
}

// Rotate replaces key's value at every target. It is all-or-nothing: every
// candidate is produced and verified before any file is written. If expectOld
// is non-empty, each target's current value must match it (optimistic
// concurrency — refuses to clobber a change the user hasn't seen).
func (e *Engine) Rotate(key string, targets []Target, newValue, expectOld string, apply bool) (*Result, error) {
	return e.run("rotate", opRotate, key, newValue, expectOld, targets, apply)
}

// Delete removes key at every target.
func (e *Engine) Delete(key string, targets []Target, expectOld string, apply bool) (*Result, error) {
	return e.run("delete", opRemove, key, "", expectOld, targets, apply)
}

// Add writes a new key=value into a single file.
func (e *Engine) Add(key, value string, target Target, apply bool) (*Result, error) {
	return e.run("add", opAdd, key, value, "", []Target{target}, apply)
}

// secureMode is owner read/write only — no group, no other.
const secureMode = os.FileMode(0o600)

// Secure tightens the permissions of key's files to owner-only (0600), so other
// users and other programs you run can no longer read them. It changes only the
// mode bits — never a byte of the file's contents — and skips files that are
// already owner-only. It is reversible: Undo restores each file's prior mode.
//
// This is the "fix it for me" behind a world-readable secret. It lives in the
// edit engine (the only writer), so it is path-checked, audited, and undoable
// like every other write. It is reachable from both the CLI (`secure`) and the
// web app (POST /api/secrets/{id}/secure, /api/secure-all) — permission-only
// changes are reversible, so unlike value edits they are safe to expose there.
func (e *Engine) Secure(key string, targets []Target, apply bool) (*Result, error) {
	if len(targets) == 0 {
		return nil, errors.New("no target files")
	}
	res := &Result{OpID: newOpID(e.now()), Op: "secure", Key: key, Applied: false}

	type prep struct {
		realPath string
		oldMode  os.FileMode
	}
	var preps []prep
	for _, t := range targets {
		real, info, err := resolveTarget(t.Path, e.roots)
		if err != nil {
			return nil, err
		}
		old := info.Mode().Perm()
		if old&0o077 == 0 {
			continue // already owner-only — nothing to tighten
		}
		preps = append(preps, prep{realPath: real, oldMode: old})
		res.Changes = append(res.Changes, Change{Path: real, Old: fmtMode(old), New: fmtMode(secureMode)})
	}
	if len(preps) == 0 || !apply {
		return res, nil // nothing to do, or preview only
	}

	// Apply, recording the prior mode so Undo can put it back. No content
	// backup is needed — contents never change — so manifest.Backup stays "".
	man := manifest{OpID: res.OpID, Op: "secure", Key: key, Time: e.now()}
	done := []prep{}
	rollback := func() {
		for _, p := range done {
			_ = os.Chmod(p.realPath, p.oldMode)
		}
	}
	for _, p := range preps {
		if err := os.Chmod(p.realPath, secureMode); err != nil {
			rollback()
			return nil, fmt.Errorf("chmod %s failed, rolled back: %w", p.realPath, err)
		}
		man.Entries = append(man.Entries, manifestEntry{Path: p.realPath, Mode: p.oldMode})
		done = append(done, p)
	}
	if err := e.writeManifest(man); err != nil {
		// Modes are changed; a missing manifest only costs undo. Tell the
		// caller so it doesn't promise an undo that won't work.
		res.Warning = "permissions were changed, but the undo record couldn't be saved — this change can't be auto-undone"
	}
	e.audit(man, "ok")
	_ = e.pruneBackups()
	res.Applied = true
	return res, nil
}

// fmtMode renders permission bits as a 4-digit octal string (e.g. "0644").
func fmtMode(m os.FileMode) string { return fmt.Sprintf("%04o", m.Perm()) }

func (e *Engine) run(opName string, action op, key, value, expectOld string, targets []Target, apply bool) (*Result, error) {
	if key == "" {
		return nil, errors.New("missing key")
	}
	if len(value) > maxValueLen {
		return nil, fmt.Errorf("value is too large (%d bytes; limit %d)", len(value), maxValueLen)
	}
	if len(targets) == 0 {
		return nil, errors.New("no target files")
	}

	type prepared struct {
		realPath  string
		mode      os.FileMode
		orig      []byte
		candidate []byte
	}
	var preps []prepared
	res := &Result{OpID: newOpID(e.now()), Op: opName, Key: key, Applied: false}

	// Phase 1: produce + verify every candidate. No writes yet.
	for _, t := range targets {
		real, info, err := resolveTarget(t.Path, e.roots)
		if err != nil {
			return nil, err
		}
		if info.Size() > maxFileLen {
			return nil, fmt.Errorf("%s is too large to edit safely", t.Path)
		}
		orig, err := os.ReadFile(real)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", real, err)
		}
		baseline, ok, err := scan.ScanFile(real)
		if err != nil || !ok {
			return nil, fmt.Errorf("%s is not an editable secret file", real)
		}
		if expectOld != "" && !hasKeyValue(baseline, key, expectOld) {
			return nil, fmt.Errorf("%s changed since you last looked — re-check before editing", real)
		}

		ed, err := editorFor(real)
		if err != nil {
			return nil, err
		}
		candidate, err := ed.apply(orig, action, key, value, t.Line)
		if err != nil {
			return nil, friendlyEditErr(err, key)
		}
		after, err := scanCandidate(real, candidate)
		if err != nil {
			return nil, err
		}
		if err := verifyChange(baseline, after, action, key, value); err != nil {
			return nil, err
		}
		preps = append(preps, prepared{realPath: real, mode: info.Mode().Perm(), orig: orig, candidate: candidate})
		res.Changes = append(res.Changes, Change{Path: real, Old: string(orig), New: string(candidate)})
	}

	if !apply {
		return res, nil // preview only
	}

	// Phase 2: back up everything, then write. On a write failure, roll back.
	man := manifest{OpID: res.OpID, Op: opName, Key: key, Time: e.now()}
	written := []prepared{}
	rollback := func() {
		for _, p := range written {
			_ = atomicWrite(p.realPath, p.orig, p.mode)
		}
	}
	for i, p := range preps {
		backup, err := e.backup(res.OpID, i, p.realPath, p.orig, p.mode)
		if err != nil {
			rollback()
			return nil, fmt.Errorf("backup failed, nothing changed: %w", err)
		}
		man.Entries = append(man.Entries, manifestEntry{Path: p.realPath, Backup: backup, Mode: p.mode})
		if err := atomicWrite(p.realPath, p.candidate, p.mode); err != nil {
			rollback()
			return nil, fmt.Errorf("write failed, rolled back: %w", err)
		}
		written = append(written, p)
	}
	if err := e.writeManifest(man); err != nil {
		// Files are written + backed up; a missing manifest only costs undo.
		// Surface it (don't roll back a successful edit) so the caller doesn't
		// promise an undo the user can't actually perform.
		res.Warning = "the change was applied, but the undo record couldn't be saved — this edit can't be auto-undone"
	}
	e.audit(man, "ok")
	_ = e.pruneBackups()
	res.Applied = true
	return res, nil
}

// Undo restores every file recorded in op opID's manifest to its pre-edit
// bytes, then records the undo itself.
func (e *Engine) Undo(opID string) error {
	man, err := e.readManifest(opID)
	if err != nil {
		return err
	}
	// A "secure" op only changed mode bits, so undo only restores the mode —
	// rewriting contents would be wrong (and could clobber a later edit).
	if man.Op == "secure" {
		for _, ent := range man.Entries {
			if err := os.Chmod(ent.Path, ent.Mode); err != nil {
				return fmt.Errorf("restore permissions of %s: %w", ent.Path, err)
			}
		}
		e.audit(manifest{OpID: opID, Op: "undo", Key: man.Key, Time: e.now(), Entries: man.Entries}, "ok")
		return nil
	}
	for _, ent := range man.Entries {
		data, err := os.ReadFile(ent.Backup)
		if err != nil {
			return fmt.Errorf("backup for %s is missing: %w", ent.Path, err)
		}
		if err := atomicWrite(ent.Path, data, ent.Mode); err != nil {
			return fmt.Errorf("restore %s: %w", ent.Path, err)
		}
	}
	e.audit(manifest{OpID: opID, Op: "undo", Key: man.Key, Time: e.now(), Entries: man.Entries}, "ok")
	return nil
}

// ---- backups + manifest + audit ---------------------------------------

func (e *Engine) backup(opID string, idx int, path string, data []byte, mode os.FileMode) (string, error) {
	dir := filepath.Join(e.configDir, "backups", opID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%03d-%s.bak", idx, filepath.Base(path))
	bp := filepath.Join(dir, name)
	if err := os.WriteFile(bp, data, 0o600); err != nil {
		return "", err
	}
	return bp, nil
}

func (e *Engine) writeManifest(m manifest) error {
	dir := filepath.Join(e.configDir, "backups", m.OpID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o600)
}

func (e *Engine) readManifest(opID string) (manifest, error) {
	var m manifest
	// SECURITY: opID names a subdirectory of backups/ and arrives from the
	// caller (e.g. op_id in POST /api/undo). filepath.Join cleans "..", so an
	// unvalidated id like "../../home/victim/.zshrc" would escape backups/ and
	// load an attacker-planted manifest.json — whose Path/Backup fields then
	// drive Undo's arbitrary file read+write. Refuse anything that isn't a
	// well-formed op id (the single choke point every undo path goes through).
	if !validOpID(opID) {
		return m, fmt.Errorf("no record of operation %q to undo", opID)
	}
	b, err := os.ReadFile(filepath.Join(e.configDir, "backups", opID, "manifest.json"))
	if err != nil {
		return m, fmt.Errorf("no record of operation %q to undo", opID)
	}
	return m, json.Unmarshal(b, &m)
}

// validOpID reports whether s is a well-formed operation id as produced by
// newOpID ("<timestamp>-<hex>", e.g. "20240610T143022-a3f2dd0b1c4e"). The
// charset is restricted to [0-9A-Za-z-], so s can never contain a path
// separator, ".", or "..": it always names exactly one directory level under
// backups/. This is the boundary that makes readManifest traversal-proof.
func validOpID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '-':
		default:
			return false
		}
	}
	return true
}

// audit appends one line to the JSONL audit log. It records who/what/when —
// op, key name, file paths, op-id — but NEVER a secret value.
func (e *Engine) audit(m manifest, result string) {
	paths := make([]string, 0, len(m.Entries))
	for _, ent := range m.Entries {
		paths = append(paths, ent.Path)
	}
	rec := map[string]any{
		"time": e.now().UTC().Format(time.RFC3339), "op": m.Op,
		"key": m.Key, "files": paths, "op_id": m.OpID, "result": result,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(e.configDir, "audit.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// maxBackupOps caps how many operation backups are retained; the oldest are
// pruned so repeated edits can't fill the disk.
const maxBackupOps = 200

func (e *Engine) pruneBackups() error {
	root := filepath.Join(e.configDir, "backups")
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) <= maxBackupOps {
		return nil
	}
	dirs := make([]string, 0, len(entries))
	for _, en := range entries {
		if en.IsDir() {
			dirs = append(dirs, en.Name())
		}
	}
	sort.Strings(dirs) // op-ids are time-sortable (timestamp prefix)
	for _, d := range dirs[:len(dirs)-maxBackupOps] {
		_ = os.RemoveAll(filepath.Join(root, d))
	}
	return nil
}

// ---- helpers ----------------------------------------------------------

func hasKeyValue(fs []scanners.FoundSecret, key, value string) bool {
	for _, f := range fs {
		if f.KeyName == key && f.Value == value {
			return true
		}
	}
	return false
}

func newOpID(t time.Time) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return t.UTC().Format("20060102T150405") + "-" + hex.EncodeToString(b[:])
}

// friendlyEditErr maps internal sentinels to user-facing messages.
func friendlyEditErr(err error, key string) error {
	switch {
	case errors.Is(err, errUnrepresentable):
		return fmt.Errorf("that value can't be stored in this file's format without risking corruption — leaving %q unchanged", key)
	case errors.Is(err, errKeyNotFound):
		return fmt.Errorf("%q isn't in that file", key)
	case errors.Is(err, errKeyExists):
		return fmt.Errorf("%q is already in that file", key)
	default:
		return err
	}
}
