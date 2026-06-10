// HTTP handlers for in-app fixes. These are the ONLY server endpoints that
// write to a user's files, and they do it the same safe way the CLI does —
// through internal/edit: preview by default, backup, atomic write, verify,
// audit, and undo. See docs/design/in-app-edits.md.
//
// The web app used to be strictly read-only; that property is intentionally
// given up so the tool's stated audience ("people who have never opened a
// terminal") can actually act on a finding. Every other safeguard stays, and
// the UI always previews + confirms before applying.

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Raftersecurity/rafter-secrets/internal/edit"
	"github.com/Raftersecurity/rafter-secrets/internal/storage"
)

// effectiveKind is the classifier's verdict unless the user pinned it.
func effectiveKind(s *storage.Secret) string {
	if s.Annotation.OverrideKind == "secret" || s.Annotation.OverrideKind == "env" {
		return s.Annotation.OverrideKind
	}
	if s.Kind == "env" {
		return "env"
	}
	return "secret"
}

type openRequest struct {
	Path string `json:"path"`
}

// handleOpenFile opens a tracked secret file in the user's default editor (the
// "Open" button on each file location). The path must be one Rafter already
// tracks — we never open an arbitrary path the caller hands us — and the OS
// opener is launched without a shell.
func (s *Server) handleOpenFile(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "store not configured")
		return
	}
	var req openRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if req.Path == "" {
		writeJSONErr(w, http.StatusBadRequest, "missing path")
		return
	}
	// Only a path Rafter is already tracking may be opened.
	known := false
	s.store.Read(func(g *storage.Global) {
		for i := range g.Secrets {
			for _, f := range g.Secrets[i].FoundIn {
				if f.Path != "" && f.Path == req.Path {
					known = true
					return
				}
			}
		}
	})
	if !known {
		writeJSONErr(w, http.StatusNotFound, "not a tracked file")
		return
	}
	// The tracked-path set is partly caller-populated (manual secrets store an
	// unvalidated path), so harden here: require an absolute path — which can't
	// start with '-', so it can never be read as an option by the OS opener —
	// and confirm it's a real regular file.
	if !filepath.IsAbs(req.Path) || strings.HasPrefix(req.Path, "-") {
		writeJSONErr(w, http.StatusBadRequest, "can only open an absolute file path")
		return
	}
	if fi, err := os.Stat(req.Path); err != nil || !fi.Mode().IsRegular() {
		writeJSONErr(w, http.StatusBadRequest, "not a readable file")
		return
	}
	if err := openExternally(req.Path); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "couldn't open it: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// openExternally launches the OS default handler for path (the user's editor for
// a text file). No shell — the path is passed as a single argument. Start, not
// Run, so we don't block on the editor staying open.
func openExternally(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	default: // linux, *bsd — "--" so a path is never read as an option
		cmd = exec.Command("xdg-open", "--", path)
	}
	return cmd.Start()
}

// exposedMode reports whether path is group- or other-readable (the "any app
// can read it" condition), used only to decide whether a NOT-owned file is
// worth flagging as skipped.
func exposedMode(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode().Perm()&0o044 != 0
}

// editTargetsOf returns the editable file locations of a secret — file sources
// only, never manual/keystore entries. Mirrors the CLI's editTargets.
func editTargetsOf(s *storage.Secret) []edit.Target {
	var ts []edit.Target
	for _, f := range s.FoundIn {
		if f.Path == "" || f.SourceType == storage.SourceManual || f.SourceType == storage.SourceKeystore {
			continue
		}
		ts = append(ts, edit.Target{Path: f.Path, Line: f.Line})
	}
	return ts
}

type secureRequest struct {
	// Apply false (default) previews; true performs the change.
	Apply bool `json:"apply"`
	// IDs, when non-empty (secure-all only), restricts the operation to these
	// secret IDs — so a filtered/searched view locks down only what it shows.
	IDs []string `json:"ids,omitempty"`
}

type secureFile struct {
	Path    string `json:"path"`
	OldMode string `json:"old_mode"`
	NewMode string `json:"new_mode"`
}

type secureResponse struct {
	OK      bool         `json:"ok"`
	Op      string       `json:"op"`
	OpID    string       `json:"op_id"`
	Applied bool         `json:"applied"`
	Files   []secureFile `json:"files"`
}

func (s *Server) handleSecretSecure(w http.ResponseWriter, r *http.Request) {
	if s.store == nil || s.editEngine == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "edits not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeJSONErr(w, http.StatusBadRequest, "missing id")
		return
	}
	var req secureRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
	}

	// Pull key + targets out under the lock, then run the edit outside it so a
	// slow disk can't stall a concurrent scan.
	var (
		key     string
		targets []edit.Target
		found   bool
	)
	s.store.Read(func(g *storage.Global) {
		for i := range g.Secrets {
			if g.Secrets[i].ID == id {
				key = g.Secrets[i].KeyName
				targets = editTargetsOf(&g.Secrets[i])
				found = true
				return
			}
		}
	})
	if !found {
		writeJSONErr(w, http.StatusNotFound, "secret not found")
		return
	}
	if len(targets) == 0 {
		writeJSONErr(w, http.StatusUnprocessableEntity, "this one has no files to secure")
		return
	}

	res, err := s.editEngine().Secure(key, targets, req.Apply)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "couldn't secure it: "+err.Error())
		return
	}
	if req.Apply && res.Applied {
		s.applyPermsToStore(res.Changes) // reflect new mode now; don't wait on the rescan
		if s.rescan != nil {
			s.rescan()
		}
	}

	out := secureResponse{OK: true, Op: res.Op, OpID: res.OpID, Applied: res.Applied}
	for _, c := range res.Changes {
		out.Files = append(out.Files, secureFile{Path: c.Path, OldMode: c.Old, NewMode: c.New})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

type undoRequest struct {
	OpID string `json:"op_id"`
}

func (s *Server) handleUndo(w http.ResponseWriter, r *http.Request) {
	if s.editEngine == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "edits not configured")
		return
	}
	var req undoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if req.OpID == "" {
		writeJSONErr(w, http.StatusBadRequest, "missing op_id")
		return
	}
	if err := s.editEngine().Undo(req.OpID); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "couldn't undo: "+err.Error())
		return
	}
	if s.rescan != nil {
		s.rescan()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "undone": req.OpID})
}

type secureAllResponse struct {
	OK              bool         `json:"ok"`
	OpID            string       `json:"op_id"`
	Applied         bool         `json:"applied"`
	Files           []secureFile `json:"files"`
	SkippedNotOwned []string     `json:"skipped_not_owned"`
}

// handleSecureAll tightens every eligible exposed SECRET file in one undoable
// operation: owned-by-this-user, real-secret (kind=secret), file sources only.
// Files we can't chmod (owned by another user) are skipped and reported, never
// failed. Already-private files are skipped by the engine. apply:false previews.
func (s *Server) handleSecureAll(w http.ResponseWriter, r *http.Request) {
	if s.store == nil || s.editEngine == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "edits not configured")
		return
	}
	var req secureRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
	}

	var (
		targets []edit.Target
		skipped []string
		seen    = map[string]bool{}
	)
	var only map[string]bool
	if len(req.IDs) > 0 {
		only = make(map[string]bool, len(req.IDs))
		for _, id := range req.IDs {
			only[id] = true
		}
	}
	s.store.Read(func(g *storage.Global) {
		for i := range g.Secrets {
			sec := &g.Secrets[i]
			if effectiveKind(sec) != "secret" {
				continue
			}
			if only != nil && !only[sec.ID] {
				continue // filtered/searched view → only these IDs
			}
			for _, t := range editTargetsOf(sec) {
				if seen[t.Path] {
					continue
				}
				seen[t.Path] = true
				if !ownedByUs(t.Path) {
					if exposedMode(t.Path) {
						skipped = append(skipped, t.Path)
					}
					continue
				}
				targets = append(targets, t)
			}
		}
	})

	out := secureAllResponse{OK: true, SkippedNotOwned: skipped}
	if len(targets) > 0 {
		// One operation over every file → one op_id → one Undo-all. The engine
		// skips files that are already owner-only, so preview lists only the
		// files that would actually change.
		res, err := s.editEngine().Secure("all exposed secrets", targets, req.Apply)
		if err != nil {
			writeJSONErr(w, http.StatusInternalServerError, "couldn't lock them down: "+err.Error())
			return
		}
		out.OpID = res.OpID
		out.Applied = res.Applied
		for _, c := range res.Changes {
			out.Files = append(out.Files, secureFile{Path: c.Path, OldMode: c.Old, NewMode: c.New})
		}
		if req.Apply && res.Applied {
			// Reflect the new modes in the store NOW so the client's immediate
			// reload is correct — don't wait on the async rescan (which, on a big
			// inventory, lands well after the UI refreshes and leaves the count
			// stale).
			s.applyPermsToStore(res.Changes)
			if s.rescan != nil {
				s.rescan()
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// applyPermsToStore writes the new file mode of each changed path back into the
// store immediately, so exposure()/findings recompute correctly on the next
// read without waiting for a rescan. The rescan still runs and will set the same
// values.
func (s *Server) applyPermsToStore(changes []edit.Change) {
	if s.store == nil || len(changes) == 0 {
		return
	}
	nm := make(map[string]string, len(changes))
	for _, c := range changes {
		nm[c.Path] = c.New
	}
	_ = s.store.Update(func(g *storage.Global) bool {
		changed := false
		for i := range g.Secrets {
			for j := range g.Secrets[i].FoundIn {
				if m, ok := nm[g.Secrets[i].FoundIn[j].Path]; ok && g.Secrets[i].FoundIn[j].Permissions != m {
					g.Secrets[i].FoundIn[j].Permissions = m
					changed = true
				}
			}
		}
		return changed
	})
}
