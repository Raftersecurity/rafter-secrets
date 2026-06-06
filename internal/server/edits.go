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
	if req.Apply && res.Applied && s.rescan != nil {
		s.rescan()
	}

	out := secureResponse{OK: true, Op: res.Op, OpID: res.OpID, Applied: res.Applied}
	for _, c := range res.Changes {
		out.Files = append(out.Files, secureFile{Path: c.Path, OldMode: c.Old, NewMode: c.New})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

type rotateRequest struct {
	Value string `json:"value"`
	Apply bool   `json:"apply"`
}

// handleSecretRotate replaces a secret's value in every file it lives in. The
// new value arrives in the POST body (localhost-only, same as it's already
// readable via /reveal) and is piped straight into the edit engine — it is
// NEVER echoed back. The response returns only which FILES changed, never
// their contents (that would leak the other secrets in the same file).
//
// Honesty: this only rewrites the local file(s). It does NOT revoke or mint a
// key at the provider — the UI says so and points the user to do that there.
func (s *Server) handleSecretRotate(w http.ResponseWriter, r *http.Request) {
	if s.store == nil || s.editEngine == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "edits not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeJSONErr(w, http.StatusBadRequest, "missing id")
		return
	}
	var req rotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if req.Value == "" {
		writeJSONErr(w, http.StatusBadRequest, "paste the new value first")
		return
	}

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
		writeJSONErr(w, http.StatusUnprocessableEntity, "this one has no editable files")
		return
	}

	res, err := s.editEngine().Rotate(key, targets, req.Value, "", req.Apply)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "couldn't replace it: "+err.Error())
		return
	}
	if req.Apply && res.Applied && s.rescan != nil {
		s.rescan()
	}
	// Files only — never the new value or the file contents.
	files := make([]string, 0, len(res.Changes))
	for _, c := range res.Changes {
		files = append(files, c.Path)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "op": res.Op, "op_id": res.OpID, "applied": res.Applied, "files": files})
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
	s.store.Read(func(g *storage.Global) {
		for i := range g.Secrets {
			sec := &g.Secrets[i]
			if effectiveKind(sec) != "secret" {
				continue
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
		if req.Apply && res.Applied && s.rescan != nil {
			s.rescan()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}
