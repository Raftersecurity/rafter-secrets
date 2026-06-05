// HTTP handlers for the scan-scope panel: GET the current scope (plus
// home-dir + suggested workspace folders so the UI can render it in plain
// language) and PUT an updated set of folders.
//
// This endpoint mutates the app's OWN config store (global.json) — the same
// store the annotate/stale endpoints already write — NOT the user's secret
// files. The read-only-user-files guarantee is unchanged: changing scope only
// changes which folders get *read* on the next scan. Like every endpoint it
// sits behind the Host/Origin guard + session token, so only the local UI can
// reach it.

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Raftersecurity/rafter-secrets/internal/storage"
	"github.com/Raftersecurity/rafter-secrets/internal/wizard"
)

const (
	maxRoots      = 32
	maxExcludes   = 500
	maxPathLen    = 4096
	maxExcludeLen = 512
)

type scanConfigResponse struct {
	Home            string   `json:"home"`
	Roots           []string `json:"roots"`
	Excludes        []string `json:"excludes"`
	Suggested       []string `json:"suggested"`
	DefaultExcludes []string `json:"default_excludes"`
}

func (s *Server) handleScanConfigGet(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "store not configured")
		return
	}
	home, _ := os.UserHomeDir()
	var resp scanConfigResponse
	s.store.Read(func(g *storage.Global) {
		resp.Roots = append([]string{}, g.ScanConfig.Roots...)
		resp.Excludes = append([]string{}, g.ScanConfig.Excludes...)
	})
	resp.Home = home
	resp.DefaultExcludes = wizard.DefaultExcludes()
	// Suggest common workspace dirs that exist under home and aren't already
	// a root, so the user can add them with one click.
	if home != "" {
		have := map[string]bool{}
		for _, r := range resp.Roots {
			have[filepath.Clean(r)] = true
		}
		for _, d := range wizard.DetectCommonLayouts(home) {
			if !have[filepath.Clean(d)] {
				resp.Suggested = append(resp.Suggested, d)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

type scanConfigPatch struct {
	Roots    []string `json:"roots"`
	Excludes []string `json:"excludes"`
}

func (s *Server) handleScanConfigUpdate(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "store not configured")
		return
	}
	var p scanConfigPatch
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	roots, err := cleanRoots(p.Roots)
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}
	excludes, err := cleanExcludes(p.Excludes)
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.store.Update(func(g *storage.Global) bool {
		g.ScanConfig.Roots = roots
		g.ScanConfig.Excludes = excludes
		return true
	}); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}

	// Re-scan with the new scope so the inventory reflects it. Best-effort and
	// asynchronous — the SSE scan_started/scan_complete frames drive the UI.
	if s.rescan != nil {
		s.rescan()
	}
	w.WriteHeader(http.StatusNoContent)
}

// cleanRoots validates and normalises the requested scan roots: each must be
// an existing directory, given as an absolute path (or ~-relative, expanded
// here). Duplicates are dropped; at least one is required. Validating that the
// path exists and is a directory keeps a typo from silently scanning nothing —
// and rejects non-directory targets before the scanner sees them.
func cleanRoots(in []string) ([]string, error) {
	home, _ := os.UserHomeDir()
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if len(p) > maxPathLen {
			return nil, fmt.Errorf("that path is too long")
		}
		if p == "~" {
			p = home
		} else if strings.HasPrefix(p, "~/") && home != "" {
			p = filepath.Join(home, strings.TrimPrefix(p, "~/"))
		}
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("%q must be a full folder path (starting with / or ~)", raw)
		}
		p = filepath.Clean(p)
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("can't find the folder %q", raw)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%q isn't a folder", raw)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) > maxRoots {
			return nil, fmt.Errorf("that's a lot of folders — please keep it under %d", maxRoots)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pick at least one folder to scan")
	}
	return out, nil
}

func cleanExcludes(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if len(e) > maxExcludeLen {
			return nil, fmt.Errorf("an exclude pattern is too long")
		}
		out = append(out, e)
		if len(out) > maxExcludes {
			return nil, fmt.Errorf("too many exclude patterns")
		}
	}
	return out, nil
}
