package server

import (
	"encoding/json"
	"testing"

	"github.com/Raftersecurity/rafter-secrets/internal/storage"
)

func TestScanConfig_UpdateValidatesAndRescans(t *testing.T) {
	s, ts, store, _ := newTestServerWithStore(t)
	rescanned := make(chan struct{}, 1)
	s.SetRescan(func() { rescanned <- struct{}{} })

	dir := t.TempDir()
	body := []byte(`{"roots":["` + dir + `"],"excludes":["**/node_modules/"]}`)
	doJSON(t, authedReq(t, "PUT", ts.URL+"/api/scan-config", s.token, body), 204)

	var got []string
	store.Read(func(g *storage.Global) { got = append([]string{}, g.ScanConfig.Roots...) })
	if len(got) != 1 || got[0] != dir {
		t.Fatalf("roots = %v, want [%s]", got, dir)
	}
	select {
	case <-rescanned:
	default:
		t.Error("scope change did not trigger a re-scan")
	}

	// A folder that doesn't exist is rejected, not silently scanning nothing.
	doJSON(t, authedReq(t, "PUT", ts.URL+"/api/scan-config", s.token, []byte(`{"roots":["/no/such/dir/xyz-123"]}`)), 400)
	// At least one folder is required.
	doJSON(t, authedReq(t, "PUT", ts.URL+"/api/scan-config", s.token, []byte(`{"roots":[]}`)), 400)
}

func TestScanConfig_Get(t *testing.T) {
	s, ts, store, _ := newTestServerWithStore(t)
	dir := t.TempDir()
	if err := store.Update(func(g *storage.Global) bool { g.ScanConfig.Roots = []string{dir}; return true }); err != nil {
		t.Fatal(err)
	}
	body := doJSON(t, authedReq(t, "GET", ts.URL+"/api/scan-config", s.token, nil), 200)
	var resp scanConfigResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Roots) != 1 || resp.Roots[0] != dir {
		t.Errorf("roots = %v, want [%s]", resp.Roots, dir)
	}
	if len(resp.DefaultExcludes) == 0 {
		t.Error("expected default_excludes to be populated")
	}
}
