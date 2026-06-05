package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Raftersecurity/rafter-secrets/internal/edit"
	"github.com/Raftersecurity/rafter-secrets/internal/storage"
)

func TestSecureEndpoint_PreviewApplyUndo(t *testing.T) {
	s, ts, store, storePath := newTestServerWithStore(t)
	root := t.TempDir()
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(realRoot, ".env")
	if err := os.WriteFile(envPath, []byte("API_KEY=secret-value-123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(envPath, 0o644); err != nil { // defeat the test umask
		t.Fatal(err)
	}
	if err := store.Update(func(g *storage.Global) bool {
		g.Secrets = append(g.Secrets, storage.Secret{
			ID: "sid", KeyName: "API_KEY",
			FoundIn: []storage.FoundIn{{SourceType: storage.SourceEnvFile, Path: envPath, Line: 1, Permissions: "0644"}},
		})
		return true
	}); err != nil {
		t.Fatal(err)
	}
	s.editEngine = func() *edit.Engine { return edit.New(filepath.Dir(storePath), []string{realRoot}) }
	s.SetRescan(func() {})

	modeOf := func() os.FileMode { fi, _ := os.Stat(envPath); return fi.Mode().Perm() }

	// Preview lists the change and writes nothing.
	body := doJSON(t, authedReq(t, "POST", ts.URL+"/api/secrets/sid/secure", s.token, []byte(`{"apply":false}`)), 200)
	var pv secureResponse
	if err := json.Unmarshal(body, &pv); err != nil {
		t.Fatal(err)
	}
	if pv.Applied || len(pv.Files) != 1 || pv.Files[0].OldMode != "0644" || pv.Files[0].NewMode != "0600" {
		t.Fatalf("preview = %+v", pv)
	}
	if modeOf() != 0o644 {
		t.Fatalf("preview changed mode to %04o", modeOf())
	}

	// Apply tightens to owner-only.
	body = doJSON(t, authedReq(t, "POST", ts.URL+"/api/secrets/sid/secure", s.token, []byte(`{"apply":true}`)), 200)
	var ap secureResponse
	if err := json.Unmarshal(body, &ap); err != nil {
		t.Fatal(err)
	}
	if !ap.Applied || ap.OpID == "" {
		t.Fatalf("apply = %+v", ap)
	}
	if modeOf() != 0o600 {
		t.Fatalf("after apply mode = %04o, want 0600", modeOf())
	}

	// Undo restores the prior mode.
	doJSON(t, authedReq(t, "POST", ts.URL+"/api/undo", s.token, []byte(`{"op_id":"`+ap.OpID+`"}`)), 200)
	if modeOf() != 0o644 {
		t.Fatalf("after undo mode = %04o, want 0644", modeOf())
	}
}

func TestSecureEndpoint_Disabled503(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	// editEngine left nil → edits unavailable.
	doJSON(t, authedReq(t, "POST", ts.URL+"/api/secrets/whatever/secure", s.token, []byte(`{"apply":false}`)), 503)
}
