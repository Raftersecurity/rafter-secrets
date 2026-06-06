package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestSecureAllEndpoint_OnlySecretsAndUndo(t *testing.T) {
	s, ts, store, storePath := newTestServerWithStore(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mk := func(name string) string {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte("K=v\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	secPath := mk("secret.env")
	envPath := mk("config.env")
	if err := store.Update(func(g *storage.Global) bool {
		g.Secrets = append(g.Secrets,
			storage.Secret{ID: "s1", KeyName: "API_KEY", Kind: "secret", FoundIn: []storage.FoundIn{{SourceType: storage.SourceEnvFile, Path: secPath, Permissions: "0644"}}},
			storage.Secret{ID: "s2", KeyName: "PORT", Kind: "env", FoundIn: []storage.FoundIn{{SourceType: storage.SourceEnvFile, Path: envPath, Permissions: "0644"}}},
		)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	s.editEngine = func() *edit.Engine { return edit.New(filepath.Dir(storePath), []string{root}) }
	s.SetRescan(func() {})
	modeOf := func(p string) os.FileMode { fi, _ := os.Stat(p); return fi.Mode().Perm() }

	body := doJSON(t, authedReq(t, "POST", ts.URL+"/api/secure-all", s.token, []byte(`{"apply":true}`)), 200)
	var resp secureAllResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Applied || len(resp.Files) != 1 {
		t.Fatalf("secure-all = %+v, want 1 file applied", resp)
	}
	if modeOf(secPath) != 0o600 {
		t.Fatalf("secret file not tightened: %04o", modeOf(secPath))
	}
	if modeOf(envPath) != 0o644 {
		t.Fatalf("env file should be untouched, got %04o", modeOf(envPath))
	}
	doJSON(t, authedReq(t, "POST", ts.URL+"/api/undo", s.token, []byte(`{"op_id":"`+resp.OpID+`"}`)), 200)
	if modeOf(secPath) != 0o644 {
		t.Fatalf("undo failed: %04o", modeOf(secPath))
	}
}

func TestRotateEndpoint_PreviewApplyUndo(t *testing.T) {
	s, ts, store, storePath := newTestServerWithStore(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("API_KEY=old-value-123\nKEEP=me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(g *storage.Global) bool {
		g.Secrets = append(g.Secrets, storage.Secret{ID: "sid", KeyName: "API_KEY", FoundIn: []storage.FoundIn{{SourceType: storage.SourceEnvFile, Path: envPath, Line: 1}}})
		return true
	}); err != nil {
		t.Fatal(err)
	}
	s.editEngine = func() *edit.Engine { return edit.New(filepath.Dir(storePath), []string{root}) }
	s.SetRescan(func() {})
	read := func() string { b, _ := os.ReadFile(envPath); return string(b) }
	orig := read()

	var resp struct {
		Applied bool     `json:"applied"`
		Files   []string `json:"files"`
		OpID    string   `json:"op_id"`
	}
	// Preview lists the file, writes nothing.
	body := doJSON(t, authedReq(t, "POST", ts.URL+"/api/secrets/sid/rotate", s.token, []byte(`{"value":"new-value-xyz","apply":false}`)), 200)
	json.Unmarshal(body, &resp)
	if resp.Applied || len(resp.Files) != 1 {
		t.Fatalf("preview = %+v", resp)
	}
	if read() != orig {
		t.Fatal("preview wrote the file")
	}
	// Empty value is rejected.
	doJSON(t, authedReq(t, "POST", ts.URL+"/api/secrets/sid/rotate", s.token, []byte(`{"value":"","apply":true}`)), 400)
	// Apply rewrites only the target key.
	body = doJSON(t, authedReq(t, "POST", ts.URL+"/api/secrets/sid/rotate", s.token, []byte(`{"value":"new-value-xyz","apply":true}`)), 200)
	json.Unmarshal(body, &resp)
	if !resp.Applied || resp.OpID == "" {
		t.Fatalf("apply = %+v", resp)
	}
	if !strings.Contains(read(), "API_KEY=new-value-xyz") || !strings.Contains(read(), "KEEP=me") {
		t.Fatalf("rotate result wrong: %q", read())
	}
	// Undo restores byte-for-byte.
	doJSON(t, authedReq(t, "POST", ts.URL+"/api/undo", s.token, []byte(`{"op_id":"`+resp.OpID+`"}`)), 200)
	if read() != orig {
		t.Fatalf("undo did not restore: %q", read())
	}
}

func TestOpenEndpoint_Validation(t *testing.T) {
	s, ts, store, _ := newTestServerWithStore(t)
	if err := store.Update(func(g *storage.Global) bool {
		g.Secrets = append(g.Secrets,
			storage.Secret{ID: "absmiss", KeyName: "K", FoundIn: []storage.FoundIn{{SourceType: storage.SourceEnvFile, Path: "/no/such/rafter-test-file.env"}}},
			storage.Secret{ID: "dash", KeyName: "K2", FoundIn: []storage.FoundIn{{SourceType: storage.SourceManual, Path: "--malicious"}}},
		)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	// Not a tracked path → 404 (the allowlist).
	doJSON(t, authedReq(t, "POST", ts.URL+"/api/open", s.token, []byte(`{"path":"/etc/passwd"}`)), 404)
	// Tracked + absolute but the file doesn't exist → 400.
	doJSON(t, authedReq(t, "POST", ts.URL+"/api/open", s.token, []byte(`{"path":"/no/such/rafter-test-file.env"}`)), 400)
	// Tracked but option-like / non-absolute → 400 (no flag injection into the opener).
	doJSON(t, authedReq(t, "POST", ts.URL+"/api/open", s.token, []byte(`{"path":"--malicious"}`)), 400)
	// Empty → 400.
	doJSON(t, authedReq(t, "POST", ts.URL+"/api/open", s.token, []byte(`{"path":""}`)), 400)
}

func TestSecureEndpoint_Disabled503(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	// editEngine left nil → edits unavailable.
	doJSON(t, authedReq(t, "POST", ts.URL+"/api/secrets/whatever/secure", s.token, []byte(`{"apply":false}`)), 503)
}
