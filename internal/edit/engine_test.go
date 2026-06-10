package edit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Raftersecurity/rafter-secrets/internal/scan"
)

// writeFile creates dir/name with content and returns the full path.
func writeFile(t *testing.T, dir, rel, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// keyAt scans a file and returns the KeyName of its first secret + that
// secret's value + line, so tests don't hardcode per-format key naming.
func keyAt(t *testing.T, path string) (key, value string, line int) {
	t.Helper()
	fs, ok, err := scan.ScanFile(path)
	if err != nil || !ok || len(fs) == 0 {
		t.Fatalf("scan %s: ok=%v err=%v n=%d", path, ok, err, len(fs))
	}
	return fs[0].KeyName, fs[0].Value, fs[0].Source.Line
}

func newEngine(t *testing.T) *Engine { return New(t.TempDir(), nil) }

// TestUndoRejectsPathTraversal locks in the readManifest op-id boundary: an
// op_id that tries to traverse out of backups/ (e.g. via POST /api/undo) must
// be refused, so a planted manifest.json can't drive an arbitrary file write.
func TestUndoRejectsPathTraversal(t *testing.T) {
	for _, s := range []string{
		"../../etc/passwd", "..", ".", "a/b", `a\b`, "", "x/../../y",
		"has space", "semi;colon", "tilde~", "slash/",
	} {
		if validOpID(s) {
			t.Errorf("validOpID(%q) = true, want false (would allow traversal)", s)
		}
	}
	for _, s := range []string{"20240610T143022-a3f2dd0b1c4e", "20060102T150405-000000000000"} {
		if !validOpID(s) {
			t.Errorf("validOpID(%q) = false, want true (valid op id)", s)
		}
	}
	// End to end: a traversal id is refused before any filesystem access.
	if err := newEngine(t).Undo("../../../../tmp/anything"); err == nil {
		t.Fatal("Undo accepted a path-traversal op id")
	}
}

func TestRotate_AllFormats_ApplyVerifyUndo(t *testing.T) {
	home := t.TempDir()
	cases := []struct{ rel, content string }{
		{".env", "# h\nAPI_KEY=old-value-123\nOTHER=keepme\n"},
		{".zshrc", "export GITHUB_TOKEN=ghp_oldtoken000\nalias x=y\n"},
		{".npmrc", "//registry.npmjs.org/:_authToken=npm_old111\n"},
		{".aws/credentials", "[default]\naws_access_key_id = AKIAOLD\naws_secret_access_key = oldsecret\n"},
		{".docker/config.json", "{\n  \"auths\": {\n    \"ghcr.io\": { \"auth\": \"b2xkYXV0aA==\" }\n  }\n}\n"},
		{"gh/hosts.yml", "github.com:\n    oauth_token: gho_oldtoken\n    user: me\n"},
	}
	for _, c := range cases {
		t.Run(c.rel, func(t *testing.T) {
			eng := New(t.TempDir(), nil)
			path := writeFile(t, home, c.rel, c.content, 0o600)
			key, oldVal, line := keyAt(t, path)
			newVal := "rotated-NEW-value-xyz"

			// preview must not write
			pre, err := eng.Rotate(key, []Target{{Path: path, Line: line}}, newVal, oldVal, false)
			if err != nil {
				t.Fatalf("preview: %v", err)
			}
			if pre.Applied {
				t.Error("preview reported Applied")
			}
			if b, _ := os.ReadFile(path); string(b) != c.content {
				t.Error("preview mutated the file")
			}

			// apply
			res, err := eng.Rotate(key, []Target{{Path: path, Line: line}}, newVal, oldVal, true)
			if err != nil {
				t.Fatalf("apply: %v", err)
			}
			if !res.Applied {
				t.Fatal("apply not Applied")
			}
			// the value really changed on disk
			_, gotVal, _ := keyAt(t, path)
			if gotVal != newVal {
				t.Fatalf("after rotate value = %q, want %q", gotVal, newVal)
			}
			// undo restores byte-for-byte
			if err := eng.Undo(res.OpID); err != nil {
				t.Fatalf("undo: %v", err)
			}
			if b, _ := os.ReadFile(path); string(b) != c.content {
				t.Errorf("undo did not restore original:\n got %q\nwant %q", b, c.content)
			}
		})
	}
}

func TestRotateEverywhere_Transaction(t *testing.T) {
	home := t.TempDir()
	eng := New(t.TempDir(), nil)
	p1 := writeFile(t, home, "a/.env", "API_KEY=sameval123\n", 0o600)
	p2 := writeFile(t, home, "b/.env", "API_KEY=sameval123\n", 0o600)
	res, err := eng.Rotate("API_KEY", []Target{{Path: p1, Line: 1}, {Path: p2, Line: 1}}, "newval999", "sameval123", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{p1, p2} {
		if _, v, _ := keyAt(t, p); v != "newval999" {
			t.Errorf("%s not rotated: %q", p, v)
		}
	}
	if err := eng.Undo(res.OpID); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{p1, p2} {
		if b, _ := os.ReadFile(p); string(b) != "API_KEY=sameval123\n" {
			t.Errorf("%s not restored: %q", p, b)
		}
	}
}

func TestShellRotate_InjectionInert(t *testing.T) {
	home := t.TempDir()
	eng := New(t.TempDir(), nil)
	path := writeFile(t, home, ".zshrc", "export TOKEN=ghp_old\n", 0o600)
	_, err := eng.Rotate("TOKEN", []Target{{Path: path, Line: 1}}, "v$(rm -rf ~)`id`", "ghp_old", true)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if want := "export TOKEN='v$(rm -rf ~)`id`'\n"; string(b) != want {
		t.Errorf("injection not inert:\n got %q\nwant %q", b, want)
	}
}

func TestAddAndDelete(t *testing.T) {
	home := t.TempDir()
	eng := New(t.TempDir(), nil)
	path := writeFile(t, home, ".env", "EXISTING=1\n", 0o600)
	if _, err := eng.Add("NEW_KEY", "secret42", Target{Path: path}, true); err != nil {
		t.Fatal(err)
	}
	if _, v, _ := scanForKey(t, path, "NEW_KEY"); v != "secret42" {
		t.Errorf("add: NEW_KEY = %q", v)
	}
	if _, err := eng.Delete("NEW_KEY", []Target{{Path: path, Line: 2}}, "secret42", true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "EXISTING=1\n" {
		t.Errorf("after delete: %q", b)
	}
}

func TestExpectOldMismatch(t *testing.T) {
	home := t.TempDir()
	eng := New(t.TempDir(), nil)
	path := writeFile(t, home, ".env", "K=actual\n", 0o600)
	if _, err := eng.Rotate("K", []Target{{Path: path, Line: 1}}, "new", "stale-expectation", true); err == nil {
		t.Error("expected concurrency error on stale expectOld")
	}
}

func modeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestSecure_TightenAndUndo(t *testing.T) {
	home := t.TempDir()
	eng := New(t.TempDir(), nil)
	path := writeFile(t, home, "code/app/.env", "API_KEY=secret-value-123\n", 0o644)
	if err := os.Chmod(path, 0o644); err != nil { // defeat the test umask
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)

	// Preview lists the mode change and writes nothing.
	pre, err := eng.Secure("API_KEY", []Target{{Path: path}}, false)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if pre.Applied || len(pre.Changes) != 1 {
		t.Fatalf("preview: applied=%v changes=%d", pre.Applied, len(pre.Changes))
	}
	if pre.Changes[0].Old != "0644" || pre.Changes[0].New != "0600" {
		t.Errorf("preview modes = %q -> %q", pre.Changes[0].Old, pre.Changes[0].New)
	}
	if m := modeOf(t, path); m != 0o644 {
		t.Errorf("preview changed mode to %04o", m)
	}

	// Apply tightens the mode but never touches contents.
	res, err := eng.Secure("API_KEY", []Target{{Path: path}}, true)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !res.Applied {
		t.Fatal("apply not Applied")
	}
	if m := modeOf(t, path); m != 0o600 {
		t.Fatalf("after secure mode = %04o, want 0600", m)
	}
	if b, _ := os.ReadFile(path); string(b) != string(content) {
		t.Error("secure changed file contents")
	}

	// Undo restores the prior mode, contents still untouched.
	if err := eng.Undo(res.OpID); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if m := modeOf(t, path); m != 0o644 {
		t.Errorf("after undo mode = %04o, want 0644", m)
	}
	if b, _ := os.ReadFile(path); string(b) != string(content) {
		t.Error("undo changed file contents")
	}
}

func TestSecure_AlreadyTightNoop(t *testing.T) {
	home := t.TempDir()
	eng := New(t.TempDir(), nil)
	path := writeFile(t, home, ".env", "API_KEY=x\n", 0o600)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := eng.Secure("API_KEY", []Target{{Path: path}}, true)
	if err != nil {
		t.Fatalf("secure: %v", err)
	}
	if res.Applied || len(res.Changes) != 0 {
		t.Errorf("already-tight should be a no-op: applied=%v changes=%d", res.Applied, len(res.Changes))
	}
}

func scanForKey(t *testing.T, path, key string) (string, string, int) {
	t.Helper()
	fs, _, _ := scan.ScanFile(path)
	for _, f := range fs {
		if f.KeyName == key {
			return f.KeyName, f.Value, f.Source.Line
		}
	}
	t.Fatalf("key %q not found in %s", key, path)
	return "", "", 0
}
