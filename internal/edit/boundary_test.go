package edit

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestInsideAnyRoot pins the path-boundary predicate, including the
// prefix-collision case (root "/a/b" must NOT contain "/a/bb/x") that a naive
// strings.HasPrefix would get wrong.
func TestInsideAnyRoot(t *testing.T) {
	cases := []struct {
		name  string
		p     string
		roots []string
		want  bool
	}{
		{"exact root", "/a/b", []string{"/a/b"}, true},
		{"child", "/a/b/c", []string{"/a/b"}, true},
		{"deep child", "/a/b/c/d/e", []string{"/a/b"}, true},
		{"prefix collision", "/a/bb/x", []string{"/a/b"}, false},
		{"sibling", "/a/c", []string{"/a/b"}, false},
		{"parent is not inside child", "/a", []string{"/a/b"}, false},
		{"second root matches", "/x/y/z", []string{"/a/b", "/x/y"}, true},
		{"no roots match", "/q/r", []string{"/a/b", "/x/y"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := insideAnyRoot(tc.p, tc.roots); got != tc.want {
				t.Fatalf("insideAnyRoot(%q, %v) = %v, want %v", tc.p, tc.roots, got, tc.want)
			}
		})
	}
}

// TestResolveTargetRefusesSymlinkEscape verifies the engine refuses to follow a
// symlink that resolves outside the configured roots — the boundary that keeps a
// web-triggered chmod or a CLI rotate from touching a file outside the user's
// scan scope. A regular file genuinely inside the root still resolves.
func TestResolveTargetRefusesSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	root := t.TempDir()
	outside := t.TempDir()

	victim := filepath.Join(outside, "victim.env")
	if err := os.WriteFile(victim, []byte("SECRET=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.env")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	// roots must be canonicalised the same way production does (EvalSymlinks)
	// so the comparison is apples-to-apples (e.g. macOS /var -> /private/var).
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := resolveTarget(link, []string{realRoot}); err == nil {
		t.Fatal("resolveTarget followed a symlink escaping the roots — expected refusal")
	}

	inside := filepath.Join(root, "real.env")
	if err := os.WriteFile(inside, []byte("SECRET=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveTarget(inside, []string{realRoot}); err != nil {
		t.Fatalf("resolveTarget refused a file genuinely inside the root: %v", err)
	}
}
