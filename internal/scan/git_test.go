package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGitInfo_TrackedVsUntracked(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_AUTHOR_DATE=2020-01-01T00:00:00",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t", "GIT_COMMITTER_DATE=2020-01-01T00:00:00")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init")
	if err := os.WriteFile(filepath.Join(root, "committed.env"), []byte("K=v\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "committed.env")
	git("commit", "-m", "x")
	if err := os.WriteFile(filepath.Join(root, "untracked.env"), []byte("K=v\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("ignored.env\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ignored.env"), []byte("K=v\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	gi := newGitInfo()
	check := func(name string, wantIn, wantCommitted, wantIgnored bool) {
		in, c, ig := gi.status(filepath.Join(root, name))
		if in != wantIn || c != wantCommitted {
			t.Errorf("%s: inRepo=%v committed=%v, want %v %v", name, in, c, wantIn, wantCommitted)
		}
		if ig == nil || *ig != wantIgnored {
			t.Errorf("%s: ignored=%v, want %v", name, ig, wantIgnored)
		}
	}
	check("committed.env", true, true, false)  // tracked, not ignored
	check("untracked.env", true, false, false) // in repo, not committed, NOT ignored — the risky case
	check("ignored.env", true, false, true)    // properly ignored — the good case

	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if in, _, _ := gi.status(filepath.Join(outside, "x.env")); in {
		t.Errorf("file outside any repo: inRepo=%v, want false", in)
	}
}
