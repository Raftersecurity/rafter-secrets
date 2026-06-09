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
	// Under-claim guard (the dangerous one): committed, then removed → still in
	// history, even though it's no longer tracked / present.
	if err := os.WriteFile(filepath.Join(root, "deleted.env"), []byte("K=v\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "deleted.env")
	git("commit", "-m", "add deleted.env")
	git("rm", "deleted.env")
	git("commit", "-m", "remove deleted.env")
	// Over-claim guard: staged but NEVER committed → not in history. Staged LAST
	// so no later commit sweeps it into the index.
	if err := os.WriteFile(filepath.Join(root, "staged.env"), []byte("K=v\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "staged.env")

	gi := newGitInfo([]string{root})
	check := func(name string, wantIn, wantCommitted, wantIgnored bool) {
		in, c, ig := gi.status(filepath.Join(root, name))
		if in != wantIn || c != wantCommitted {
			t.Errorf("%s: inRepo=%v committed=%v, want %v %v", name, in, c, wantIn, wantCommitted)
		}
		if ig == nil || *ig != wantIgnored {
			t.Errorf("%s: ignored=%v, want %v", name, ig, wantIgnored)
		}
	}
	check("committed.env", true, true, false)  // in history, not ignored
	check("untracked.env", true, false, false) // in repo, never committed, NOT ignored — the risky case
	check("ignored.env", true, false, true)    // properly ignored — the good case
	check("staged.env", true, false, false)    // staged but never committed → NOT in history (no over-claim)
	check("deleted.env", true, true, false)    // committed then removed → STILL in history (no under-claim)

	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if in, _, _ := gi.status(filepath.Join(outside, "x.env")); in {
		t.Errorf("file outside any repo: inRepo=%v, want false", in)
	}
}
