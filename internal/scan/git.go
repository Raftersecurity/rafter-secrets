package scan

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
)

// gitInfo answers two read-only questions per scanned file, for the
// "secret committed to git" leak signal: is it inside a git repo, and is it
// *tracked* (i.e. committed/staged — so likely in history and maybe pushed)?
//
// It walks up for a .git entry (cached per directory) and runs `git ls-files`
// once per repo (cached). It never writes to the repo. If the git binary is
// missing it degrades to in-repo detection only. One gitInfo is created per
// scan.Run, so it picks up changes between scans.
type gitInfo struct {
	repoRoots map[string]string          // dir → repo root ("" = not in a repo)
	tracked   map[string]map[string]bool // repo root → set of tracked abs paths
	noGit     bool
}

func newGitInfo() *gitInfo {
	gi := &gitInfo{repoRoots: map[string]string{}, tracked: map[string]map[string]bool{}}
	if _, err := exec.LookPath("git"); err != nil {
		gi.noGit = true
	}
	return gi
}

// status reports whether the absolute file path is in a git repo and whether
// git tracks it (committed/staged).
func (g *gitInfo) status(path string) (inRepo, committed bool) {
	if g == nil || path == "" {
		return false, false
	}
	root := g.repoRootFor(filepath.Dir(path))
	if root == "" {
		return false, false
	}
	if g.noGit {
		return true, false
	}
	return true, g.trackedFor(root)[path]
}

// repoRootFor walks up from dir looking for a .git entry (dir OR file — the
// latter covers worktrees/submodules), memoising the whole chain.
func (g *gitInfo) repoRootFor(dir string) string {
	if r, ok := g.repoRoots[dir]; ok {
		return r
	}
	var chain []string
	d := dir
	for {
		if r, ok := g.repoRoots[d]; ok {
			for _, c := range chain {
				g.repoRoots[c] = r
			}
			return r
		}
		chain = append(chain, d)
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			for _, c := range chain {
				g.repoRoots[c] = d
			}
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	for _, c := range chain {
		g.repoRoots[c] = ""
	}
	return ""
}

func (g *gitInfo) trackedFor(root string) map[string]bool {
	if set, ok := g.tracked[root]; ok {
		return set
	}
	set := map[string]bool{}
	g.tracked[root] = set // cache even on failure so we don't re-run
	// Fixed args, no shell — root is a filesystem path, never shell-interpreted.
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		return set
	}
	for _, rel := range bytes.Split(out, []byte{0}) {
		if len(rel) == 0 {
			continue
		}
		set[filepath.Join(root, string(rel))] = true
	}
	return set
}
