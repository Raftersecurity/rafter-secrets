package scan

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
)

// gitInfo answers two read-only questions per scanned file, for the
// "secret committed to git" leak signal: is it inside a git repo, and has it
// ever appeared in that repo's history (on any ref)?
//
// It walks up for a .git entry (cached, bounded to the scan roots) and runs
// `git log --all -- <path>` once per file (cached). It never writes to the repo.
// If the git binary is missing it degrades to in-repo detection only. One
// gitInfo is created per scan.Run, so it picks up changes between scans.
type gitInfo struct {
	roots        []string          // scan roots — the upward .git walk stops here
	repoRoots    map[string]string // dir → repo root ("" = not in a repo)
	historyCache map[string]bool   // abs path → ever in git history?
	ignoreCache  map[string]bool   // abs path → git-ignored?
	noGit        bool
}

func newGitInfo(roots []string) *gitInfo {
	gi := &gitInfo{roots: roots, repoRoots: map[string]string{}, historyCache: map[string]bool{}, ignoreCache: map[string]bool{}}
	if _, err := exec.LookPath("git"); err != nil {
		gi.noGit = true
	}
	return gi
}

// status reports, for an absolute file path: whether it's in a git repo,
// whether git tracks it (committed/staged), and whether git ignores it. The
// ignore result is nil when unknown (no git, or not in a repo) so the caller
// can distinguish "checked, not ignored" (the risky case) from "didn't check".
func (g *gitInfo) status(path string) (inRepo, committed bool, ignored *bool) {
	if g == nil || path == "" {
		return false, false, nil
	}
	root := g.repoRootFor(filepath.Dir(path))
	if root == "" {
		return false, false, nil
	}
	if g.noGit {
		return true, false, nil
	}
	committed = g.inHistory(root, path)
	ig := g.checkIgnore(root, path)
	return true, committed, &ig
}

// inHistory reports whether path ever appeared in this repo's history on ANY
// ref — `git log --all -1 -- <path>` finds a commit. This is true "in history",
// not merely "currently tracked": it does NOT over-claim a staged-but-never-
// committed file, and (the dangerous case) it DOES catch a secret that was
// committed then deleted or git-ignored — still in history, maybe already pushed.
func (g *gitInfo) inHistory(root, path string) bool {
	if v, ok := g.historyCache[path]; ok {
		return v
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	// Fixed args, no shell. -1 stops at the first matching commit (existence only).
	out, _ := exec.Command("git", "-C", root, "log", "--all", "--format=%h", "-1", "--", rel).Output()
	v := len(bytes.TrimSpace(out)) > 0
	g.historyCache[path] = v
	return v
}

// checkIgnore reports whether git ignores path (respecting .gitignore, nested
// ignores, and global excludes). `git check-ignore -q` exits 0 when ignored,
// 1 when not. Cached per path; a handful of scanned files per repo, so the
// per-file cost is negligible.
func (g *gitInfo) checkIgnore(root, path string) bool {
	if v, ok := g.ignoreCache[path]; ok {
		return v
	}
	ig := exec.Command("git", "-C", root, "check-ignore", "-q", "--", path).Run() == nil
	g.ignoreCache[path] = ig
	return ig
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
		// Don't walk above a scan root — a .git outside the user's project (e.g.
		// a repo at $HOME) isn't what "committed to git" should mean here.
		if g.atRoot(d) {
			break
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

// atRoot reports whether d is one of the scan roots (the upward .git walk
// boundary).
func (g *gitInfo) atRoot(d string) bool {
	for _, r := range g.roots {
		if d == r {
			return true
		}
	}
	return false
}
