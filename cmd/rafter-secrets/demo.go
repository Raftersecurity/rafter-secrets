package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Raftersecurity/rafter-secrets/internal/storage"
)

// demoDir is the sandbox root for `rafter-secrets demo`. It lives under the OS
// temp dir (not the user's home) so the demo never scans — or writes near —
// real files. Recreated on every `demo` run so the fixtures are pristine.
func demoDir() string { return filepath.Join(os.TempDir(), "rafter-secrets-demo") }

// setupDemo builds a self-contained sandbox of fake-but-realistic secret files
// and returns a store path + doc scoped to it. `rafter-secrets demo` then
// launches the normal UI against this sandbox, so anyone can see the full
// experience — committed-to-git leaks, exposed files, duplicates, publishable
// NEXT_PUBLIC_* values, placeholders — WITHOUT scanning (or touching) their
// real machine.
//
// Every value is synthetic: generated high-entropy so the classifier treats it
// as a real secret, but produced fresh from crypto/rand — never a live key.
func setupDemo() (storePath string, doc *storage.Global, err error) {
	base := demoDir()
	if err := os.RemoveAll(base); err != nil {
		return "", nil, fmt.Errorf("reset demo dir: %w", err)
	}
	files := filepath.Join(base, "projects")
	storeDir := filepath.Join(base, "store")
	for _, d := range []string{files, storeDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", nil, fmt.Errorf("create demo dir: %w", err)
		}
	}

	// --- acme-payments: a git repo with a secret committed to history (the #1
	// vector), a gitignored local override (safe), and an example template. ---
	acme := filepath.Join(files, "acme-payments")
	_ = os.MkdirAll(acme, 0o755)
	writeFile(filepath.Join(acme, ".env"), ""+
		"# acme-payments — committed by mistake\n"+
		"STRIPE_SECRET_KEY="+tokenDemo("sk_live_", 30)+"\n"+
		"DATABASE_URL=postgres://acme:"+tokenDemo("", 16)+"@db.acme.internal:5432/acme\n"+
		"PORT=8080\n"+
		"NODE_ENV=production\n", 0o600)
	writeFile(filepath.Join(acme, ".gitignore"), ".env.local\n", 0o644)
	writeFile(filepath.Join(acme, ".env.example"), ""+
		"STRIPE_SECRET_KEY=sk_live_your_key_here\n"+
		"DATABASE_URL=postgres://user:password@localhost:5432/db\n", 0o644)
	// Committed: init a repo and commit the .env so it shows as in-git-history.
	gitSeed(acme)
	// .env.local is created AFTER the commit and is gitignored → "safe" state.
	writeFile(filepath.Join(acme, ".env.local"), "OPENAI_API_KEY="+tokenDemo("sk-proj-", 32)+"\n", 0o600)

	// --- web-frontend: a git repo, secret NOT committed and NOT gitignored
	// (one `git add` from leaking), plus publishable NEXT_PUBLIC_* values that
	// should stay in Environment, and one real secret mistakenly made public. ---
	web := filepath.Join(files, "web-frontend")
	_ = os.MkdirAll(web, 0o755)
	gitSeed(web) // empty repo first; the .env below is untracked & not ignored
	writeFile(filepath.Join(web, ".env"), ""+
		"GITHUB_TOKEN="+tokenDemo("ghp_", 36)+"\n"+
		"NEXT_PUBLIC_SUPABASE_ANON_KEY="+demoJWT()+"\n"+
		"NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY="+tokenDemo("pk_live_", 30)+"\n"+
		"NEXT_PUBLIC_OOPS_KEY="+tokenDemo("sk_live_", 30)+"\n"+ // a real secret made public — still flagged
		"NEXT_PUBLIC_API_URL=https://api.example.com\n", 0o600)

	// --- a world-readable (0644) .env (exposed to other accounts on this
	// computer) so the "Lock down" path has something to act on. ---
	writeFile(filepath.Join(files, "tooling", ".env"), ""+
		"AWS_ACCESS_KEY_ID="+tokenDemo("AKIA", 16)+"\n"+
		"AWS_SECRET_ACCESS_KEY="+tokenDemo("", 40)+"\n", 0o644)

	// --- the same secret saved in two places (duplicated) so that finding
	// shows up too. ---
	shared := tokenDemo("sg.", 40)
	writeFile(filepath.Join(files, "service-a", ".env"), "SENDGRID_API_KEY="+shared+"\n", 0o600)
	writeFile(filepath.Join(files, "service-b", ".env"), "SENDGRID_API_KEY="+shared+"\n", 0o600)

	doc = storage.Empty()
	doc.ScanConfig.Roots = []string{files}
	doc.ScanConfig.Excludes = []string{"**/.git/", "**/node_modules/"}
	return filepath.Join(storeDir, "global.json"), doc, nil
}

// writeFile is a panic-free best-effort writer for demo fixtures; a fixture
// that fails to write just means one fewer demo finding, never a crash.
func writeFile(path, body string, mode os.FileMode) {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, []byte(body), mode)
}

// gitSeed initialises a git repo in dir and commits whatever is staged, so a
// committed fixture shows the "in git history" leak signal. Best-effort: if git
// isn't installed the fixtures still classify as secrets, just not as committed.
func gitSeed(dir string) {
	run := func(args ...string) {
		c := exec.Command("git", args...)
		c.Dir = dir
		c.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Rafter Demo", "GIT_AUTHOR_EMAIL=demo@rafter.local",
			"GIT_COMMITTER_NAME=Rafter Demo", "GIT_COMMITTER_EMAIL=demo@rafter.local")
		_ = c.Run()
	}
	run("init", "-q")
	run("add", "-A")
	run("commit", "-q", "-m", "seed")
}

// tokenDemo returns prefix + n high-entropy base62 chars from crypto/rand — a
// synthetic value that clears the classifier's entropy floors (so it's treated
// as a real secret) but is never a live key.
func tokenDemo(prefix string, n int) string {
	const cs = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = cs[int(b[i])%len(cs)]
	}
	return prefix + string(b)
}

// demoJWT builds a JWT-shaped value (header.payload.signature) so it exercises
// the "publishable anon key under NEXT_PUBLIC_" classification path.
func demoJWT() string {
	return "eyJhbGciOiJIUzI1NiJ9." + tokenDemo("", 40) + "." + tokenDemo("", 43)
}
