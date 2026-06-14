// Package scan is Rafter Secrets' filesystem orchestrator. It walks the user's
// configured scan roots, dispatches each recognised credential-bearing
// file to the matching read-only scanner in internal/scanners/*, and
// folds the resulting observations into the global store via
// storage.Global.Upsert.
//
// The orchestrator is deliberately the only place in Rafter Secrets that opens
// directories. Every individual scanner already opens files O_RDONLY;
// here we add the matching guarantee for traversal: no file is created,
// renamed, or deleted, and symlinks pointing OUT of the configured roots
// are not followed (track devices: TestScan_NeverWritesAnyFile pins this).
package scan

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/Raftersecurity/rafter-secrets/internal/storage"
)

// Result is the per-Run summary returned to the caller. The same shape
// drives the optional telemetry payload (Inventory-Tool-Spec.md
// "Telemetry"). Counters are best-effort: a single secret seen at three
// paths increments FilesScanned three times but SecretsFound only once.
type Result struct {
	FilesScanned            int
	SecretsFound            int
	KeystoreEntriesFound    int
	FilesInGitRepos         int
	FilesCommittedInHistory int

	// Errors is the list of non-fatal problems hit during the walk
	// (unreadable file, dangling symlink, malformed config). The walk
	// continues past each one. A truly fatal error (e.g. nil doc) is
	// returned from Run instead.
	Errors []error

	// Changes is the per-secret outcome list emitted by Upsert during
	// Apply, in scan order. The drift watcher uses this to publish
	// SSE events; CLI callers ignore it. Populated by Apply, not Observe.
	Changes []Change

	// upserts is the list of observations collected during the filesystem
	// walk (Observe). Apply folds them into a storage.Global. Kept
	// unexported so the walk and the doc-mutation halves stay decoupled:
	// Observe never touches a doc, so it can run with no lock held.
	upserts []storage.Upsertable

	// git answers "is this file in/tracked by git?" for the leak signal.
	// Unexported — never serialised; one per Run.
	git *gitInfo
}

// Change is the per-secret summary of one Upsert during a scan. It
// mirrors storage.UpsertResult but copies the immutable fields so a
// subsequent Upsert (which may reslice g.Secrets) cannot invalidate
// data the watcher pipeline is about to publish.
type Change struct {
	Outcome  storage.Outcome
	SecretID string
	KeyName  string
	Path     string
}

// Run walks every root in cfg, scans recognised files, and writes
// findings into doc via Upsert. The host clock is sampled once at the
// start of the run; every Secret created or refreshed during this Run
// shares the same FirstSeen/LastSeen value so a partial scan still
// produces a coherent timeline.
//
// Run never mutates any source file. It is safe to invoke repeatedly
// against the same doc — Upsert handles dedup, drift, and re-observation.
//
// Run is exactly Observe followed by Apply against doc, in one call. It
// exists for single-threaded callers (the CLI) that hold no lock. The
// server's rescan loop calls Observe and Apply separately so the long
// filesystem walk never holds the docstore lock — see internal/rescan.
func Run(ctx context.Context, doc *storage.Global, cfg storage.ScanConfig) (*Result, error) {
	if doc == nil {
		return nil, errors.New("scan: nil doc")
	}
	r, err := Observe(ctx, cfg)
	if err != nil {
		// On a cancelled walk the observations are partial; don't apply
		// them, so doc is never left half-mutated. The caller surfaces err.
		return r, err
	}
	r.Apply(doc)
	return r, nil
}

// Observe walks every root in cfg and collects one observation per secret
// seen, plus per-walk stats and non-fatal errors. It never touches a
// storage.Global: the (long) filesystem walk runs with no lock held, so
// the caller can fold the results in afterwards under its store lock with
// Apply. The host clock is sampled once here so every Secret applied from
// this Observe shares one FirstSeen/LastSeen timestamp.
func Observe(ctx context.Context, cfg storage.ScanConfig) (*Result, error) {
	r := &Result{}
	excludes := compileExcludes(cfg.Excludes)

	roots := canonicalRoots(cfg.Roots, r)
	// gitInfo bounds its upward .git walk to these roots (a .git above the scan
	// root isn't the user's project repo).
	r.git = newGitInfo(roots)
	if len(roots) == 0 {
		return r, nil
	}

	seen := make(map[string]struct{})
	now := time.Now().UTC()
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		walkRoot(ctx, root, roots, excludes, seen, r, now)
	}
	return r, nil
}

// Apply folds the observations collected by Observe into doc and returns
// the per-secret Changes (the drift watcher turns these into SSE events).
// It is the short, lock-friendly half of a scan: no filesystem I/O happens
// here, only in-memory Upserts. Call it at most once per Result — a second
// call would double-apply every observation.
//
// A nil doc is a no-op returning nil, so Run can guard nil before Observe.
func (r *Result) Apply(doc *storage.Global) []Change {
	if doc == nil {
		return nil
	}
	r.Changes = r.Changes[:0]
	for i := range r.upserts {
		out := doc.Upsert(r.upserts[i])
		if out.Secret != nil {
			r.Changes = append(r.Changes, Change{
				Outcome:  out.Outcome,
				SecretID: out.Secret.ID,
				KeyName:  out.Secret.KeyName,
				Path:     r.upserts[i].Found.Path,
			})
		}
	}
	return r.Changes
}

// canonicalRoots resolves each configured root to an absolute,
// symlink-resolved path. Roots that fail to resolve are dropped with an
// error appended to r.Errors so a misconfigured entry never aborts the
// rest of the scan.
func canonicalRoots(in []string, r *Result) []string {
	out := make([]string, 0, len(in))
	for _, root := range in {
		abs, err := filepath.Abs(expandHome(root))
		if err != nil {
			r.Errors = append(r.Errors, err)
			continue
		}
		// EvalSymlinks fails if the root is missing; that's a real
		// configuration error worth surfacing but not aborting on.
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			r.Errors = append(r.Errors, err)
			continue
		}
		out = append(out, real)
	}
	return out
}
