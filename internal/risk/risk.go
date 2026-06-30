// Package risk turns a stored Secret into a leak/exposure assessment with a
// single severity tier — the canonical, server-side form of the ranking the
// web UI computes in app.js. It exists so the CLI (`list --json`), an agent
// skill, and any script all rank the same way instead of each re-deriving
// "is this committed to git / world-readable / expiring" from raw FoundIn
// fields. The web dashboard predates this and still has its own copy; the
// predicates here mirror it exactly (see internal/server/static/app.js).
//
// Ranking follows vision.md's threat model: a secret committed to git is the
// #1 vector (it may already be public), an ungitignored file in a repo is one
// `git add` from the same fate, and file permissions ("readable by other
// accounts") are deliberately the WEAKEST signal — marginal on a single-user
// laptop — so they never outrank a git leak.
package risk

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Raftersecurity/rafter-secrets/internal/storage"
)

// Severity is a coarse leak-risk tier, worst first.
type Severity string

const (
	SeverityCritical Severity = "critical" // committed to git history — may already be public
	SeverityHigh     Severity = "high"     // in a repo and not gitignored, or expired
	SeverityMedium   Severity = "medium"   // expiring soon
	SeverityLow      Severity = "low"      // readable by other accounts (marginal)
	SeverityNone     Severity = "none"     // no exposure signal
)

// Rank maps a severity to a sortable integer (higher = worse) so callers can
// order findings worst-first without a string switch.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Assessment is the computed leak/exposure summary for one secret. The boolean
// fields are independent signals; Severity is the single worst-applicable tier
// derived from them.
type Assessment struct {
	Severity       Severity `json:"severity"`
	Kind           string   `json:"kind"` // effective kind: "secret" or "env"
	CommittedToGit bool     `json:"committed_to_git"`
	NotGitignored  bool     `json:"not_gitignored"`
	GitIgnored     bool     `json:"git_ignored"`
	WorldReadable  bool     `json:"world_readable"`
	GroupReadable  bool     `json:"group_readable"`
	Duplicated     bool     `json:"duplicated"`
	Expired        bool     `json:"expired,omitempty"`
	ExpiringSoon   bool     `json:"expiring_soon,omitempty"`
	Stale          bool     `json:"stale"`
	// Reasons is a short, human-readable explanation of every signal that
	// fired, worst-first — handy for a CLI line or an agent prompt.
	Reasons []string `json:"reasons,omitempty"`
}

// Assess evaluates a secret against the current wall clock.
func Assess(s *storage.Secret) Assessment { return assessAt(s, time.Now()) }

// assessAt is the testable core: expiry is relative to now.
func assessAt(s *storage.Secret, now time.Time) Assessment {
	a := Assessment{Kind: EffectiveKind(s), Stale: s.Annotation.Stale}

	example := isExampleSecret(s)
	files := fileLocations(s)
	a.Duplicated = len(files) > 1

	for _, f := range files {
		if f.AppearsInGitHistory != nil && *f.AppearsInGitHistory {
			if !example {
				a.CommittedToGit = true
			}
		}
		if !example && f.InGitRepo != nil && *f.InGitRepo &&
			!(f.AppearsInGitHistory != nil && *f.AppearsInGitHistory) &&
			f.InGitignore != nil && !*f.InGitignore {
			a.NotGitignored = true
		}
		if f.InGitignore != nil && *f.InGitignore {
			a.GitIgnored = true
		}
		switch readableBy(f.Permissions) {
		case "other":
			a.WorldReadable = true
		case "group":
			a.GroupReadable = true
		}
	}
	// gitIgnored is only a positive ("safe place") signal when nothing is
	// actually committed — mirror app.js gitIgnoredOk.
	if a.CommittedToGit {
		a.GitIgnored = false
	}

	// Expiry (optional, annotation-driven).
	if d, ok := daysUntilExpiry(s, now); ok && !a.Stale {
		switch {
		case d < 0:
			a.Expired = true
		case d <= 30:
			a.ExpiringSoon = true
		}
	}

	a.Severity, a.Reasons = severityAndReasons(&a, len(files))
	return a
}

// severityAndReasons picks the single worst tier and lists every signal that
// fired. A stale ("not in use") secret is never a risk regardless of exposure.
func severityAndReasons(a *Assessment, fileCount int) (Severity, []string) {
	// Environment/config (PORT, NODE_ENV, NEXT_PUBLIC_*…) is meant to live in
	// the repo and be readable — a committed .env config value is not a leak.
	// Mirror the UI, which only ranks the Secrets lens. The factual flags above
	// (committed_to_git etc.) stay set; only the risk tier is suppressed.
	if a.Kind != "secret" {
		return SeverityNone, nil
	}
	if a.Stale {
		return SeverityNone, []string{"marked not in use"}
	}
	var reasons []string
	sev := SeverityNone
	bump := func(s Severity) {
		if s.Rank() > sev.Rank() {
			sev = s
		}
	}
	if a.CommittedToGit {
		bump(SeverityCritical)
		reasons = append(reasons, "committed to git — rotate it (it may already be pushed)")
	}
	if a.Expired {
		bump(SeverityHigh)
		reasons = append(reasons, "expired — replace it")
	}
	if a.NotGitignored {
		bump(SeverityHigh)
		reasons = append(reasons, "in a git repo but not gitignored — one `git add` from leaking")
	}
	if a.ExpiringSoon {
		bump(SeverityMedium)
		reasons = append(reasons, "expires soon")
	}
	if a.WorldReadable {
		bump(SeverityLow)
		reasons = append(reasons, "readable by other accounts on this computer (marginal)")
	} else if a.GroupReadable {
		bump(SeverityLow)
		reasons = append(reasons, "readable by your group on this computer (marginal)")
	}
	if a.Duplicated {
		reasons = append(reasons, "saved in "+strconv.Itoa(fileCount)+" files — update every copy when rotating")
	}
	return sev, reasons
}

// EffectiveKind is the classifier's verdict unless the user pinned an override.
// Empty/unknown defaults to "secret" (fail-safe), matching app.js and the
// server's own effectiveKind.
func EffectiveKind(s *storage.Secret) string {
	if k := s.Annotation.OverrideKind; k == "secret" || k == "env" {
		return k
	}
	if s.Kind == "env" {
		return "env"
	}
	return "secret"
}

// fileLocations returns the file-backed locations (path set, not a manual
// entry) — the only ones that carry git/permission exposure.
func fileLocations(s *storage.Secret) []storage.FoundIn {
	var out []storage.FoundIn
	for _, f := range s.FoundIn {
		if f.Path != "" && f.SourceType != storage.SourceManual {
			out = append(out, f)
		}
	}
	return out
}

// exampleMarkers mirror the classifier's: a template/example env file is
// committed on purpose and full of placeholders, so its git signals aren't a
// leak.
var exampleMarkers = []string{"example", "sample", "template", ".dist", ".tmpl", ".tpl"}

func isExampleSecret(s *storage.Secret) bool {
	for _, f := range fileLocations(s) {
		b := strings.ToLower(filepath.Base(f.Path))
		for _, m := range exampleMarkers {
			if strings.Contains(b, m) {
				return true
			}
		}
	}
	return false
}

// readableBy reports the widest non-owner read access implied by a "%04o"
// permission string: "other", "group", or "". Mirrors app.js parsePerm.
func readableBy(perms string) string {
	if perms == "" {
		return ""
	}
	n, err := strconv.ParseInt(perms, 8, 32)
	if err != nil {
		return ""
	}
	switch {
	case n&0o004 != 0:
		return "other"
	case n&0o040 != 0:
		return "group"
	default:
		return ""
	}
}

// daysUntilExpiry parses the optional annotation date ("2026-07-01") and
// returns whole days until it (negative if past). ok is false when no valid
// date is set.
func daysUntilExpiry(s *storage.Secret, now time.Time) (int, bool) {
	v := strings.TrimSpace(s.Annotation.ExpiresAt)
	if v == "" {
		return 0, false
	}
	d, err := time.Parse("2006-01-02", v)
	if err != nil {
		return 0, false
	}
	// Ceil of the day difference, matching the UI's Math.ceil.
	diff := d.Sub(now).Hours() / 24
	days := int(diff)
	if diff > float64(days) {
		days++
	}
	return days, true
}
