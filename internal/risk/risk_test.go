package risk

import (
	"testing"
	"time"

	"github.com/Raftersecurity/rafter-secrets/internal/storage"
)

func bptr(v bool) *bool { return &v }

func secret(kind string, files ...storage.FoundIn) *storage.Secret {
	return &storage.Secret{KeyName: "K", Kind: kind, FoundIn: files}
}

func TestAssess_Severity(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

	committed := storage.FoundIn{SourceType: storage.SourceEnvFile, Path: "/p/.env", Permissions: "0600",
		InGitRepo: bptr(true), AppearsInGitHistory: bptr(true)}
	notIgnored := storage.FoundIn{SourceType: storage.SourceEnvFile, Path: "/p/.env", Permissions: "0600",
		InGitRepo: bptr(true), InGitignore: bptr(false), AppearsInGitHistory: bptr(false)}
	ignored := storage.FoundIn{SourceType: storage.SourceEnvFile, Path: "/p/.env", Permissions: "0600",
		InGitRepo: bptr(true), InGitignore: bptr(true)}
	worldReadable := storage.FoundIn{SourceType: storage.SourceEnvFile, Path: "/p/.env", Permissions: "0644"}
	exampleCommitted := storage.FoundIn{SourceType: storage.SourceEnvFile, Path: "/p/.env.example", Permissions: "0600",
		InGitRepo: bptr(true), AppearsInGitHistory: bptr(true)}

	cases := []struct {
		name string
		s    *storage.Secret
		want Severity
	}{
		{"committed to git is critical", secret("secret", committed), SeverityCritical},
		{"committed env/config is not a leak", secret("env", committed), SeverityNone},
		{"not gitignored is high", secret("secret", notIgnored), SeverityHigh},
		{"gitignored is clean", secret("secret", ignored), SeverityNone},
		{"world-readable only is low (chmod is marginal)", secret("secret", worldReadable), SeverityLow},
		{"example file in git history is not a leak", secret("secret", exampleCommitted), SeverityNone},
	}
	for _, c := range cases {
		if got := assessAt(c.s, now).Severity; got != c.want {
			t.Errorf("%s: severity = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestAssess_StaleNeverRisky(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	s := secret("secret", storage.FoundIn{SourceType: storage.SourceEnvFile, Path: "/p/.env",
		InGitRepo: bptr(true), AppearsInGitHistory: bptr(true)})
	s.Annotation.Stale = true
	a := assessAt(s, now)
	if a.Severity != SeverityNone {
		t.Errorf("stale committed secret severity = %q, want none", a.Severity)
	}
	if !a.CommittedToGit {
		t.Error("committed_to_git signal should still be reported even when stale")
	}
}

func TestAssess_Expiry(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	mk := func(date string) *storage.Secret {
		s := secret("secret", storage.FoundIn{SourceType: storage.SourceEnvFile, Path: "/p/.env", Permissions: "0600"})
		s.Annotation.ExpiresAt = date
		return s
	}
	if got := assessAt(mk("2026-06-01"), now).Severity; got != SeverityHigh { // past
		t.Errorf("expired severity = %q, want high", got)
	}
	if got := assessAt(mk("2026-07-10"), now).Severity; got != SeverityMedium { // ~10 days
		t.Errorf("expiring-soon severity = %q, want medium", got)
	}
	if got := assessAt(mk("2027-06-01"), now).Severity; got != SeverityNone { // far future
		t.Errorf("far-future severity = %q, want none", got)
	}
}

func TestAssess_Duplicated(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	a := assessAt(secret("secret",
		storage.FoundIn{SourceType: storage.SourceEnvFile, Path: "/a/.env", Permissions: "0600"},
		storage.FoundIn{SourceType: storage.SourceEnvFile, Path: "/b/.env", Permissions: "0600"},
	), now)
	if !a.Duplicated {
		t.Error("two file locations should be duplicated")
	}
	if a.Severity != SeverityNone {
		t.Errorf("duplication alone is informational, severity = %q, want none", a.Severity)
	}
}

func TestEffectiveKind(t *testing.T) {
	s := secret("env")
	if EffectiveKind(s) != "env" {
		t.Error("classifier env should be env")
	}
	s.Annotation.OverrideKind = "secret"
	if EffectiveKind(s) != "secret" {
		t.Error("override should win")
	}
	if EffectiveKind(secret("")) != "secret" {
		t.Error("empty kind defaults to secret")
	}
}
