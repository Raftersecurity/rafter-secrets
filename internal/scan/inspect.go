package scan

import (
	"path/filepath"
	"strings"

	"github.com/Raftersecurity/rafter-secrets/internal/scanners"
)

// Source-kind tags returned by SourceKind. The edit engine dispatches on
// these to choose the right format-aware editor; they mirror scannerFor's
// dispatch exactly so a file that scans is always editable-or-explicitly-not.
const (
	KindDotenv  = "dotenv"
	KindShellRC = "shellrc"
	KindNpmrc   = "npmrc"
	KindAWS     = "aws-credentials"
	KindDocker  = "docker"
	KindGh      = "gh-hosts"
	KindClaude  = "claude"
)

// ScanFile reads a single file with the scanner that matches its path and
// returns every (key, value) it finds. ok is false when no scanner claims
// the path (the file is not a recognised credential source). It never
// mutates the file. The edit engine uses it twice per write: once to
// snapshot the baseline, once to verify the candidate result.
func ScanFile(path string) (found []scanners.FoundSecret, ok bool, err error) {
	fn, ok := scannerFor(path)
	if !ok {
		return nil, false, nil
	}
	out, err := fn(path)
	return out, true, err
}

// SourceKind classifies a path into one of the Kind* tags, or ok=false if
// no scanner recognises it. Dispatch mirrors scannerFor so the two never
// disagree about whether a path is a credential source.
func SourceKind(path string) (kind string, ok bool) {
	base := filepath.Base(path)
	parent := filepath.Base(filepath.Dir(path))

	switch base {
	case ".zshrc", ".bashrc", ".profile", ".zshenv", ".bash_profile":
		return KindShellRC, true
	}
	if base == ".env" || base == ".envrc" || strings.HasPrefix(base, ".env.") {
		return KindDotenv, true
	}
	switch base {
	case ".npmrc":
		return KindNpmrc, true
	case "credentials":
		if parent == ".aws" {
			return KindAWS, true
		}
	case "config.json":
		if parent == ".docker" {
			return KindDocker, true
		}
	case "hosts.yml":
		if parent == "gh" {
			return KindGh, true
		}
	case "settings.json":
		if parent == ".claude" {
			return KindClaude, true
		}
	}
	return "", false
}
