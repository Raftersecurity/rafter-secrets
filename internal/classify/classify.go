// Package classify decides whether a scanned key=value observation is a real
// secret or ordinary environment/config. It's the fix for the "1,867 findings,
// mostly noise" problem: scanners emit every key=value pair, but PORT=3000 and
// LOG_LEVEL=debug aren't secrets and burying the real ones helps no one.
//
// The positive "this is a credential" signal is generic value shapes (PEM, JWT,
// URL-with-creds, Slack) plus the vendored betterleaks detection ruleset
// (ruleset.go). The cascade is: source → placeholder → credential value → path
// → public prefix → secret-y key name → trivial value → default. Ambiguous now
// defaults to **env**: we no longer guess "secret" from raw entropy (it
// mis-flagged UUIDs, hashes and build IDs); the ruleset is the positive signal,
// and a missed unlabelled token is one click to promote. The result is derived,
// recomputed on every scan; it isn't user data.
package classify

import (
	"math"
	"path/filepath"
	"regexp"
	"strings"
)

// Kinds.
const (
	KindSecret = "secret"
	KindEnv    = "env"
)

// Classify returns KindSecret or KindEnv for one observation. sourceType is a
// storage.Source* tag; path is the file it came from (used only for context).
func Classify(keyName, value, sourceType, path string) string {
	v := strings.TrimSpace(value)
	lk := strings.ToLower(strings.TrimSpace(keyName))

	// The OS keystore only ever holds credentials.
	if sourceType == "keystore" {
		return KindSecret
	}
	// Example/template files (.env.example, .env.sample, …) are documentation,
	// committed on purpose and full of placeholders — never a live secret.
	// Keyed on the FILENAME: the value-based placeholder logic below misses
	// vendor-prefixed fillers like hf_xxxx… that match a credential rule.
	if isExampleFile(path) {
		return KindEnv
	}
	// Empty or obvious placeholder (the .env.example case) is not a live secret.
	if isPlaceholder(v) {
		return KindEnv
	}
	// A recognisable credential value is the strongest signal — even under a
	// "public" key name (a real key mistakenly in NEXT_PUBLIC_* is a *worse*
	// problem, so we want it in Secrets). Generic shapes + the vendored
	// betterleaks ruleset.
	if looksLikeCredentialValue(keyName, v) {
		return KindSecret
	}
	// A filesystem path is a pointer to a file, not a secret value — even under a
	// secret-ish key (GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json, PATH=…).
	// The file it points at is scanned on its own. Checked before the key-name
	// rule so a path-valued "credentials" key isn't mislabelled a secret.
	if isPathValue(v) {
		return KindEnv
	}
	// Public-by-convention env vars ship to browsers by design.
	if hasPublicPrefix(keyName) {
		return KindEnv
	}
	// Secret-ish key name (works even when the value looks unremarkable, e.g.
	// SESSION_SECRET=shorthand).
	if keyLooksSecret(lk) {
		return KindSecret
	}
	// Known-benign config keys.
	if isBenignKey(lk) {
		return KindEnv
	}
	// Trivial values — booleans, numbers, plain URLs, host:port — are config.
	if isBenignValue(v) {
		return KindEnv
	}
	// No known-credential shape and no secret-y key name → treat as config. We
	// no longer guess "secret" from raw entropy (it flagged UUIDs, hashes, build
	// IDs); the vendored ruleset is the positive signal now, so the ambiguous
	// default is env. A missed unlabelled token is one click to promote.
	return KindEnv
}

var (
	reAngle      = regexp.MustCompile(`^<.*>$`)
	reYourKey    = regexp.MustCompile(`^(your|my|the)[-_ ]?(api[-_ ]?)?(key|secret|token|password|pass|pwd)`)
	reAllStars   = regexp.MustCompile(`^[*•.xX]{3,}$`)
	rePEM        = regexp.MustCompile(`-----BEGIN[ A-Z]*PRIVATE KEY-----`)
	reJWT        = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.`)
	reURLCreds   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@`)
	reSlack      = regexp.MustCompile(`^xox[baprs]-`)
	reNumber     = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
	rePlainURL   = regexp.MustCompile(`^https?://[^@\s]+$`)
	reHostPort   = regexp.MustCompile(`^[\w.-]+:\d{2,5}$`)
	reSecretName = regexp.MustCompile(`(secret|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key|priv[_-]?key|auth[_-]?token|oauth[_-]?token|_token$|^token|signing|bearer|credential|encryption[_-]?key|webhook[_-]?secret|session[_-]?secret|dsn$)`)
	// Absolute, home, relative, Windows-drive paths, or a colon-list of them
	// (PATH=/usr/bin:/bin). A value with whitespace isn't treated as a path.
	rePath = regexp.MustCompile(`^(~?/|\.\.?/|[A-Za-z]:[\\/])\S`)
)

func isPathValue(v string) bool {
	if v == "" || strings.ContainsAny(v, " \t") {
		return false
	}
	return rePath.MatchString(v)
}

// looksLikeCredentialValue is the positive "this value is a credential" signal:
// cheap generic shapes (PEM / JWT / URL-with-creds / Slack) first, then the
// vendored betterleaks ruleset (matchesRuleset, ruleset.go) — which subsumes the
// old hand-rolled vendor-prefix list with far broader, tuned coverage.
func looksLikeCredentialValue(keyName, v string) bool {
	if rePEM.MatchString(v) || reJWT.MatchString(v) || reURLCreds.MatchString(v) || reSlack.MatchString(v) {
		return true
	}
	return matchesRuleset(keyName, v)
}

var publicPrefixes = []string{
	"NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_", "EXPO_PUBLIC_",
	"GATSBY_", "NUXT_PUBLIC_", "STORYBOOK_",
}

func hasPublicPrefix(keyName string) bool {
	u := strings.ToUpper(strings.TrimSpace(keyName))
	for _, p := range publicPrefixes {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}

func keyLooksSecret(lowerKey string) bool { return reSecretName.MatchString(lowerKey) }

var benignKeys = map[string]bool{
	"node_env": true, "rails_env": true, "app_env": true, "env": true,
	"environment": true, "port": true, "host": true, "hostname": true,
	"debug": true, "log_level": true, "loglevel": true, "verbose": true,
	"tz": true, "timezone": true, "lang": true, "locale": true,
	"base_url": true, "api_url": true, "app_url": true, "public_url": true,
	"frontend_url": true, "backend_url": true, "vite_port": true,
}

func isBenignKey(lowerKey string) bool { return benignKeys[lowerKey] }

var benignWords = map[string]bool{
	"true": true, "false": true, "yes": true, "no": true, "on": true,
	"off": true, "development": true, "production": true, "staging": true,
	"test": true, "local": true, "localhost": true, "debug": true, "info": true,
	"warn": true, "error": true, "none": true,
}

func isBenignValue(v string) bool {
	lv := strings.ToLower(v)
	if benignWords[lv] || reNumber.MatchString(v) || rePlainURL.MatchString(v) || reHostPort.MatchString(v) {
		return true
	}
	return false
}

var placeholderWords = map[string]bool{
	"changeme": true, "change-me": true, "change_me": true, "xxx": true,
	"xxxx": true, "placeholder": true, "example": true, "todo": true,
	"none": true, "null": true, "nil": true, "secret": true, "password": true,
	"your_api_key": true, "your-api-key": true, "your_secret": true,
	"yourkeyhere": true, "replace_me": true, "redacted": true, "dummy": true,
}

func isPlaceholder(v string) bool {
	if v == "" {
		return true
	}
	lv := strings.ToLower(v)
	if placeholderWords[lv] || reAngle.MatchString(v) || reYourKey.MatchString(lv) || reAllStars.MatchString(v) {
		return true
	}
	// Vendor-prefix + filler: hf_xxxx…, sk_live_0000…, ghp_AAAA…. A real token is
	// high-entropy; a long value with near-zero entropy is placeholder filler,
	// even when it matches a credential regex (some rules have no entropy floor).
	if len(v) >= 12 && shannon(v) < 2.0 {
		return true
	}
	return false
}

// exampleMarkers identify documentation/template env files by filename.
var exampleMarkers = []string{"example", "sample", "template", ".dist", ".tmpl", ".tpl"}

// isExampleFile reports whether path is a template/example env file
// (.env.example, .env.sample, .env.template, .env.dist, …) — committed on
// purpose, never a live secret.
func isExampleFile(path string) bool {
	if path == "" {
		return false
	}
	b := strings.ToLower(filepath.Base(path))
	for _, m := range exampleMarkers {
		if strings.Contains(b, m) {
			return true
		}
	}
	return false
}

// shannon is the per-byte Shannon entropy of s, used to clear a rule's entropy
// floor (ruleset.go) so low-entropy lookalikes don't match a credential regex.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]float64
	n := 0
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
		n++
	}
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := c / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}
