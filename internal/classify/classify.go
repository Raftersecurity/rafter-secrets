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
	// Public-by-convention env vars (NEXT_PUBLIC_*, VITE_*, …) ship to the
	// browser by design — a publishable key belongs there: Stripe pk_, a
	// Supabase anon JWT, a Firebase/Maps config key. So a public-prefixed key is
	// env even when its value looks credential-shaped. The ONE exception is a
	// genuinely-PRIVATE credential (a private key, a URL with embedded creds, a
	// secret-class provider token like sk_live_/ghp_/AKIA): shipping one of
	// those to the browser is a real leak, so keep flagging it as a secret.
	// Checked before the generic credential-value rule so publishable values
	// aren't swept into Secrets.
	if hasPublicPrefix(keyName) {
		if looksLikePrivateCredential(v) {
			return KindSecret
		}
		return KindEnv
	}
	// A recognisable credential value is the strongest signal. Generic shapes +
	// the vendored betterleaks ruleset.
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
	"GATSBY_", "NUXT_PUBLIC_", "NUXT_ENV_", "STORYBOOK_", "VUE_APP_",
	"REDWOOD_ENV_",
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

// rePrivateCred matches value prefixes that are unambiguously a SECRET (never
// a publishable key), so we still flag them when they appear under a public
// prefix — that's a real key mistakenly shipped to the browser. Deliberately
// excludes publishable shapes (Stripe pk_, JWTs/anon keys, Google AIza* map
// keys), which under a public prefix are working-as-intended.
var rePrivateCred = regexp.MustCompile(`(?i)^(` +
	`sk_live_|sk_test_|rk_live_|rk_test_|` + // Stripe secret / restricted
	`sk-ant-|sk-proj-|sk-[a-z0-9]{20}|` + // Anthropic / OpenAI secret keys
	`gh[posur]_|github_pat_|glpat-|` + // GitHub / GitLab tokens
	`xox[baprs]-|` + // Slack tokens
	`shp(ss|at|ca|pa)_|` + // Shopify tokens
	`npm_|` + // npm token
	`AKIA|ASIA` + // AWS access key id
	`)`)

// looksLikePrivateCredential reports whether v is a genuinely-private secret
// (vs a publishable key). Used only to decide whether a public-prefixed var is
// a real leak. A private-key PEM or a URL with embedded credentials is always
// private; otherwise we match the known secret-class provider prefixes.
func looksLikePrivateCredential(v string) bool {
	if rePEM.MatchString(v) || reURLCreds.MatchString(v) {
		return true
	}
	return rePrivateCred.MatchString(v)
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
	// Fake/demo values under a secret-y key (GITHUB_TOKEN=ghp_FakeToken…,
	// SIGNING_KEY=your-signing-key). These don't match any credential rule, but
	// keyLooksSecret would still promote them — catch them here first.
	return looksFakeValue(v)
}

// fakeWords are obvious non-secret markers; if one appears in the value it's a
// demo/placeholder, not a live credential.
var fakeWords = []string{
	"fake", "dummy", "example", "sample", "placeholder", "changeme", "change-me",
	"redacted", "your-", "your_", "yourkey", "todo", "insert-", "replace-me",
	"replaceme", "notreal", "specimen", "test-key", "test_key",
}

// reSlug matches an all-lowercase, hyphen/underscore-separated slug
// (local-secret, sk-fake-openai-key-12345, projectcare-ai-super-secret-key-2024).
// Real tokens are one long high-entropy run, usually mixed-case — never a tidy
// run of dictionary words.
var reSlug = regexp.MustCompile(`^[a-z0-9]+(?:[-_][a-z0-9]+)+$`)

func looksFakeValue(v string) bool {
	lv := strings.ToLower(v)
	for _, w := range fakeWords {
		if strings.Contains(lv, w) {
			return true
		}
	}
	if !reSlug.MatchString(v) {
		return false
	}
	// All segments are short, word-like — not a 20+ char random token chunk.
	for _, seg := range strings.FieldsFunc(v, func(r rune) bool { return r == '-' || r == '_' }) {
		if len(seg) > 16 {
			return false
		}
	}
	return true
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
