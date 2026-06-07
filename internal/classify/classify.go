// Package classify decides whether a scanned key=value observation is a real
// secret or ordinary environment/config. It's the fix for the "1,867 findings,
// mostly noise" problem: scanners emit every key=value pair, but PORT=3000 and
// LOG_LEVEL=debug aren't secrets and burying the real ones helps no one.
//
// The cascade is: source → value shape → key name → value triviality →
// entropy, and ambiguous defaults to **secret** (fail safe — a missed real
// secret is far worse than a config line shown in the Secrets list, and the
// user can demote it in one click). The result is derived, recomputed on every
// scan; it isn't user data.
package classify

import (
	"math"
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
	// Empty or obvious placeholder (the .env.example case) is not a live secret.
	if isPlaceholder(v) {
		return KindEnv
	}
	// A recognisable credential value is the strongest signal — even under a
	// "public" key name (a real key mistakenly in NEXT_PUBLIC_* is a *worse*
	// problem, so we want it in Secrets).
	if looksLikeCredentialValue(v) {
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
	// A long high-entropy value under an otherwise-neutral key is probably a
	// token (FOO=9f2c1ae7b3…).
	if highEntropy(v) {
		return KindSecret
	}
	// Ambiguous → fail safe.
	return KindSecret
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

// credentialPrefixes are vendor key prefixes that are unambiguously secret.
// Stripe publishable keys (pk_) are deliberately excluded — they're public.
var credentialPrefixes = []string{
	"sk_live_", "sk_test_", "rk_live_", "rk_test_", // Stripe secret/restricted
	"sk-ant-", "sk-proj-", "sk-", // Anthropic / OpenAI
	"akia", "asia", // AWS access key ids (case-insensitive below)
	"aiza",                                        // Google
	"ghp_", "gho_", "ghs_", "ghu_", "github_pat_", // GitHub
	"glpat-",           // GitLab
	"shppa_", "shpat_", // Shopify
	"sg.",            // SendGrid
	"xoxb-", "xoxp-", // Slack (also reSlack)
	"dop_v1_", // Doppler
}

func looksLikeCredentialValue(v string) bool {
	if rePEM.MatchString(v) || reJWT.MatchString(v) || reURLCreds.MatchString(v) || reSlack.MatchString(v) {
		return true
	}
	lv := strings.ToLower(v)
	for _, p := range credentialPrefixes {
		if strings.HasPrefix(lv, p) {
			return true
		}
	}
	return false
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
	return false
}

// highEntropy reports whether v is long and random-looking enough to be a
// token. Sentences and slugs fall below the threshold; random base62/hex
// strings clear it.
func highEntropy(v string) bool {
	if len(v) < 24 {
		return false
	}
	if strings.ContainsAny(v, " \t") {
		return false // prose, not a token
	}
	return shannon(v) >= 3.5
}

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
