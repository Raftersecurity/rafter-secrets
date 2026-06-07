package classify

import (
	"strings"
	"testing"
)

// Credential-shaped test inputs are assembled at runtime (prefix + filler) so
// no full provider-token literal ever sits in the source — that keeps fake
// fixtures from tripping GitHub's secret-scanning push protection. The filler is
// varied base62 (not repeated chars) so it clears the ruleset's entropy floors,
// the way a real high-entropy token would.
func tok(prefix string, n int) string {
	const cs = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[(i*37+11)%len(cs)]
	}
	return prefix + string(b)
}

func TestClassify(t *testing.T) {
	jwt := "ey" + "J0eXAi" + "." + strings.Repeat("a", 12) + "." + strings.Repeat("b", 12)
	dbURL := "postgres://app:" + "s3cr3tpw" + "@db.internal:5432/app"
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("M", 20)

	cases := []struct {
		key, val, src string
		want          string
	}{
		// Real secrets — by value shape (tokens built at runtime).
		{"STRIPE_KEY", tok("sk_live_", 28), "envfile", KindSecret},
		{"OPENAI_API_KEY", tok("sk-proj-", 28), "envfile", KindSecret},
		{"AWS_ACCESS_KEY_ID", tok("AKIA", 16), "envfile", KindSecret},
		{"TOKEN", jwt, "envfile", KindSecret},
		{"DATABASE_URL", dbURL, "envfile", KindSecret},
		{"PRIVKEY", pem, "envfile", KindSecret},
		// Real secrets — by key name even with a dull value.
		{"SESSION_SECRET", "shorthand", "envfile", KindSecret},
		{"WEBHOOK_SECRET", "whatever123", "envfile", KindSecret},
		// Keystore is always a secret.
		{"login", "anything", "keystore", KindSecret},
		// A high-entropy blob under a NEUTRAL key (no vendor shape, no secret-y
		// name) is now config, not a secret — we don't entropy-guess anymore
		// (this is the false-positive fix: UUIDs / hashes / build IDs).
		{"FOO", "9f2c1ae7b3d84c0fa1e6b27c5d9038af", "envfile", KindEnv},
		// A GitHub PAT is caught by the vendored ruleset.
		{"GH_TOKEN", tok("ghp_", 36), "envfile", KindSecret},
		// A real key mistakenly under a PUBLIC prefix is still a secret.
		{"NEXT_PUBLIC_STRIPE", tok("sk_live_", 24), "envfile", KindSecret},

		// Env / config — not secrets.
		{"PORT", "3000", "envfile", KindEnv},
		{"NODE_ENV", "production", "envfile", KindEnv},
		{"LOG_LEVEL", "debug", "envfile", KindEnv},
		{"DEBUG", "true", "envfile", KindEnv},
		{"NEXT_PUBLIC_API_URL", "https://api.example.com", "envfile", KindEnv},
		{"VITE_APP_TITLE", "My App", "envfile", KindEnv},
		{"BASE_URL", "https://example.com", "envfile", KindEnv},
		{"HOST", "localhost", "envfile", KindEnv},
		// Filesystem paths are pointers to files, not secret values — even when
		// the key name looks secret-y (the path isn't the secret; the file is).
		{"GOOGLE_APPLICATION_CREDENTIALS", "/Users/me/keys/gcp.json", "envfile", KindEnv},
		{"PATH", "/usr/local/bin:/usr/bin:/bin", "shell-rc", KindEnv},
		{"HOME", "/home/me", "shell-rc", KindEnv},
		{"SSL_CERT_FILE", "./certs/server.pem", "envfile", KindEnv},
		{"PRIVATE_KEY_PATH", "~/.ssh/id_rsa", "envfile", KindEnv},
		// ...but a path-shaped key whose VALUE is an actual credential still wins.
		{"PRIVATE_KEY", pem, "envfile", KindSecret},
		// Placeholders (the .env.example case).
		{"API_KEY", "your-api-key-here", "envfile", KindEnv},
		{"SECRET_KEY", "changeme", "envfile", KindEnv},
		{"TOKEN", "<your-token>", "envfile", KindEnv},
		{"PASSWORD", "", "envfile", KindEnv},
	}
	for _, c := range cases {
		if got := Classify(c.key, c.val, c.src, ""); got != c.want {
			t.Errorf("Classify(%q=%q, %s) = %s, want %s", c.key, c.val, c.src, got, c.want)
		}
	}
}
