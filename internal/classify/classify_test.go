package classify

import (
	"strings"
	"testing"
)

// Credential-shaped test inputs are assembled at runtime (prefix + filler) so
// no full provider-token literal ever sits in the source — that keeps fake
// fixtures from tripping GitHub's secret-scanning push protection while still
// exercising the classifier's prefix/shape rules.
func tok(prefix string, n int) string { return prefix + strings.Repeat("a", n) }

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
		// High-entropy token under a neutral key.
		{"FOO", "9f2c1ae7b3d84c0fa1e6b27c5d9038af", "envfile", KindSecret},
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
