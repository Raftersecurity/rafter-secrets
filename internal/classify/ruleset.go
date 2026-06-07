package classify

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
)

// betterleaks detection rules (distilled — see rules/NOTICE.md). Vendored as the
// positive "this value is a known credential" signal, replacing the old
// hand-rolled prefix list. We use only keywords + regex + entropy floor; the
// upstream `validate` (liveness-over-HTTP) clauses are deliberately not shipped.
//
//go:embed rules/betterleaks.rules.json
var rulesJSON []byte

type rawRule struct {
	ID  string   `json:"id"`
	Kw  []string `json:"kw"`
	Re  string   `json:"re"`
	Ent float64  `json:"ent"`
}

type compiledRule struct {
	kw  []string
	re  *regexp.Regexp
	ent float64
}

var ruleset []compiledRule

func init() {
	var rs []rawRule
	if err := json.Unmarshal(rulesJSON, &rs); err != nil {
		return // ruleset unavailable; generic shapes + key/value heuristics still apply
	}
	for _, r := range rs {
		re, err := regexp.Compile(r.Re)
		if err != nil {
			continue // skip any rule that won't compile under RE2 (none today)
		}
		ruleset = append(ruleset, compiledRule{kw: r.Kw, re: re, ent: r.Ent})
	}
}

// matchesRuleset reports whether value looks like a known credential per the
// vendored betterleaks rules: a rule whose keyword appears in the key-or-value,
// whose regex matches the value, and (if the rule sets an entropy floor) whose
// value clears it. The keyword prefilter keeps this cheap — only the handful of
// rules whose keyword is present run their regex.
func matchesRuleset(keyName, value string) bool {
	if len(ruleset) == 0 || value == "" {
		return false
	}
	hay := strings.ToLower(keyName + " " + value)
	for i := range ruleset {
		r := &ruleset[i]
		if !anyKeyword(hay, r.kw) {
			continue
		}
		if !r.re.MatchString(value) {
			continue
		}
		if r.ent > 0 && shannon(value) < r.ent {
			continue
		}
		return true
	}
	return false
}

// anyKeyword reports whether any keyword is a substring of hay. A rule with no
// keywords always runs (betterleaks semantics) — though all current rules have
// at least one.
func anyKeyword(hay string, kws []string) bool {
	if len(kws) == 0 {
		return true
	}
	for _, k := range kws {
		if k == "" || strings.Contains(hay, k) {
			return true
		}
	}
	return false
}
