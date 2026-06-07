# Vendored detection ruleset — betterleaks

`betterleaks.rules.json` is a **distilled** copy of the betterleaks secret-
detection rule pack, used as the positive "is this value a known credential?"
signal in `internal/classify`.

- **Upstream:** https://github.com/betterleaks/betterleaks (MIT, by Zachary
  Rice, original author of gitleaks)
- **Pinned commit:** `40d5cafea2045d16a217c1b70a69d6bba6b892ec`
- **Source file:** `config/betterleaks.toml` (280 rules)
- **License:** MIT — see `LICENSE` in this directory.

## What we kept / dropped

We vendor **only the detection fields** — per rule: `id`, `kw` (keywords,
lowercased), `re` (RE2 regex), `ent` (entropy floor, parsed from the rule's
`entropy =` field or a `filter` of the form `entropy(finding["secret"]) <= X`).

We deliberately **drop** every rule's `validate` CEL clause (the upstream
liveness check makes an HTTP request *with the secret*). Rafter never transmits
secret values, so that code/data is not shipped. Descriptions, tags, and complex
CEL filters are also dropped.

## Regenerate (to re-sync with upstream)

```
gh api repos/betterleaks/betterleaks/contents/config/betterleaks.toml \
  --jq '.content' | base64 -d > /tmp/betterleaks.toml
python3 scripts/distill-betterleaks.py /tmp/betterleaks.toml \
  > internal/classify/rules/betterleaks.rules.json
```

Then bump the pinned commit above. All 279 emitted regexes compile under Go RE2.

## Expected: secret scanners will "flag" this file

This file is a pack of secret-shaped regexes, so any secret scanner — including
rafter/betterleaks itself — will self-match patterns in it (e.g. an
`aws-amazon-bedrock` HIGH on the bedrock rule's own literal). That's a **false
positive on vendored rule data**, not a leaked credential.

Note: rafter-secrets (this product) does **not** scan this file — its dispatcher
only reads specific named files (`.env*`, `.npmrc`, `.aws/credentials`, …), and a
generic `.json` is never opened. The self-flag only happens with general
text scanners (`rafter secrets`, gitleaks, etc.). For CI, scan changed files
(`--diff`/`--staged`) so the unchanged pack doesn't re-flag, or treat this path
as a known allowlisted false positive.
