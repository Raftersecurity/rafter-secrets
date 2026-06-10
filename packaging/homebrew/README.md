# Homebrew packaging

Canonical Homebrew formula for Rafter Secrets, plus how it reaches users.

## One-time setup (human — needs org permission)

The tap install command is:

```sh
brew install raftersecurity/tap/rafter-secrets
```

…which resolves to the repo **`Raftersecurity/homebrew-tap`**. That repo does
not exist yet and must be created by someone with repo-create permission on the
`Raftersecurity` org (a regular member without that permission gets
`cannot create a repository for Raftersecurity`). To create it:

```sh
gh repo create Raftersecurity/homebrew-tap --public \
  --description "Homebrew tap for Rafter Secrets"
# then seed it:
mkdir -p tap/Formula && cp rafter-secrets.rb tap/Formula/
cd tap && git init -q && git add -A \
  && git commit -q -m "Add rafter-secrets formula at v0.2.0" \
  && git branch -M main \
  && git remote add origin https://github.com/Raftersecurity/homebrew-tap \
  && git push -u origin main
```

## Each release

`rafter-secrets.rb` here is the source of truth. On a new tag:

1. Bump `version` and the four `sha256` values from the release's `SHA256SUMS`.
2. Copy this file to `Raftersecurity/homebrew-tap:Formula/rafter-secrets.rb`.

This is a few lines in the release GitHub Action — wire it up so the tap
self-updates on every tagged release.
