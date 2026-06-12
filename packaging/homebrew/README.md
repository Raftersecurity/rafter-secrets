# Homebrew packaging

Canonical Homebrew formula for Rafter Secrets, plus how it reaches users.

## Status: live

The tap is published at **`Raftersecurity/homebrew-tap`** (public), seeded with
`Formula/rafter-secrets.rb` at v0.3.0 and verified end-to-end:

```sh
brew install raftersecurity/tap/rafter-secrets
```

The tap is a shared repo for the whole Rafter family — add more formulae (e.g.
the Rafter CLI) as `Formula/<name>.rb` in the same repo; users then run
`brew install raftersecurity/tap/<name>`.

To re-seed from scratch (if ever needed):

```sh
mkdir -p tap/Formula && cp rafter-secrets.rb tap/Formula/
cd tap && git init -q && git add -A \
  && git commit -q -m "Add rafter-secrets formula" \
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
