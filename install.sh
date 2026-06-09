#!/bin/sh
# Rafter Secrets installer.
#
#   curl -fsSL https://raftersecurity.github.io/rafter-secrets/install.sh | sh
#
# Auto-detects your OS + CPU, downloads the matching binary from the latest
# GitHub release, verifies its SHA256, and installs it to a bin dir on PATH.
# Nothing else — no account, no telemetry. Override the target with
# RAFTER_INSTALL_DIR=/somewhere.
set -eu

REPO="Raftersecurity/rafter-secrets"
BIN="rafter-secrets"
BASE="https://github.com/$REPO/releases/latest/download"

fail() { echo "rafter-secrets: $1" >&2; exit 1; }

# --- detect os / arch -------------------------------------------------------
os=$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')
case "$os" in
  darwin) os=darwin ;;
  linux)  os=linux ;;
  *) fail "unsupported OS '$os' (macOS and Linux only). Build from source: https://github.com/$REPO" ;;
esac
arch=$(uname -m 2>/dev/null)
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) fail "unsupported CPU '$arch' (amd64/arm64 only)." ;;
esac
asset="${BIN}-${os}-${arch}"

command -v curl >/dev/null 2>&1 || fail "curl is required."

# --- pick an install dir on PATH (avoid sudo when we can) -------------------
if [ -n "${RAFTER_INSTALL_DIR:-}" ]; then
  dir="$RAFTER_INSTALL_DIR"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
  dir="/usr/local/bin"
else
  dir="$HOME/.local/bin"
fi
mkdir -p "$dir" || fail "cannot create install dir $dir"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "rafter-secrets: downloading $asset…"
curl -fSL -o "$tmp/$BIN" "$BASE/$asset" || fail "download failed for $asset"

# --- verify checksum against the release SHA256SUMS (mandatory) -------------
# Fail closed: a security tool should never install an unverified binary. Set
# RAFTER_SKIP_VERIFY=1 to override (e.g. air-gapped mirror without sums).
if [ "${RAFTER_SKIP_VERIFY:-}" = "1" ]; then
  echo "rafter-secrets: WARNING — skipping checksum verification (RAFTER_SKIP_VERIFY=1)." >&2
else
  curl -fSL -o "$tmp/SHA256SUMS" "$BASE/SHA256SUMS" \
    || fail "could not fetch SHA256SUMS to verify the download (set RAFTER_SKIP_VERIFY=1 to override)."
  want=$(awk -v a="$asset" '$2==a {print $1}' "$tmp/SHA256SUMS")
  [ -n "$want" ] || fail "no checksum listed for $asset (set RAFTER_SKIP_VERIFY=1 to override)."
  if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$tmp/$BIN" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "$tmp/$BIN" | awk '{print $1}')
  else
    fail "no sha256sum/shasum available to verify the download (set RAFTER_SKIP_VERIFY=1 to override)."
  fi
  [ "$want" = "$got" ] || fail "checksum mismatch — aborting (expected $want, got $got)."
  echo "rafter-secrets: checksum verified."
fi

chmod +x "$tmp/$BIN"
mv "$tmp/$BIN" "$dir/$BIN" || fail "could not install to $dir"
echo "rafter-secrets: installed to $dir/$BIN"

case ":$PATH:" in
  *":$dir:"*) echo "Run it:  $BIN" ;;
  *) echo "Add $dir to your PATH, then run:  $BIN" ;;
esac
