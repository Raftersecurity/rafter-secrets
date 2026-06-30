# Rafter Secrets — Homebrew formula.
#
#   brew install raftersecurity/tap/rafter-secrets
#
# This is the canonical copy. It ships to the tap by copying this file to
# Raftersecurity/homebrew-tap:Formula/rafter-secrets.rb. Prebuilt,
# checksum-pinned binaries from the GitHub Release — no toolchain needed.
# Bump `version` + the four sha256s on each release (the release GitHub Action
# can automate this from the published SHA256SUMS).
class RafterSecrets < Formula
  desc "See and manage every secret sitting in plain text on your machine"
  homepage "https://github.com/Raftersecurity/rafter-secrets"
  version "0.4.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Raftersecurity/rafter-secrets/releases/download/v0.4.0/rafter-secrets-darwin-arm64"
      sha256 "54f47781bb73925262d06d29c683773f2776925715b52f2d15cf2be24a2bf230"
    end
    on_intel do
      url "https://github.com/Raftersecurity/rafter-secrets/releases/download/v0.4.0/rafter-secrets-darwin-amd64"
      sha256 "2e63192b3296fd4309c563ba1efc9b769e571eff5e8f7e99f3978e496e8e2239"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Raftersecurity/rafter-secrets/releases/download/v0.4.0/rafter-secrets-linux-arm64"
      sha256 "f709c752f004d9f16dbc47336520945bca7eb23c954a24039a0bd593af5b5575"
    end
    on_intel do
      url "https://github.com/Raftersecurity/rafter-secrets/releases/download/v0.4.0/rafter-secrets-linux-amd64"
      sha256 "4cf9185285ec94a7fba365f856df5315a0460668a3124188a62364efb0a7193c"
    end
  end

  def install
    # The release ships one bare binary per platform; install it unsuffixed.
    bin.install Dir["rafter-secrets-*"].first => "rafter-secrets"
  end

  test do
    assert_match "Rafter Secrets", shell_output("#{bin}/rafter-secrets --help")
  end
end
