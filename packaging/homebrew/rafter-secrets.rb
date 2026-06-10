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
  version "0.2.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Raftersecurity/rafter-secrets/releases/download/v0.2.0/rafter-secrets-darwin-arm64"
      sha256 "78082b19704c760066bd3a18d8c7d9c0fd516e442d4bff19d9e0eb255525d823"
    end
    on_intel do
      url "https://github.com/Raftersecurity/rafter-secrets/releases/download/v0.2.0/rafter-secrets-darwin-amd64"
      sha256 "91b4ee7cb7d4a6e8b1e64eee88e95f62bf198d86a6b0c39a943fd8b531c9dae7"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Raftersecurity/rafter-secrets/releases/download/v0.2.0/rafter-secrets-linux-arm64"
      sha256 "bb4ed8e8c86d320360fef6929e6404195159eee6ecc53f6b008fbbefd1840f95"
    end
    on_intel do
      url "https://github.com/Raftersecurity/rafter-secrets/releases/download/v0.2.0/rafter-secrets-linux-amd64"
      sha256 "e6c97d9fcbee6a1b4bb64acddbbd3ccac1a1a6b1309be529f6aaf43f7712ea76"
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
