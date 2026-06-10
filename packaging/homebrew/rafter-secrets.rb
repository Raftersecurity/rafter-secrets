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
  version "0.3.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Raftersecurity/rafter-secrets/releases/download/v0.3.0/rafter-secrets-darwin-arm64"
      sha256 "c92b82fb8e2bfbce09e0f988a32386592c96dfda4fdf0cc703b097cffd0d9c2f"
    end
    on_intel do
      url "https://github.com/Raftersecurity/rafter-secrets/releases/download/v0.3.0/rafter-secrets-darwin-amd64"
      sha256 "1badd51ae1f73015f6960b7182858ba890dd79c796d7520e583559e6b789f4f8"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Raftersecurity/rafter-secrets/releases/download/v0.3.0/rafter-secrets-linux-arm64"
      sha256 "82c26c4d3577bf3d0f80628190acc0a25a1fe6cee209f6daa2c4b1dc70ff4c43"
    end
    on_intel do
      url "https://github.com/Raftersecurity/rafter-secrets/releases/download/v0.3.0/rafter-secrets-linux-amd64"
      sha256 "8106c53ec560d48d5ba0d517729cd06ea537a2340cb68e28fe5019c382fcc020"
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
