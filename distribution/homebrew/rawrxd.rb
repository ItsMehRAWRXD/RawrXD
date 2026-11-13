# rawrxd.rb
# Phase H.2 Batch 3/5: Homebrew Formula
#
# STATUS: NOT_PUBLISHED · DRAFT_SHA_BOUND · PROMOTE=0 · CERTIFIED=0
# FORMULA_INSTALLABLE=0 — macOS tarball ABSENT on measured tags.
# sha256 below is the MEASURED Windows zip (v14.7.3) for cross-ref bind only.
# Do NOT `brew install` until a real macOS artifact + clean-VM witness exist.
# Authority: evidence/PRODUCTION_MATURITY_TOP25_001/TOP25_RECOGNITION_OPS_001/
# Witness: release_assets/SHA256.txt
#
# Measured Windows SHAs (2026-11-13):
#   RawrXD-14.7.3-Windows-x64.zip =
#     DDEB7D50840C1097B2C79A5702C54C115BD076B108F9C43D15BCB4BE563B829D
#   RawrXD-v1.0.0-Release.zip =
#     3B692DDC9F14D75D373CB682CE1968B9B3E25074327254F88CFE910DE8BDE7D5

class Rawrxd < Formula
  desc "Sovereign AI runtime (DRAFT_SHA_BOUND; NOT_PUBLISHED; macOS asset ABSENT)"
  homepage "https://github.com/ItsMehRAWRXD/RawrXD"
  # Windows zip URL used only as SHA-bind registry; not a macOS bottle claim.
  url "https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v14.7.3/RawrXD-14.7.3-Windows-x64.zip"
  sha256 "ddeb7d50840c1097b2c79a5702c54c115bd076b108f9c43d15bcb4be563b829d"
  license "MIT"
  version "14.7.3"

  depends_on arch: :x86_64
  depends_on macos: :big_sur

  def install
    odie <<~EOS
      RawrXD Homebrew formula is NOT_PUBLISHED / FORMULA_INSTALLABLE=0.
      sha256 is DRAFT_SHA_BOUND to the Windows zip only; macOS tarball ABSENT.
      Use repo INSTALL.md (local cmake/ninja → rawr.exe) instead.
    EOS
  end

  def caveats
    <<~EOS
      STATUS: NOT_PUBLISHED · DRAFT_SHA_BOUND · PROMOTE=0
      This formula must not be treated as an install path.
    EOS
  end

  test do
    odie "NOT_PUBLISHED — no brew test until macOS artifact + clean-VM witness"
  end
end
