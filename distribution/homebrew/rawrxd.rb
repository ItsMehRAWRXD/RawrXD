# rawrxd.rb
# Phase H.2 Batch 3/5: Homebrew Formula
# Usage: brew install --cask rawrxd
#
# STATUS: NOT_PUBLISHED · PROMOTE=0 · CERTIFIED=0
# sha256 is PLACEHOLDER — formula is draft only until real artifact + checksum bind.
# Authority: evidence/PRODUCTION_MATURITY_TOP25_001/TOP25_RECOGNITION_OPS_001/

class Rawrxd < Formula
  desc "Sovereign AI runtime with autonomous capabilities"
  homepage "https://rawrxd.ai"
  url "https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v1.0.0/RawrXD-1.0.0-macOS.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  version "1.0.0"

  depends_on arch: :x86_64
  depends_on macos: :big_sur

  def install
    bin.install "RawrXD"
    (etc/"rawrxd").install "config/rawrxd.yaml" => "rawrxd.yaml.default"
    (var/"log/rawrxd").mkpath
    (var/"lib/rawrxd").mkpath
  end

  def post_install
    (var/"log/rawrxd").mkpath
    (var/"lib/rawrxd").mkpath

    # Create config from template if doesn't exist
    unless (etc/"rawrxd/rawrxd.yaml").exist?
      (etc/"rawrxd").install "rawrxd.yaml.default" => "rawrxd.yaml"
    end
  end

  def caveats
    <<~EOS
      RawrXD Sovereign has been installed!

      Configuration file: #{etc}/rawrxd/rawrxd.yaml
      Log directory: #{var}/log/rawrxd
      Data directory: #{var}/lib/rawrxd

      To start RawrXD:
        rawrxd --config #{etc}/rawrxd/rawrxd.yaml

      Or use launchd service:
        brew services start rawrxd

      Documentation: https://docs.rawrxd.ai
    EOS
  end

  service do
    run [opt_bin/"RawrXD", "--config", etc/"rawrxd/rawrxd.yaml"]
    keep_alive true
    log_path var/"log/rawrxd/service.log"
    error_log_path var/"log/rawrxd/error.log"
    environment_variables PATH: std_service_path_env
  end

  test do
    system "#{bin}/RawrXD", "--version"
  end
end
