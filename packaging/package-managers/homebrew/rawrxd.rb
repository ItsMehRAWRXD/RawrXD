# rawrxd.rb
# Phase F.1 Batch 1/5: Homebrew formula for RawrXD Sovereign

class Rawrxd < Formula
  desc "Autonomous AI runtime with sovereign execution capabilities"
  homepage "https://rawrxd.ai"
  url "https://github.com/ItsMehRAWRXD/RawrXD/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  head "https://github.com/ItsMehRAWRXD/RawrXD.git", branch: "main"

  depends_on "cmake" => :build
  depends_on "ninja" => :build
  depends_on "python@3.11" => :build
  depends_on "openblas"
  depends_on "libomp"
  depends_on "openssl@3"

  # Optional GPU support
  depends_on "rocm" => :optional

  def install
    args = %W[
      -DCMAKE_BUILD_TYPE=Release
      -DCMAKE_INSTALL_PREFIX=#{prefix}
      -DRWRXD_ENABLE_TESTS=OFF
      -DRWRXD_ENABLE_BENCHMARKS=ON
    ]

    # Enable GPU if ROCm is available
    if build.with? "rocm"
      args << "-DRWRXD_ENABLE_ROCM=ON"
    end

    system "cmake", "-S", ".", "-B", "build", *args
    system "cmake", "--build", "build", "--parallel"
    system "cmake", "--install", "build"

    # Install benchmark suite
    bin.install "build/benchmarks/sovereign_vs_ollama/RawrXD_Benchmark" => "rawrxd-benchmark"

    # Install shell completions
    bash_completion.install "scripts/completions/rawrxd.bash"
    zsh_completion.install "scripts/completions/_rawrxd"
    fish_completion.install "scripts/completions/rawrxd.fish"
  end

  def post_install
    # Create config directory
    (etc/"rawrxd").mkpath

    # Create default config if it doesn't exist
    unless (etc/"rawrxd/config.yaml").exist?
      (etc/"rawrxd/config.yaml").write <<~EOS
        version: "1.0.0"
        runtime:
          threads: auto
          gpu: true
          memory_limit_gb: 0
        benchmark:
          default_model: "phi-3-mini-Q4"
          confidence_level: 0.95
      EOS
    end

    # Create data directory
    (var/"rawrxd").mkpath
  end

  def caveats
    <<~EOS
      RawrXD Sovereign Runtime has been installed!

      Quick start:
        rawrxd --help              # Show help
        rawrxd benchmark --quick   # Run quick benchmark
        rawrxd serve               # Start runtime server

      Configuration:
        Edit #{etc}/rawrxd/config.yaml to customize settings

      Models:
        Place GGUF models in #{var}/rawrxd/models/

      Documentation:
        https://docs.rawrxd.ai
    EOS
  end

  service do
    run [opt_bin/"rawrxd", "serve", "--config", etc/"rawrxd/config.yaml"]
    keep_alive true
    error_log_path var/"log/rawrxd.log"
    log_path var/"log/rawrxd.log"
    working_dir var/"rawrxd"
  end

  test do
    # Test version
    assert_match version.to_s, shell_output("#{bin}/rawrxd --version")

    # Test validation
    system "#{bin}/rawrxd", "validate", "--quick"

    # Test benchmark
    system "#{bin}/rawrxd-benchmark", "--help"
  end
end
