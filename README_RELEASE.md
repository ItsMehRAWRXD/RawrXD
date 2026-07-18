# RawrXD Sovereign - Production Release

## Phase F.1 Complete: Production-Ready Distribution System

This release includes a complete production distribution infrastructure for RawrXD Sovereign.

### Quick Install

**Windows (PowerShell):**
```powershell
winget install RawrXD.SovereignRuntime
# or
choco install rawrxd
# or
irm https://rawrxd.ai/install.ps1 | iex
```

**macOS/Linux (Bash):**
```bash
brew install rawrxd
# or
curl -fsSL https://rawrxd.ai/install.sh | bash
```

**Docker:**
```bash
docker pull rawrxd/sovereign:latest
docker run -p 8080:8080 rawrxd/sovereign serve
```

### Package Contents

This release includes:

#### Core Binaries
- `rawrxd.exe` / `rawrxd` - Sovereign runtime engine
- `rawrxd-benchmark.exe` / `rawrxd-benchmark` - Benchmark suite

#### Benchmark Suite (15 Benchmarks)
1. **InferenceTPSBenchmark** - Token throughput measurement
2. **AgentSpawnBenchmark** - Agent instantiation rate
3. **Swarm16Benchmark** - 16-agent parallel scaling
4. **SEGExecutionBenchmark** - Sovereign Execution Graph
5. **DecisionMakingBenchmark** - Autonomous decision quality
6. **SelfCorrectionBenchmark** - OADEL loop performance
7. **ResponseQualityBenchmark** - Output quality metrics
8. **ContextHandlingBenchmark** - Context window scaling
9. **AutonomousRuntimeBenchmark** - Full OADEL cycle
10. **ResourceUsageBenchmark** - Memory/CPU profiling
11. **FailureStormBenchmark** - Cascading failure resilience
12. **MutationStormBenchmark** - Graph mutation stability
13. **ResourceStarvationBenchmark** - Resource pressure handling
14. **OscillationStormBenchmark** - Oscillation dampening
15. **DegradedHardwareBenchmark** - Hardware failure recovery

#### Scoring Framework
- **SIS (Sovereign Intelligence Score)** - Weighted composite metric
- **Statistical Comparator** - Cohen's d effect sizes
- **Regression Tracker** - Historical performance tracking
- **Report Generator** - HTML/Markdown/PDF outputs

### Verification

All binaries are signed and include SHA256 checksums.

**Windows:**
```powershell
Get-AuthenticodeSignature rawrxd.exe
Get-FileHash rawrxd.exe -Algorithm SHA256
```

**Linux/macOS:**
```bash
gpg --verify rawrxd.tar.gz.asc
sha256sum -c SHA256SUMS
```

### Benchmark Execution

**Quick Validation:**
```bash
rawrxd-benchmark --quick
```

**Full Benchmark Suite:**
```bash
rawrxd-benchmark --backend both --model phi-3-mini-Q4 --runs 50
```

**With Dashboard:**
```powershell
.\packaging\benchmark-execution\benchmark_runner.ps1 `
    -Backend both `
    -GenerateDashboard `
    -ExportCSV
```

### Docker Usage

**Run Benchmarks:**
```bash
docker run rawrxd/sovereign benchmark --quick
docker run rawrxd/sovereign benchmark --full --stress
```

**Start Server:**
```bash
docker run -p 8080:8080 -v /path/to/models:/models rawrxd/sovereign serve
```

**Interactive Shell:**
```bash
docker run -it rawrxd/sovereign shell
```

### Package Manager Integration

| Platform | Package Manager | Command |
|----------|----------------|---------|
| Windows | winget | `winget install RawrXD.SovereignRuntime` |
| Windows | Chocolatey | `choco install rawrxd` |
| macOS | Homebrew | `brew install rawrxd` |
| Linux | APT | `apt install rawrxd` |
| Linux | AUR | `yay -S rawrxd` |
| Universal | Docker | `docker pull rawrxd/sovereign` |

### Security

- **Code Signing**: All Windows binaries signed with Authenticode
- **GPG Signing**: Linux/macOS packages signed with GPG
- **Checksums**: SHA256 checksums for all artifacts
- **Secure Updates**: Signed update channel with rollback support

### CI/CD Integration

GitHub Actions workflows included:
- `build-and-release.yml` - Matrix builds for all platforms
- `benchmark-regression.yml` - Automated regression detection

### Directory Structure

```
packaging/
├── install/
│   ├── installer_builder.ps1    # Windows MSI/NSIS builder
│   └── install.sh               # One-line installer
├── docker/
│   ├── Dockerfile.sovereign-runtime
│   ├── Dockerfile.benchmark-suite
│   ├── docker-compose.yml
│   └── docker-entrypoint.sh
├── package-managers/
│   ├── homebrew/rawrxd.rb
│   ├── chocolatey/
│   │   ├── rawrxd.nuspec
│   │   └── tools/chocolateyinstall.ps1
│   └── winget/rawrxd.yaml
├── security/
│   ├── sign_and_verify.ps1      # Code signing
│   ├── secure_update_channel.ps1 # Update mechanism
│   ├── verify_release.ps1       # Release validation
│   └── gpg_sign.sh              # GPG signing
├── benchmark-execution/
│   └── benchmark_runner.ps1     # Automated runner
└── release/
    ├── version_manager.ps1      # Version bumping
    ├── create_release_package.ps1
    └── RELEASE_CHECKLIST.md
```

### Support

- **Documentation**: https://docs.rawrxd.ai
- **Issues**: https://github.com/ItsMehRAWRXD/RawrXD/issues
- **Discussions**: https://github.com/ItsMehRAWRXD/RawrXD/discussions

### License

MIT License - See LICENSE file for details.

---

**RawrXD Sovereign v1.0.0** - Autonomous AI Runtime with Sovereign Execution
