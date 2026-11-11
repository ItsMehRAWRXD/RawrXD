# RawrXD Validation Framework - Complete Index

**Quick Navigation** | **Last Updated:** 2026-07-30 | **Version:** 1.0.0

---

## 🚀 Quick Start (5 Minutes)

New to the validation framework? Start here:

1. **[QUICKSTART.md](QUICKSTART.md)** - Get up and running in 5 minutes
2. **Build the framework:** `cd harness && build.bat`
3. **Run validation:** `.\Validate-Production.ps1`
4. **View results:** Open `dashboard/ValidationDashboard.html`

---

## 📚 Documentation

### Getting Started
| Document | Purpose | Read Time |
|----------|---------|-----------|
| [QUICKSTART.md](QUICKSTART.md) | 5-minute quick start guide | 5 min |
| [harness/README.md](harness/README.md) | Component documentation | 15 min |
| [tools/README.md](tools/README.md) | Additional utilities | 10 min |

### Comprehensive Guides
| Document | Purpose | Read Time |
|----------|---------|-----------|
| [PRODUCTION_READINESS_GUIDE.md](../PRODUCTION_READINESS_GUIDE.md) | Complete production readiness | 30 min |
| [VALIDATION_FRAMEWORK_SUMMARY.md](../VALIDATION_FRAMEWORK_SUMMARY.md) | Framework overview | 20 min |
| [VERIFICATION_STATUS.md](../VERIFICATION_STATUS.md) | Architecture verification | 15 min |

---

## 🔧 Components

### Core Validation (harness/)
```
harness/
├── ValidationHarness.cpp      # Main validation suite (~400 lines)
├── HardwareValidator.cpp        # GPU detection (~350 lines)
├── RealInferenceBenchmark.cpp # Performance testing (~450 lines)
├── TelemetryCollector.cpp     # Real-time monitoring (~400 lines)
├── include/
│   └── ValidationTypes.hpp    # Common types (~150 lines)
├── build.bat                  # Build script
└── CMakeLists.txt             # CMake configuration
```

**Build:** `cd harness && build.bat`  
**Output:** 4 executables (ValidationHarness.exe, HardwareValidator.exe, etc.)

### Orchestration Scripts
| Script | Purpose | Usage |
|--------|---------|-------|
| `Validate-Production.ps1` | Full validation pipeline | `.\Validate-Production.ps1 -BenchmarkRuns 100` |
| `Run-Validation.ps1` | Quick validation | `.\Run-Validation.ps1 -Iterations 10` |
| `ci/Validate-CI.ps1` | CI/CD integration | See [CI Guide](ci/README.md) |

### Additional Tools (tools/)
| Tool | Purpose | Usage |
|------|---------|-------|
| `Compare-ValidationResults.ps1` | Compare runs | Track improvements/regressions |
| `Generate-ValidationReport.ps1` | Generate reports | Executive/technical/CI reports |

### Visualization
| Component | Purpose | Usage |
|-----------|---------|-------|
| `dashboard/ValidationDashboard.html` | Web dashboard | Open in browser |

---

## 📊 Validation Artifacts

Running the framework generates **9 artifacts**:

| Artifact | Format | Purpose |
|----------|--------|---------|
| `boot.log` / `boot_report.json` | Text/JSON | IDE startup timing |
| `gateway.log` | Text | REST API validation |
| `inference_trace.json` | JSON | Request-level metrics |
| `gpu_metrics.json` | JSON | GPU utilization data |
| `hardware_report.json` | JSON | GPU detection results |
| `benchmark_results.json` | JSON | Performance benchmarks |
| `telemetry_report.json` | JSON | Real-time telemetry |
| `validation_summary.json` | JSON | High-level results |
| `final_validation_report.json` | JSON | Certification decision |

**Location:** `validation_output/` (or specified output directory)

---

## 🎯 Certification Criteria

### Performance Targets

| Metric | Target | Critical? |
|--------|--------|-----------|
| Boot Time | < 5000ms | ✅ Yes |
| TPS | ≥ 100 | ✅ Yes |
| Latency | < 5000ms | ✅ Yes |
| TTFT | < 250ms | ✅ Yes |
| Success Rate | ≥ 95% | ✅ Yes |
| GPU Temp | < 85°C | ⚠️ Warning |

### Hardware Requirements

| Component | Requirement | Detection |
|-----------|-------------|-----------|
| Primary GPU | Radeon AI PRO R9700 32GB | Automatic |
| Secondary GPU | RX 7800 XT 16GB | Automatic |
| Multi-GPU | Both GPUs utilized | Automatic |

---

## 🏃 Common Workflows

### First-Time Setup

```powershell
# 1. Build framework
cd d:\RawrXD\validation\harness
build.bat

# 2. Run quick validation
cd d:\RawrXD\validation
.\Run-Validation.ps1 -Iterations 10

# 3. View results
start dashboard\ValidationDashboard.html
```

### Production Certification

```powershell
# Full certification run
.\Validate-Production.ps1 `
  -TargetUrl "http://127.0.0.1:8080" `
  -BenchmarkRuns 100 `
  -HardwareValidation

# Generate reports
.\tools\Generate-ValidationReport.ps1 `
  -ValidationOutputPath "validation_output" `
  -ReportType Full
```

### CI/CD Integration

```yaml
- name: Validate RawrXD
  run: |
    .\validation\ci\Validate-CI.ps1 `
      -TargetUrl "http://localhost:8080" `
      -BenchmarkRuns 50 `
      -FailOnCertification
```

### Performance Tracking

```powershell
# Compare with baseline
.\tools\Compare-ValidationResults.ps1 `
  -BaselinePath "baseline.json" `
  -CurrentPath "validation_output\final_validation_report.json" `
  -GenerateHTML
```

---

## 📁 Directory Structure

```
validation/
├── INDEX.md                    # This file
├── QUICKSTART.md              # Quick start guide
├── README.md                  # Main documentation
├── Validate-Production.ps1    # Main orchestration
├── Run-Validation.ps1         # Quick validation
│
├── harness/                   # C++ Components
│   ├── ValidationHarness.cpp
│   ├── HardwareValidator.cpp
│   ├── RealInferenceBenchmark.cpp
│   ├── TelemetryCollector.cpp
│   ├── include/
│   │   └── ValidationTypes.hpp
│   ├── build.bat
│   ├── CMakeLists.txt
│   └── README.md
│
├── ci/                        # CI/CD Integration
│   ├── Validate-CI.ps1
│   └── README.md
│
├── dashboard/                 # Visualization
│   └── ValidationDashboard.html
│
├── tools/                     # Additional utilities
│   ├── Compare-ValidationResults.ps1
│   ├── Generate-ValidationReport.ps1
│   └── README.md
│
└── tests/                     # Self-tests
    └── test_validation_framework.ps1
```

---

## 🔍 Troubleshooting

### Build Issues

| Issue | Solution |
|-------|----------|
| "nlohmann/json not found" | Ensure `3rdparty/json/include/nlohmann/json.hpp` exists |
| "Visual Studio not found" | Install VS 2022 with C++ workload or use CMake |
| "Unresolved external symbol" | Link against `ws2_32.lib` and `pdh.lib` |

### Runtime Issues

| Issue | Solution |
|-------|----------|
| "Connection refused" | Verify RawrXD is running on target URL |
| "No GPUs detected" | Run as Administrator, check Device Manager |
| "TPS below target" | Check GPU utilization and temperature |
| "WMI query failed" | Ensure WMI service is running |

### Report Issues

| Issue | Solution |
|-------|----------|
| "Validation report not found" | Run validation first |
| "Empty comparison" | Check both reports have same structure |
| "Dashboard not loading" | Check browser console for errors |

---

## 📈 Success Criteria

RawrXD is production-ready when:

✅ **All certification criteria met**
- Boot time < 5000ms
- TPS ≥ 100
- Latency < 5000ms
- TTFT < 250ms
- Success rate ≥ 95%

✅ **Hardware validated**
- R9700 detected and functional
- 7800 XT detected and functional
- Multi-GPU distribution working

✅ **Stability proven**
- 24-hour continuous operation
- No memory leaks
- Graceful error recovery

✅ **Documentation complete**
- Validation artifacts archived
- Performance baseline established
- Deployment guide finalized

---

## 🔄 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-30 | Initial release |

---

## 📞 Support

### Documentation
- **Quick Start:** [QUICKSTART.md](QUICKSTART.md)
- **Component Docs:** [harness/README.md](harness/README.md)
- **Production Guide:** [PRODUCTION_READINESS_GUIDE.md](../PRODUCTION_READINESS_GUIDE.md)

### Troubleshooting
1. Check [Troubleshooting](#-troubleshooting) section above
2. Review component logs in `validation_output/`
3. Run individual components for detailed diagnostics
4. Consult [VERIFICATION_STATUS.md](../VERIFICATION_STATUS.md) for known limitations

### Contributing
- Framework source: `validation/harness/`
- Scripts: `validation/*.ps1`
- Tests: `validation/tests/`

---

## 🎯 Next Steps

### Immediate (Today)
1. ✅ Review this INDEX
2. ⏳ Read [QUICKSTART.md](QUICKSTART.md)
3. ⏳ Build the framework: `cd harness && build.bat`
4. ⏳ Run first validation: `.\Run-Validation.ps1`

### This Week
1. Run full validation (100 iterations)
2. Address any certification failures
3. Establish performance baseline
4. Document results

### Next Week
1. Run validation on R9700 + 7800 XT system
2. Verify multi-GPU distribution
3. Capture hardware validation evidence

---

**Ready to validate? Start with [QUICKSTART.md](QUICKSTART.md)**
