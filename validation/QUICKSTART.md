# RawrXD Validation Framework - Quick Start Guide

## Prerequisites

- Windows 10/11 x64
- Visual Studio 2022 with C++ workload
- RawrXD running on target system
- PowerShell 5.1 or later

## Quick Start (3 Steps)

### Step 1: Build the Validation Harness

```cmd
cd d:\RawrXD\validation\harness
build.bat
```

Expected output: 4 executables created
- `ValidationHarness.exe`
- `HardwareValidator.exe`
- `RealInferenceBenchmark.exe`
- `TelemetryCollector.exe`

### Step 2: Run Full Validation

```powershell
cd d:\RawrXD\validation
.\Validate-Production.ps1 -TargetUrl "http://127.0.0.1:8080" -BenchmarkRuns 100
```

### Step 3: Review Results

Check `validation_output\final_validation_report.json` for:
- Hardware detection results
- Performance metrics (TPS, latency, TTFT)
- Certification pass/fail status

## Component Usage

### Hardware Validation Only

```powershell
harness\HardwareValidator.exe output\hardware.json
```

Checks for:
- Radeon AI PRO R9700 (32GB)
- RX 7800 XT (16GB)
- Multi-GPU readiness

### Inference Benchmark Only

```powershell
harness\RealInferenceBenchmark.exe `
  --host 127.0.0.1 `
  --port 8080 `
  --runs 50 `
  --warmup 10 `
  --output benchmark.json
```

Measures:
- TPS (tokens per second)
- Latency (ms)
- TTFT (time to first token, ms)

### Telemetry Collection Only

```powershell
harness\TelemetryCollector.exe `
  --duration 60 `
  --interval 1000 `
  --output telemetry.json
```

Collects:
- GPU utilization
- Memory usage
- Temperature
- Power draw

## Certification Targets

| Metric | Target | Status |
|--------|--------|--------|
| Boot Time | < 5000ms | ⏱️ |
| TPS | ≥ 100 | 🚀 |
| Latency | < 5000ms | ⚡ |
| TTFT | < 250ms | 🎯 |
| Multi-GPU | Both GPUs | 🎮 |

## Troubleshooting

### "Build failed"
- Ensure Visual Studio 2022 is installed
- Run from Developer Command Prompt
- Check that nlohmann/json is available

### "Connection refused"
- Verify RawrXD is running on target URL
- Check firewall settings
- Try different port with `--port` flag

### "No GPUs detected"
- Run as Administrator
- Check AMD drivers are installed
- Verify GPUs are visible in Device Manager

## Output Files

```
validation_output/
├── boot.log                    # Boot sequence timing
├── boot_report.json           # Boot metrics
├── gateway.log                # API validation
├── inference_trace.json       # Request metrics
├── gpu_metrics.json          # GPU telemetry
├── hardware_report.json      # GPU detection
├── benchmark_results.json    # Inference benchmarks
├── telemetry_report.json     # Real-time telemetry
├── validation_summary.json   # High-level results
└── final_validation_report.json  # Complete report
```

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Run Production Validation
  run: |
    .\validation\Validate-Production.ps1 -BenchmarkRuns 50
    
- name: Upload Results
  uses: actions/upload-artifact@v3
  with:
    name: validation-results
    path: validation_output/
    
- name: Check Certification
  run: |
    $report = Get-Content validation_output/final_validation_report.json | ConvertFrom-Json
    if ($report.overall_status -ne "PASS") { throw "Validation failed" }
```

## Next Steps

1. ✅ Run validation: `.\Validate-Production.ps1`
2. 📊 Review results: `final_validation_report.json`
3. 🎯 Check certification: All targets met?
4. 📦 Archive artifacts: Store with release
5. 🚀 Production ready: Ship with confidence

## Support

For issues or questions:
1. Check `VERIFICATION_STATUS.md` for known limitations
2. Review component logs in `validation_output/`
3. Run individual components for detailed diagnostics
