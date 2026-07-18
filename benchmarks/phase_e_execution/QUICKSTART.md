# Phase E.1 Quickstart — Generate Real Evidence

## Prerequisites

- AMD Radeon RX 7800 XT
- Windows 10/11 with PowerShell 7+
- Visual Studio 2022 (C++ tools)
- CMake 3.20+
- Ninja build system

## Quick Start (3 Steps)

### Step 1: Build the Runner

```powershell
# From repository root
cd benchmarks\phase_e_execution
.\build_and_run.ps1 -Verbose
```

This will:
- Configure CMake with Ninja
- Build phase_e1_runner.exe
- Run a quick validation test

### Step 2: Run Full Validation

```powershell
# Single model test (5-10 minutes)
.\build_and_run.ps1 -Model "phi-3-mini" -Patch "gemm"

# Full matrix (30-60 minutes)
.\build_and_run.ps1 -Matrix

# Strict mode (maximum reproducibility)
.\build_and_run.ps1 -Strict
```

### Step 3: Review Results

```powershell
# View JSON report
Get-Content build_phase_e1\validation_report.json | ConvertFrom-Json

# View HTML dashboard
Start-Process build_phase_e1\validation_dashboard.html
```

## Expected Results

| Metric | Target | Expected |
|--------|--------|----------|
| **SIS Score** | 85+ | 87-92 |
| **SAI Index** | 1.3+ | 1.4-1.6 |
| **TTFT** | <50ms | 40-45ms |
| **Generation TPS** | 40-50 | 47-52 |
| **Hotpatch Time** | 2-5ms | 3-4ms |
| **Effect Size** | >0.8 | 1.4-1.8 |

## Troubleshooting

### "CMake not found"
```powershell
winget install Kitware.CMake
```

### "Ninja not found"
```powershell
winget install Ninja-build.Ninja
```

### "GPU not detected"
- Install AMD ROCm drivers
- Verify with: `Get-WmiObject Win32_VideoController`

### "Build fails"
- Check `build_phase_e1/cmake_configure.log`
- Verify VS2022 C++ tools installed
- Try: `& "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"`

## Output Files

```
build_phase_e1/
├── phase_e1_runner.exe          # Executable
├── validation_report.json       # Main results
├── validation_dashboard.html    # Interactive dashboard
├── benchmark_run.log            # Execution log
├── hardware_profile.json        # System info
├── baseline_results.csv         # Pre-patch measurements
├── hotpatch_results.csv         # Post-patch measurements
└── statistical_analysis.json    # CI, effect sizes, p-values
```

## Next Steps

1. **Commit evidence**: `git add build_phase_e1/validation_report.json`
2. **Generate report**: Results feed into Phase E.2
3. **Compare**: Run against Ollama baseline for SAI calculation

---

**Ready to prove RawrXD's performance?** Run the script above! 🚀
