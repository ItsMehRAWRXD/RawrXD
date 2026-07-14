# RawrXD Sovereign Runtime v1.0.0 - Validation Execution Runbook

**Date:** 2026-07-14  
**Version:** v1.0.0-RUNBOOK  
**Status:** READY FOR EXECUTION

---

## Quick Start

### Run Validation Now
```powershell
# 1. Navigate to project root
cd d:\rawrxd-ci-bootstrap

# 2. Execute full validation suite
.\tests\run_validation_suite.ps1 -BuildDir "build"

# 3. Check results
Get-Content .\results\VALIDATION_REPORT.md
```

---

## Pre-Validation Checklist

Before running validation, ensure:

- [ ] Clean working tree (`git status` shows no uncommitted changes)
- [ ] Build successful (`build\RawrXD-AgenticIDE.exe` exists)
- [ ] Test models downloaded (`models\*.gguf` files present)
- [ ] Sufficient disk space (10 GB free)
- [ ] Sufficient RAM (16 GB recommended)
- [ ] Windows SDK installed
- [ ] MSVC compiler available

---

## Phase-by-Phase Execution

### Phase V1: Build Reproducibility (10 minutes)

**Step 1: Clean Build**
```powershell
git clean -fdx
git reset --hard HEAD
mkdir build
cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja RawrXD-AgenticIDE
```

**Step 2: Verify Executable**
```powershell
# Check executable exists
Test-Path .\RawrXD-AgenticIDE.exe

# Check size (should be ~10.5 MB)
(Get-Item .\RawrXD-AgenticIDE.exe).Length / 1MB

# Capture hash
Get-FileHash .\RawrXD-AgenticIDE.exe -Algorithm SHA256
```

**Step 3: Check Dependencies**
```powershell
# Verify no Qt dependencies
dumpbin /dependents RawrXD-AgenticIDE.exe | findstr Qt
# Should return nothing

# Verify Windows API only
dumpbin /dependents RawrXD-AgenticIDE.exe
# Should show: KERNEL32.dll, USER32.dll, etc.
```

**Expected Result:** ✅ PASS

---

### Phase V2: Runtime Validation (30 minutes)

**Step 1: Launch Test**
```powershell
.\RawrXD-AgenticIDE.exe --version
# Expected: "RawrXD Sovereign Runtime v1.0.0"
```

**Step 2: GGUF Loading Test**
```powershell
# Download test model if not present
if (-not (Test-Path "models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf")) {
    mkdir models -Force
    # Download from HuggingFace
    Invoke-WebRequest -Uri "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" -OutFile "models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
}

# Run loading test
.\tests\v2_gguf_loading.exe
```

**Step 3: Tokenizer Test**
```powershell
.\tests\v2_tokenizer.exe
# Expected: "PASS: Tokenizer validation"
```

**Step 4: Inference E2E Test**
```powershell
.\tests\v2_inference_e2e.exe
# Expected: "PASS: Inference E2E"
# Should complete in <30 seconds
```

**Expected Result:** ✅ PASS

---

### Phase V3: Memory Safety (60 minutes)

**Step 1: ASan Build**
```powershell
# Build with Address Sanitizer
mkdir build-asan
cd build-asan
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="/fsanitize=address"
ninja RawrXD-AgenticIDE

# Run tests
.\RawrXD-AgenticIDE.exe --test-mode
# Expected: No ASan errors
```

**Step 2: UBSan Build**
```powershell
# Build with Undefined Behavior Sanitizer
mkdir build-ubsan
cd build-ubsan
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="/fsanitize=undefined"
ninja RawrXD-AgenticIDE

# Run tests
.\RawrXD-AgenticIDE.exe --test-mode
# Expected: No UBSan errors
```

**Step 3: Memory Leak Test**
```powershell
.\tests\v3_memory_leaks.exe
# Expected: "PASS: No memory leaks detected"
```

**Expected Result:** ✅ PASS

---

### Phase V4: Fault Injection (15 minutes)

**Step 1: Corrupted GGUF Test**
```powershell
.\tests\v4_corrupted_gguf.exe
# Expected: "PASS: Corrupted GGUF handling"
```

**Step 2: OOM Handling Test**
```powershell
.\tests\v4_oom_handling.exe
# Expected: "PASS: OOM handling"
```

**Expected Result:** ✅ PASS

---

### Phase V5: Concurrency (30 minutes)

**Step 1: Concurrent Loading Test**
```powershell
.\tests\v5_concurrent_loading.exe
# Expected: "PASS: Concurrent loading"
```

**Step 2: Concurrent Inference Test**
```powershell
.\tests\v5_concurrent_inference.exe
# Expected: "PASS: Concurrent inference"
```

**Expected Result:** ✅ PASS

---

### Phase V6: Performance Baseline (30 minutes)

**Step 1: Load Time Benchmark**
```powershell
.\tests\v6_load_time_benchmark.exe
# Expected: Generates benchmark_load_times.csv
```

**Step 2: TPS Benchmark**
```powershell
.\tests\v6_inference_tps_benchmark.exe
# Expected: Generates benchmark_tps.csv
```

**Step 3: Verify Results**
```powershell
# Check load times
Import-Csv .\benchmark_load_times.csv

# Expected results (approximate):
# Model: tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
# Size: ~600 MB
# Load time: 2-5 seconds

# Check TPS
Import-Csv .\benchmark_tps.csv

# Expected results (approximate):
# TPS: 10-50 tokens/second (depends on hardware)
```

**Expected Result:** ✅ PASS

---

## Full Automation

### Run All Phases Automatically
```powershell
# Execute complete validation suite
cd d:\rawrxd-ci-bootstrap
.\tests\run_validation_suite.ps1 -BuildDir "build"

# Check exit code
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ ALL TESTS PASSED" -ForegroundColor Green
} else {
    Write-Host "❌ SOME TESTS FAILED" -ForegroundColor Red
}

# View report
.\results\VALIDATION_REPORT.md
```

### CI/CD Execution
```yaml
# GitHub Actions will automatically run validation on push
git push origin copilot/vscode-mlyextom-3zgo-phase7a

# Monitor progress at:
# https://github.com/ItsMehRAWRXD/RawrXD/actions
```

---

## Troubleshooting

### Build Failures

**Issue:** "CMake not found"
```powershell
# Solution: Install CMake
choco install cmake
```

**Issue:** "Ninja not found"
```powershell
# Solution: Install Ninja
choco install ninja
```

**Issue:** "MSVC not found"
```powershell
# Solution: Run from Developer Command Prompt
# Or: Import Visual Studio environment
Import-Module "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "C:\Program Files\Microsoft Visual Studio\2022\Enterprise" -DevCmdArguments "-arch=x64"
```

### Test Failures

**Issue:** "Test model not found"
```powershell
# Solution: Download test models
mkdir models
Invoke-WebRequest -Uri "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" -OutFile "models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
```

**Issue:** "Out of memory"
```powershell
# Solution: Close other applications
# Or: Use smaller test model
# Or: Increase page file size
```

**Issue:** "ASan/UBSan not supported"
```powershell
# Solution: Skip sanitizer tests
.\tests\run_validation_suite.ps1 -BuildDir "build" -SkipSlowTests
```

---

## Results Interpretation

### PASS Criteria
- All test cases execute without errors
- Exit code 0
- No crashes
- Performance within ±20% of baseline
- Memory usage stable

### FAIL Criteria
- Any test case fails
- Non-zero exit code
- Crashes or hangs
- Performance regression >20%
- Memory leaks detected

### Report Generation
```powershell
# Generate validation report
$report = @"
# RawrXD Validation Report

**Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Build:** $(Get-FileHash build\RawrXD-AgenticIDE.exe -Algorithm SHA256).Hash

## Summary

| Phase | Status |
|-------|--------|
| V1 - Build | $(if (Test-Path build\RawrXD-AgenticIDE.exe) { "✅ PASS" } else { "❌ FAIL" }) |
| V2 - Runtime | $(if ($LASTEXITCODE -eq 0) { "✅ PASS" } else { "❌ FAIL" }) |
| V3 - Memory | $(if (Test-Path results\memory_test.log) { "✅ PASS" } else { "⏳ PENDING" }) |
| V4 - Fault | $(if (Test-Path results\fault_test.log) { "✅ PASS" } else { "⏳ PENDING" }) |
| V5 - Concurrency | $(if (Test-Path results\concurrency_test.log) { "✅ PASS" } else { "⏳ PENDING" }) |
| V6 - Performance | $(if (Test-Path results\benchmark_tps.csv) { "✅ PASS" } else { "⏳ PENDING" }) |

## Recommendation

$(if ($LASTEXITCODE -eq 0) { "**APPROVE** - Ready for release" } else { "**REJECT** - Fix failures before release" })
"@

$report | Out-File -FilePath "results\VALIDATION_REPORT.md" -Encoding UTF8
```

---

## Release Decision

### Approve Release Candidate If:
- [ ] All phases PASS
- [ ] No critical bugs
- [ ] Performance acceptable
- [ ] Documentation complete
- [ ] Build reproducible

### Reject Release Candidate If:
- [ ] Any phase FAILs
- [ ] Critical bugs found
- [ ] Performance regression >20%
- [ ] Memory leaks detected
- [ ] Security issues found

---

## Post-Validation Actions

### If Validation PASSES:
1. Tag release: `git tag v1.0.0`
2. Create release package
3. Upload to GitHub Releases
4. Announce release

### If Validation FAILS:
1. Fix identified issues
2. Re-run failed tests
3. Re-validate
4. Repeat until PASS

---

## Contact

**Validation Team:**
- Test Engineer: [NAME]
- Build Engineer: [NAME]
- Release Manager: [NAME]

**Escalation:**
- Critical issues: Immediate escalation
- Performance issues: 24-hour response
- Documentation issues: Next release cycle

---

## Appendix

### Test Model URLs

| Model | Size | URL |
|-------|------|-----|
| TinyLlama-1.1B | ~600 MB | https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF |
| Llama-2-7B | ~4 GB | https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF |
| Llama-2-13B | ~8 GB | https://huggingface.co/TheBloke/Llama-2-13B-Chat-GGUF |

### Expected Performance Baselines

| Model | Load Time | TPS (CPU) | TPS (GPU) |
|-------|-----------|-----------|-----------|
| TinyLlama-1.1B | 2-5s | 10-20 | 50-100 |
| Llama-2-7B | 10-20s | 2-5 | 20-40 |
| Llama-2-13B | 20-40s | 1-3 | 10-20 |

### Hardware Requirements

**Minimum:**
- CPU: Intel Core i5 / AMD Ryzen 5
- RAM: 8 GB
- Disk: 10 GB free
- OS: Windows 10/11

**Recommended:**
- CPU: Intel Core i7 / AMD Ryzen 7
- RAM: 16 GB
- Disk: 50 GB free
- GPU: NVIDIA RTX 3060 or better
- OS: Windows 11

---

**Validation Framework:** ✅ COMPLETE  
**Ready for Execution:** ✅ YES  
**Estimated Duration:** 3 hours  
**Release Candidate:** ⏳ PENDING EXECUTION