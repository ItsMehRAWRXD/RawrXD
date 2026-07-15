# RawrXD Production Validation Guide

## Overview

This guide walks you through validating RawrXD for production deployment. The validation suite consists of two phases:

- **Phase 6**: Real Model Validation - Proves the runtime works with actual GGUF models
- **Phase 7A**: 24-Hour Soak Test - Proves the runtime is stable under continuous load

## Prerequisites

1. **Models**: Download GGUF models to a local directory
   - Recommended: TheBloke/Llama-2-7B-GGUF (for quick validation)
   - Optional: 13B, 70B variants (for comprehensive testing)

2. **Hardware**: GPU with sufficient VRAM
   - 7B models: ~4-8 GB VRAM
   - 13B models: ~8-12 GB VRAM
   - 70B models: ~40-80 GB VRAM (or CPU offload)

3. **Tools**: PowerShell 5.1+ or PowerShell Core

## Quick Start

### Full Validation (Phase 6 + Phase 7A)

```powershell
# Run complete production validation
.\tests\production_validation_suite.ps1 -ModelsDir "F:\models" -Mode "full"
```

### Phase 6 Only (Quick - ~5 minutes)

```powershell
# Validate real model loading only
.\tests\production_validation_suite.ps1 -ModelsDir "F:\models" -Mode "phase6"
```

### Phase 7A Only (Long-running - 24 hours)

```powershell
# Run 24-hour soak test with specific model
.\tests\production_validation_suite.ps1 `
    -ModelsDir "F:\models" `
    -Mode "phase7a" `
    -SoakModel "F:\models\llama-2-7b.Q4_K_M.gguf" `
    -SoakDurationHours 24
```

## What Each Phase Validates

### Phase 6: Real Model Validation

| Test | Purpose |
|------|---------|
| Model Discovery | Finds all .gguf files recursively |
| GGUF Header Parse | Validates file format and reads tensor count |
| GPU VRAM Detection | Correctly reports dedicated VRAM (not shared) |
| VRAM Sufficiency | Checks if model fits in GPU memory |
| DX12 Upload | Validates DirectX 12 residency pipeline |

**Success Criteria:**
- All models discovered
- GPU VRAM correctly detected (not 4GB fallback)
- Models fit in available VRAM

### Phase 7A: 24-Hour Soak Test

| Metric | Threshold | Purpose |
|--------|-----------|---------|
| Duration | 24 hours | Proves long-term stability |
| TPS Variance | < 5% | Detects performance drift |
| Memory Growth | < 512 MB heap, < 1 GB VRAM | Detects leaks |
| Thermal Throttling | None | Detects overheating |
| Residency Thrash | < threshold | Detects inefficient memory management |
| Fault Recovery | 100% | Proves resilience |

**Success Criteria:**
- 24-hour continuous operation
- No memory leaks
- No TPS degradation
- No thermal throttling
- Automatic recovery from faults

## Output Files

After validation completes, check:

```
production_reports/
├── production_validation_summary.md    # Overall results
├── phase6_validation_YYYYMMDD_HHMMSS.md  # Phase 6 details
└── soak_reports/
    ├── soak_test_telemetry.csv         # Raw telemetry data
    ├── soak_test_health.log            # Health check log
    └── soak_test_report.md             # Soak test summary
```

## Interpreting Results

### ✅ Production Ready

If both phases pass:
- Model loading works correctly
- GPU detection is accurate
- 24-hour stability proven
- No memory leaks
- No performance drift

### ❌ Common Failures

| Issue | Cause | Fix |
|-------|-------|-----|
| "No GGUF models found" | Wrong directory | Check -ModelsDir path |
| "GPU VRAM shows 4GB" | Using SharedSystemMemory | Fixed in Phase 6 validator |
| "Model too large for VRAM" | Insufficient GPU memory | Use smaller model or enable CPU offload |
| "TPS degraded" | Thermal throttling | Check GPU cooling |
| "Memory leak detected" | Heap/VRAM growth | Review allocation patterns |

## Advanced Options

### Fault Injection Testing

Test automatic recovery by injecting faults:

```powershell
.\tests\production_validation_suite.ps1 `
    -ModelsDir "F:\models" `
    -Mode "phase7a" `
    -EnableFaultInjection
```

### Custom Duration

Run shorter soak for development:

```powershell
.\tests\production_validation_suite.ps1 `
    -ModelsDir "F:\models" `
    -Mode "phase7a" `
    -SoakDurationHours 1    # 1-hour test
```

### Skip Build

If binaries already exist:

```powershell
.\tests\production_validation_suite.ps1 `
    -ModelsDir "F:\models" `
    -Mode "full" `
    -SkipBuild
```

## Production Deployment Checklist

After validation passes:

- [ ] Phase 6: Model discovery working
- [ ] Phase 6: GPU VRAM correctly detected
- [ ] Phase 7A: 24-hour soak completed
- [ ] Phase 7A: TPS variance < 5%
- [ ] Phase 7A: No memory leaks
- [ ] Phase 7A: No thermal throttling
- [ ] Review all validation reports
- [ ] Document hardware configuration
- [ ] Set up monitoring for production

## Support

If validation fails:

1. Check logs in `production_reports/`
2. Verify GPU drivers are up to date
3. Ensure sufficient disk space for models
4. Review Windows Event Viewer for GPU errors
5. Re-run with `-Verbose` flag for detailed output

---

**RawrXD Sovereign Inference Runtime**  
*Production Validation v1.0*
