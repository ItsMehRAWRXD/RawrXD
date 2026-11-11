# RawrXD Shipping Manifest

**Version:** 14.7.3  
**Date:** 2026-07-15  
**Status:** ✅ READY TO SHIP

## Package Details

| Property | Value |
|----------|-------|
| Package | RawrXD-14.7.3-Windows-x64.zip |
| Size | 266,454 bytes (260 KB) |
| SHA256 | A0DD3F624F2D8BECA6680222D3676489BB4B1E041E011A3E806DA20D9CDF5AA2 |
| Commit | 0dc5494e80f2c6098e382b1bc88207b5b17b33a7 |
| Environment | staging |

## Build Validation

### Core Binaries
- ✅ RawrXD.exe (274 KB) - Main IDE executable
- ✅ RawrXD-InferenceRoutingTest.exe (277 KB) - Inference test harness

### Kernel Tests (8/8 PASS)
- ✅ Softmax - 1.70x speedup (AVX2)
- ✅ SiLU Activation - AVX-512 optimized
- ✅ GELU Activation - Exact match
- ✅ RMS Normalization - Exact match
- ✅ Layer Normalization - Exact match
- ✅ Self-Attention - Exact match
- ✅ RoPE - Exact match
- ✅ Matrix Multiplication - Exact match

### Smoke Tests
- ✅ Binary Health Check
- ✅ Launch Test
- ✅ Application startup verified

## Contents

```
RawrXD-14.7.3/
├── bin/
│   ├── RawrXD.exe              # Main IDE
│   └── RawrXD-InferenceRoutingTest.exe
├── config/
│   └── default.json
├── docs/
│   └── README.md
└── LICENSE
```

## Deployment Checklist

- [x] Build successful
- [x] All kernel tests pass
- [x] Smoke tests pass
- [x] Package created
- [x] Checksum generated
- [x] Release notes prepared
- [ ] Push to production (manual step)

## Installation

```powershell
# Download and extract
Expand-Archive RawrXD-14.7.3-Windows-x64.zip -DestinationPath C:\RawrXD

# Run
C:\RawrXD\bin\RawrXD.exe
```

## Verification

```powershell
# Verify checksum
Get-FileHash RawrXD-14.7.3-Windows-x64.zip -Algorithm SHA256
# Expected: A0DD3F624F2D8BECA6680222D3676489BB4B1E041E011A3E806DA20D9CDF5AA2
```

---

**Status:** ✅ READY FOR PRODUCTION DEPLOYMENT
