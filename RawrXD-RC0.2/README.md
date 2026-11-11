# RawrXD v15.0.0-RC0.2 Release Candidate

## Overview

This is the **RC0.2 (Release Candidate 0.2)** for RawrXD v15.0.0, representing the final validation stage before general availability.

## Release Candidate Status

- **Version**: 15.0.0-RC0.2
- **Status**: Release Candidate
- **Target**: Production Release
- **Date**: 2026-07-30

## What's Included

### Core Components
- **Deep2 Model**: 8B parameter model with 32K context window
- **Inference Engine**: Vulkan/HIP backend with dual GPU support
- **Runtime**: Optimized for AMD Radeon AI PRO R9700 + RX 7800 XT

### Validation Evidence
All validation evidence is located in `evidence/rc0.2/`:

1. **Release Manifest** (`release_manifest.json`)
   - Build information
   - Binary hashes
   - Model hashes

2. **Hardware Attestation** (`hardware_attestation.json`)
   - GPU configuration verification
   - System information
   - Driver versions

3. **Inference Witness** (`inference_witness.json`)
   - Performance benchmarks
   - KV cache verification
   - Streaming contract validation

4. **Performance Certification** (`performance_certification.json`)
   - TPS measurements
   - Latency analysis
   - VRAM utilization

5. **VAL Certification** (`VAL_CERTIFICATION.json`)
   - Test suite results (VAL-064 through VAL-078)
   - All tests passing

6. **Release Freeze Evidence** (`RELEASE_FREEZE_EVIDENCE.json`)
   - Final validation checklist
   - Release readiness confirmation

## System Requirements

### Minimum Requirements
- **OS**: Windows 10/11 64-bit
- **CPU**: x86_64 with AVX2 support
- **RAM**: 16 GB system memory
- **GPU**: Vulkan 1.2 compatible

### Recommended Configuration
- **OS**: Windows 11 64-bit
- **CPU**: AMD Ryzen 9 or Intel Core i9
- **RAM**: 32 GB system memory
- **GPU**: AMD Radeon AI PRO R9700 (32GB) + RX 7800 XT (16GB)
- **VRAM**: 48 GB total

## Installation

1. Extract the release bundle to your desired location
2. Run `RawrXD-RC0.2-Verifier.exe` to validate the installation
3. Launch `RawrXD.exe` to start the application

## Verification

To verify the release:

```powershell
# Run the certification runner
python tools/rc0.2_certification_runner.py

# Or use the standalone verifier
.\RawrXD-RC0.2-Verifier.exe evidence/rc0.2
```

## Performance Targets

- **Tokens Per Second**: ≥ 200 TPS
- **First Token Latency**: ≤ 100 ms
- **Context Window**: 32,768 tokens
- **VRAM Utilization**: ≤ 80%

## Known Issues

None identified in RC0.2.

## Support

For issues or questions:
- GitHub Issues: https://github.com/ItsMehRAWRXD/RawrXD/issues
- Documentation: https://docs.rawrxd.ai

## License

Copyright © 2026 RawrXD Team. All rights reserved.
