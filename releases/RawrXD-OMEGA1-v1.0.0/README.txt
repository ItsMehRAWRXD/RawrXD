# RawrXD OMEGA-1 v1.0.0

## Overview

RawrXD OMEGA-1 is a local LLM inference IDE with dual GPU support and ghost text completion.

## System Requirements

- **OS:** Windows 10/11 (x64)
- **CPU:** AMD Ryzen 7 7800X3D or equivalent
- **RAM:** 64GB DDR5
- **GPU:** Dual AMD GPU setup (e.g., Radeon AI PRO R9700 + RX 7800 XT)
- **Storage:** 10GB free space

## Quick Start

1. Run the IDE:
   `
   bin\RawrXD-Win32IDE.exe
   `

2. Run the Inference Engine:
   `
   bin\RawrXD-InferenceEngine.exe --model <path> --prompt "Hello"
   `

## Dual GPU Configuration

The system automatically distributes inference layers across dual GPUs:
- **Primary GPU (R9700):** 22 layers (70%)
- **Secondary GPU (7800XT):** 10 layers (30%)

## Testing

Run validation tests:
`powershell
# Dual GPU test
powershell -ExecutionPolicy Bypass -File scripts\test_dual_gpu.ps1

# IPC communication test
powershell -ExecutionPolicy Bypass -File scripts\test_ipc.ps1
`

## Documentation

- docs\BUILD_SUMMARY.md - Build details and validation results
- docs\OMEGA1_INTEGRATION.md - Integration guide

## Performance Targets

- Prompt Processing: 557 t/s
- Token Generation: 344 t/s

## Support

For issues and feature requests, refer to the documentation in the docs folder.

---

*Built: 2026-07-29 09:01:20*
*Version: 1.0.0*
