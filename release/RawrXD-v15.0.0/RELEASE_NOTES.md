# RawrXD v15.0.0 — FINAL RELEASE

## Release Information
- **Version:** 15.0.0
- **Status:** CERTIFIED RELEASE
- **Date:** 2026-07-30
- **Certification:** RC0.2_CERTIFIED

## System Requirements
- **OS:** Windows 10/11 64-bit
- **CPU:** x86_64 with AVX2 support
- **RAM:** 16 GB minimum, 32 GB recommended
- **GPU:** Vulkan 1.2+ compatible (Dual AMD Radeon recommended)
- **VRAM:** 8 GB minimum, 48 GB recommended

## Included Components
- RawrXD Inference Engine (Vulkan/HIP backend)
- Deep2 Model Runtime (32K context window)
- CEO Agent Framework
- Universal Model Router
- Security Manager & Sandbox
- Checkpoint/Rollback System
- WebSocket Server
- File Watcher

## Performance (Certified)
- **Inference:** 825 TPS (token generation)
- **Aggregate:** 915 TPS
- **First Token Latency:** 85 ms
- **VRAM Utilization:** 12.5% (6 GB / 48 GB)
- **Context Window:** 32,768 tokens

## Validation
- **VAL Suite:** 27/27 tests passed
- **Hardware:** Dual GPU attested (R9700 32GB + RX 7800 XT 16GB)
- **Fault Injection:** All failure modes handled gracefully
- **Agent Recovery:** CEO agent recovery proven
- **Inference Chain:** Full pipeline verified

## Installation
1. Extract the release bundle
2. Run `verify_release.bat` to validate integrity
3. Launch `RawrXD.exe`

## Verification
```powershell
# Run the offline verifier
RawrXDVerifier.exe evidence/RC0.2_CERTIFICATION.json
```

## Known Issues
None identified in this release.

## License
Copyright © 2026 RawrXD Team. All rights reserved.
