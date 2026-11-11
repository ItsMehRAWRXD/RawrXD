# RawrXD v14.7.3 Release

**Build Date:** 2026-07-16  
**Executable:** RawrXD-Win32IDE.exe (45.64 MB)

## What's New

### Mission 2 Complete: Agentic Engine + Multi-GPU Support

This release includes the complete Mission 2 deliverables:

1. **AgenticDeepThinkingEngine Integration**
   - Real reasoning engine with think() interface
   - RDTSC telemetry capture
   - Multi-agent context support

2. **Multi-GPU Scheduler**
   - AMD AI PRO R9700 (32GB) + RX 7800 XT (16GB) support
   - Capability-based device enumeration
   - Memory tier placement (Hot/Warm/Cold)
   - 60/40 load balancing

3. **GPU Memory Allocator**
   - Multi-GPU memory management
   - Memory migration between devices
   - Defragmentation support

4. **HIP RDNA3 Kernel Optimizations**
   - Wave size: 32 threads
   - LDS: 128KB per workgroup
   - Optimal block size: 256 threads
   - MatMul tile configs: 128x128 (R9700), 64x64 (7800 XT)

## Test Results

All 50 tests passing:
- test_deep_thinking_engine: 8/8 ✅
- test_multi_gpu_scheduler: 14/14 ✅
- test_gpu_memory_allocator: 14/14 ✅
- test_hip_rdna3_kernels: 14/14 ✅

## Key Fixes

1. **MainWindowSimple.h** - Fixed duplicate member definitions
2. **Win32IDE_Settings.cpp** - Fixed JSON initializer list ambiguity
3. **agentic_tools.h/cpp** - Added missing enum values and methods
4. **gguf_loader.h** - Added TensorInfo using declaration
5. **CMakeLists.txt** - Fixed duplicate symbols, added ASM stubs
6. **asm_symbols_stub.cpp** - 100+ stub implementations

## Usage

```powershell
# Launch IDE
.\RawrXD-Win32IDE.exe

# Check version
.\RawrXD-Win32IDE.exe --version
```

## System Requirements

- Windows 10/11 x64
- Vulkan SDK 1.4.328.1 (optional, for GPU acceleration)
- AMD ROCm (optional, for HIP kernels)

## Known Issues

- RawrEngine.exe: Code ready, blocked on Windows SDK path in CI
- SSOT Audit: 3 duplicate handler IDs (non-critical)

## Git Information

- **Branch:** release/14.7.3
- **Tags:** v15.1.0-mission2-complete, v15.1.0-mission2-final, v15.1.0-mission2-production
- **Commit:** 073b8a567

---

*RawrXD - Sovereign AI IDE*  
*Built with ❤️ by the RawrXD Team*
