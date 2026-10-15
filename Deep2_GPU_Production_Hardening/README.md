# Deep2 GPU Production Hardening — Source Drop

## Overview
Complete C++20 source changes to fix the critical GPU performance bottlenecks identified in the Strata benchmarks:

| Issue | Impact | Fix |
|-------|--------|-----|
| `kernel_ms` = CPU fence-wait time | Misleading performance metrics | Real GPU timestamp queries (P0-A) |
| 11,787 synchronous submit/wait pairs | 184 submits/token, serialized execution | Batched command buffers (P0-B) |
| MoE expert ledger: 0 observations | No expert residency optimization | Router → recordExpertAccess integration (P0-C) |
| 1.06 GB cache peak ≠ model residency | Cannot verify GPU weight residency | Total device-local allocation tracking (P1) |
| 117.8s bind phase | Startup dominates TTFT | Pipeline cache reuse (P1) |

## Files Included

```
Deep2_GPU_Production_Hardening/
├── src/
│   ├── deep2/
│   │   ├── vulkan_compute.h          # Added GpuCounters, real GPU timing
│   │   ├── vulkan_compute.cpp        # Batched submissions, timestamp queries
│   │   ├── runtime_graph_executor.cpp # MoE expert recording hook
│   │   ├── Deep2Engine.cpp           # Expert access recording
│   │   └── quant_dot_dispatch.hpp    # Updated counters API
│   └── tools/
│       └── deep2_strata_bench.cpp    # Enhanced receipt output
├── CMakeLists.txt                     # Build configuration
├── apply_patches.ps1                  # Automated patch application
└── verify_build.ps1                   # Build + benchmark verification
```

## Quick Apply

```powershell
cd F:\rawrxd
Expand-Archive .\Deep2_GPU_Production_Hardening.zip . -Force
.\Deep2_GPU_Production_Hardening\apply_patches.ps1
.\Deep2_GPU_Production_Hardening\verify_build.ps1
```

## Verification

After build, run both benchmarks and compare:

```powershell
# Nemotron 30B MoE (baseline)
.\tools\deep2_strata_bench.exe --model F:\rawrxd\models\nemotron-3.5-lightning_30b.gguf --generate 64 --gpu

# DeepSeek 32B Dense (baseline)
.\tools\deep2_strata_bench.exe --model F:\rawrxd\models\deepseek-r1_32b.gguf --generate 64 --gpu
```

Expected receipt fields (new):

```json
{
  "gpu_ms": 12345.6,              // Real GPU timestamp-derived
  "host_wait_ms": 2345.6,         // CPU fence-wait time
  "submit_cpu_ms": 123.4,         // CPU submission overhead
  "total_device_weight_bytes": 18490000000,
  "cache_device_bytes": 1059058156,
  "expert_observations": 384,
  "expert_hits": 312,
  "expert_misses": 72
}
```

## Changes Summary

### P0-A: Real GPU Timing (vulkan_compute.h/cpp)
- Added `GpuCounters` struct with `gpu_ms`, `host_wait_ms`, `submit_cpu_ms`
- Timestamp query pool integration at every dispatch
- `calibrateTick()` converts device ticks → host nanoseconds
- `finalizeInterval()` fills `gpuStartNs`/`gpuEndNs` from query results
- Deprecated `kernel_ms` alias (kept for compatibility, marked)

### P0-B: Batched Submissions (vulkan_compute.cpp)
- `BeginFusedLayer()` / `EndFusedLayer()` pattern expanded
- `SubmitBatch()` records multiple dispatches into single command buffer
- `vkQueueSubmit` + single `vkWaitForFences` per batch
- Barrier recording between dependent operations
- Async material upload path already exists — promoted

### P0-C: MoE Expert Telemetry (runtime_graph_executor.cpp + Deep2Engine.cpp)
- `OpMoEExecute` calls `Deep2Engine::recordExpertAccess(layer, expertId, weight)`
- `StrataExpertResidency` integrated via `Deep2Engine` instance
- Strata bench prints `S01_EXPERT_LEDGER` with real observations

### P1: Total GPU Residency (vulkan_compute.cpp + quant_dot_dispatch.hpp)
- `total_device_weight_bytes` tracks all `VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT` allocations
- Separate from `weightCacheBytes_` (managed cache)
- Receipt includes both values

### P1: Pipeline Cache (vulkan_compute.cpp)
- `VkPipelineCache` created at device init
- `createPipelineFromFile` uses cache
- Bind-phase time reported separately

## Build Requirements
- Vulkan SDK 1.3+
- CMake 3.20+
- MSVC 19.30+ (VS 2022 17.5+)
- C++20

## Compatibility
- All changes are additive or internal refactoring
- Public API of `VulkanCompute` unchanged
- `quant_dot_dispatch` receipt struct expanded (backward compatible)
- Strata bench output format extended (additive fields)