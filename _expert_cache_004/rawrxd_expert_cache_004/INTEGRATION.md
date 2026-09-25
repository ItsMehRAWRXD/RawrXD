# RAWRXD_EXPERT_CACHE_004 — Deep2 Vulkan transport integration

Cumulative source drop: 001–004. No third-party source dependency is required.

## What 004 adds

- `HostStagingRing`: submission-ordered circular allocator for one persistently mapped host-visible Vulkan staging buffer.
- `ExpertTransport` optional async DMA callbacks: `submitUpload`, `pollUpload`, `waitUpload`.
- `ExpertCache` now lets `prefetch()` submit without blocking; `acquire()` waits only if the selected expert is still in flight.
- `VulkanExpertTransport`: Windows source-only Vulkan backend that dynamically loads `vulkan-1.dll` and attaches to Deep2's existing `VkPhysicalDevice`, `VkDevice`, `VkQueue`, and `VkCommandPool`.
- Persistent device-local `VkBuffer` + `VkDeviceMemory` per resident expert.
- Persistent host-visible/coherent staging allocation.
- One-time command buffers + fences for copy completion.
- `VulkanBufferBinding` extraction for the existing Deep2 GEMV/GEMM descriptor/buffer binding path.
- Transport telemetry, including `cpuExpertCompute`, fixed at zero by this transport.

## No Vulkan SDK compile dependency

`VulkanExpertTransport.cpp` contains the minimal ABI declarations it uses and resolves Vulkan entry points dynamically from `vulkan-1.dll`. It does not include `<vulkan/vulkan.h>` and does not link `vulkan-1.lib`.

The runtime still requires the normal installed Vulkan loader/driver, which Deep2 already uses.

## Attach to Deep2's already-created Vulkan device

```cpp
#include "VulkanExpertTransport.h"
#include "ExpertCacheEnv.h"

using namespace rawrxd::deep2;

VulkanExpertTransportConfig vkcfg{};
vkcfg.physicalDevice = reinterpret_cast<void*>(deep2VkPhysicalDevice);
vkcfg.device         = reinterpret_cast<void*>(deep2VkDevice);
vkcfg.queue          = reinterpret_cast<void*>(deep2TransferOrComputeQueue);
vkcfg.commandPool    = reinterpret_cast<void*>((uintptr_t)deep2TransferCommandPool);
vkcfg.deviceOrdinal  = selectedDeviceOrdinal;
vkcfg.stagingBytes   = expertStagingBytesFromEnv();

auto vkExpert = VulkanExpertTransport::create(vkcfg);
if (!vkExpert || !vkExpert->ready()) {
    // Strict mode: fail expert-cache admission. Do not CPU-compute the expert.
}

ExpertCacheConfig ccfg = expertCacheConfigFromEnv();
Deep2ExpertCacheBridge expertBridge(ccfg, vkExpert->callbacks(), true);
expertBridge.importCatalog(expertCatalog);
```

## Router / prefetch path

```cpp
expertBridge.noteRouterScores(layer, ids, probs, count, tokenIndex);
expertBridge.prefetchTopK(layer, ids, probs, count,
                          ccfg.prefetchDepth, tokenIndex + 1);
```

With the 004 async callbacks, that prefetch submits the Vulkan copy and returns without waiting.

## Demand path

```cpp
auto cached = expertBridge.acquire({layer, selectedExpert}, tokenIndex);
if (!cached) {
    // strict GPU failure
}

VulkanBufferBinding gpu{};
if (!vkExpert->binding(cached.deviceHandle, gpu)) {
    // strict GPU failure
}

// gpu.buffer is the resident expert VkBuffer.
// cached.tensorOffsets[] are the projection offsets produced by 003.
// Bind gpu.buffer + cached.tensorOffsets[i] to the existing Deep2 GPU GEMV/GEMM path.
```

## Environment

```text
DEEP2_EXPERT_CACHE_MB=<VRAM expert-cache budget>
DEEP2_EXPERT_CACHE_DEVICE=<device ordinal>
DEEP2_EXPERT_CACHE_POLICY=EMA_LFU|LRU
DEEP2_EXPERT_PREFETCH_DEPTH=1
DEEP2_EXPERT_STAGING_MB=64
```

Start with prefetch depth 1. Keep staging large enough for the largest individual expert bundle plus overlap.

## Dual-GPU policy

Create one `VulkanExpertTransport` + `Deep2ExpertCacheBridge` per Vulkan device. Do not share opaque device handles across the R9700 and 7800 XT. Each device gets its own staging ring, cache budget, command pool, and expert ownership map.

Because the two GPUs need not share a Vulkan device group, host-visible staging remains the legal/common transfer bridge. Expert compute remains on GPU; host memory only backs/stages weights.

## Queue synchronization requirement

Use a dedicated Deep2 transfer queue for this transport when available. If the supplied queue is also submitted to elsewhere, Deep2 must externally serialize queue submissions as required by Vulkan. The transport serializes its own submissions internally but cannot lock unrelated submission code it does not own.

## Gate

`tests/test_expert_cache_async.cpp` validates the cache-level asynchronous contract without requiring a physical GPU:

```text
GATE=RAWRXD_EXPERT_CACHE_004
STAGING_RING=PASS
ASYNC_PREFETCH_NONBLOCKING=PASS
ACQUIRE_WAITS_INFLIGHT=PASS
GPU_BYTES_VALID=PASS
DEMAND_ASYNC=PASS
CPU_EXPERT_COMPUTE=0
ASYNC_SUBMITS=2
ASYNC_WAITS=2
GPU_FREED=PASS
VERDICT=PASS
```

The Windows Vulkan attachment path must still be exercised inside the real Deep2 process because this build environment does not expose your R9700/7800 XT Vulkan device handles.

## Recommended production receipt fields

```text
EXPERT_CACHE_VULKAN_ATTACH=
EXPERT_STAGING_BYTES=
EXPERT_CACHE_REQUESTS=
EXPERT_CACHE_HITS=
EXPERT_CACHE_MISSES=
EXPERT_ASYNC_SUBMITS=
EXPERT_ASYNC_WAITS=
EXPERT_UPLOAD_BYTES=
EXPERT_UPLOAD_FAILURES=
EXPERT_STALL_US=
CPU_EXPERT_COMPUTE=0
STRICT_GPU_VIOLATIONS=
DECODE_TPS=
```
