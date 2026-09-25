# RAWRXD_EXPERT_CACHE_006 integration

## 1. What changes in 006

Batch 006 puts a production authority above the Batch-004 per-device caches. The important ownership
rule is now:

```text
GGUF / mapped host bytes (ONE copy per expert)
        |
        +--> ExpertCache(device 0 / R9700) ----> VulkanExpertTransport(0)
        |
        +--> ExpertCache(device 1 / 7800 XT) --> VulkanExpertTransport(1)
                         ^
                         |
                 ExpertScheduler
            router probability + locality
            + compute pressure + transfer pressure
```

Do not create two `Deep2ExpertCacheBridge` objects for the same catalog if that would duplicate the
host expert backing. Use `Deep2MultiGpuExpertCache`, which copies the catalog once and registers those
stable host pointers with each device cache.

## 2. Deep2 creation

Create one Batch-004 `VulkanExpertTransport` per actual Deep2 Vulkan device/queue/command-pool set.
Convert each transport to `ExpertTransport` callbacks and give each device an explicit cache budget.
No Vulkan device-group or peer-memory assumption is made.

```cpp
std::vector<MultiGpuExpertDeviceConfig> devices;

MultiGpuExpertDeviceConfig r9700{};
r9700.cache.deviceOrdinal = 0;
r9700.cache.budgetBytes = r9700ExpertBudgetBytes;
r9700.cache.prefetchDepth = 1;
r9700.transport = r9700Transport->callbacks();
devices.push_back(r9700);

MultiGpuExpertDeviceConfig rx7800{};
rx7800.cache.deviceOrdinal = 1;
rx7800.cache.budgetBytes = rx7800ExpertBudgetBytes;
rx7800.cache.prefetchDepth = 1;
rx7800.transport = rx7800Transport->callbacks();
devices.push_back(rx7800);

MultiGpuExpertRuntimeConfig runtimeCfg{};
runtimeCfg.enabled = cacheEnabled;
runtimeCfg.strictGpuOnly = true;
runtimeCfg.evictSourceAfterMigration = true;
runtimeCfg.prefetchDepth = 1;

Deep2MultiGpuExpertCache expertRuntime(std::move(devices), runtimeCfg);
expertRuntime.importCatalog(expertCatalog);
```

## 3. Router / decode integration

Immediately after router scores exist, feed the current rolling device pressure and prefetch the most
likely future expert while current GPU work is executing:

```cpp
expertRuntime.updateDevicePressure(0, gpu0ComputeUs, gpu0TransferUs, gpu0Available);
expertRuntime.updateDevicePressure(1, gpu1ComputeUs, gpu1TransferUs, gpu1Available);

RoutedExpertHint next[] = {
    {{layer, nextExpert0}, nextProb0},
    {{layer, nextExpert1}, nextProb1},
};
expertRuntime.prefetchPredicted(next, std::size(next), tokenIndex + 1);
```

At demand time:

```cpp
RoutedExpertHint need{{layer, expertId}, routerProbability};
auto binding = expertRuntime.acquire(need, tokenIndex);
if (!binding) {
    // strict GPU failure -- do not run the expert on CPU
    return false;
}

// Use binding.deviceOrdinal to select that GPU's Vulkan transport.
// Convert binding.deviceHandle with VulkanExpertTransport::binding() and bind
// binding.tensorOffsets to the existing expert GEMV/GEMM path.

runExpertGpu(binding);
expertRuntime.release(binding);
```

When cache is ON, `release()` keeps the expert resident. When cache is OFF, the same call evicts after
GPU execution, making the next request pay the real upload again. This keeps OFF/ON comparisons on the
same compute path.

## 4. Important 004 correction carried by 006

Batch 004 counted async transfer lifetime as `stallMicros`, including time hidden by prefetch. That
made a successful overlap look like a decode stall. Batch 006 changes the accounting:

```text
transferMicros = total async H2D lifetime
stallMicros    = time demand actually blocks waiting for H2D
residentBytes  = ready device-local expert bytes
inflightBytes  = device-local bytes reserved by transfers still in flight
```

Demand on an in-flight expert now polls first. If the transfer has already completed, no fence wait or
stall is charged.

## 5. Stack-overflow closure from 005 remains mandatory

The supplied stack guard does not patch your `Deep2Engine.cpp` automatically. The shipping forward
path still needs all model/prompt-sized stack temporaries moved to `HeapScratchArena` (or your existing
context scratch allocator), with `ForwardDepthGuard` at the public forward boundary. The acceptance
run that previously exited with `0xC00000FD` must be repeated.

## 6. Hardware A/B receipt

Use the same model, quant, prompt, context, generated-token count, and GPU assignment for both runs.
Populate `ExpertBenchmarkSample` from the actual decode wall clock and `expertRuntime.receipt()`, then
format with `formatExpertCacheReceipt()`.

Require at minimum:

```text
GATE=RAWRXD_EXPERT_CACHE_006
CACHE_OFF_TPS=<real>
CACHE_ON_TPS=<real>
TPS_GAIN_PERCENT=<real>
EXPERT_CACHE_HIT_RATE=<real>
EXPERT_BYTES_H2D_OFF=<bytes>
EXPERT_BYTES_H2D_ON=<bytes>
EXPERT_TRANSFER_US_ON=<us>
EXPERT_STALL_US_OFF=<us>
EXPERT_STALL_US_ON=<us>
PREFETCH_ISSUED=<n>
MIGRATIONS=<n>
CPU_EXPERT_COMPUTE=0
STRICT_GPU_VIOLATIONS=0
DEVICE0_EXPERTS=<n>
DEVICE1_EXPERTS=<n>
```

For the exact crash regression additionally require:

```text
STACK_OVERFLOW=0
FORWARD_RECURSION_REJECTS=0
LOGITS_FINITE=PASS
GENERATED_TOKEN_COUNT=>0
```
