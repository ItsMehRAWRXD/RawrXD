# RAWRXD_EXPERT_CACHE_005

This batch closes the stack-overflow failure observed as Windows status `0xC00000FD` while adding the first production dual-GPU expert placement scheduler.

## 1. Stack-overflow closure

The observed crash occurs after a successful Vulkan forward sequence and at the start of a new generation prefill. Do not increase process stack as the primary fix. Remove `_alloca`, VLAs, and large frame-local activation/attention/rope scratch buffers from forward code and allocate them from `HeapScratchArena` or Deep2's existing heap scratch allocator.

At the top of forward entry points:

```cpp
ForwardDepthGuard depth(runtime.maxForwardDepth);
if (!enterForward(runtime, depth)) {
    // receipt: FWD_RECURSION_GUARD=FAIL
    return false;
}
```

Create/reuse one arena per worker thread or inference context:

```cpp
thread_local HeapScratchArena scratch(8 * 1024 * 1024);
scratch.reset();
float* tmp = scratch.allocArray<float>(count, 64);
if (!tmp) return false;
```

Never put model-size-dependent buffers on the stack.

## 2. Required source audit

Search Deep2 forward/generate paths for:

- `_alloca`, `alloca`
- `T local[variable_or_large_constant]`
- recursive `forward`, `forwardLayer`, `generate`, prefill helpers
- lambdas/functions that accidentally call the public generate path during prefill

The crash trace strongly suggests re-entry or model/prompt-size stack growth around the second `GEN_PREFILL_BEGIN`.

## 3. Dual-GPU expert scheduler

`ExpertScheduler` scores devices using available cache capacity, router probability, existing locality, transfer pressure, and recent compute pressure. It makes no peer-memory assumption, matching separate-device Vulkan operation.

Feed it the live R9700/7800XT telemetry and hand the chosen device to the Batch-004 per-device `VulkanExpertTransport`/cache instance.

## 4. Strict receipt

Require the shipping gate to emit:

```text
STACK_OVERFLOW=0
FORWARD_DEPTH_MAX=<n>
FORWARD_RECURSION_REJECTS=0
HEAP_SCRATCH=PASS
VULKAN_FORWARD=PASS
LOGITS_FINITE=PASS
CPU_EXPERT_COMPUTE=0
EXPERT_CACHE_HIT_RATE=<ratio>
EXPERT_BYTES_H2D=<bytes>
EXPERT_STALL_US=<us>
DEVICE0_EXPERTS=<n>
DEVICE1_EXPERTS=<n>
DECODE_TPS=<value>
VERDICT=PASS
```

## 5. Regression invocation

Use the exact model/prompt path that reproduced `0xC00000FD`. The acceptance criterion is not merely process survival: forward must complete, logits must be finite, at least one token must be generated, and the stack overflow status must disappear.
