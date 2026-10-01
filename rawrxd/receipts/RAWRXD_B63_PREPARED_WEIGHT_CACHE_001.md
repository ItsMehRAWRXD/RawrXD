# RAWRXD_B63_PREPARED_WEIGHT_CACHE_001

## Status: PASS

The gate is not a TPS target. It is that CPU dequantization for a prepared
weight happens at most once across the whole generation.

```
GATE_PRIMARY = CPU_DEQUANT_CALLS(weight) <= 1 across multiple generated tokens
GATE_PASS    = 1
```

## The defect

`BOUNDED_STREAM` conflated two independent questions:

1. how much F32 may be resident on the GPU  (a VRAM admission question)
2. whether a weight is re-dequantized      (a CPU cost question)

It answered (2) by re-dequantizing on every call, into `thread_local` scratch
that was then uploaded and discarded. For Q2_K that is once per
(layer, weight, decode token). Measured before the fix:

```
ENSURE_F32_STREAM = 3024   (llama3.2-3b-Q2_K, 32 tokens)
ENSURE_F32_STREAM = 0      (tinyllama Q4_K_M, same engine, same binary)
```

So the engine was manufacturing its GPU representation from scratch every token
and throwing it away. That is why decode TPS fell with model size rather than
tracking the memory-bandwidth bound.

## The fix

Split the representation lifecycle from the memory policy:

```
quantized source authority (GGUF tensor, authoritative and unchanged)
        |
        v
persistent prepared F32   (host, LRU-bounded, survives GPU eviction)
        |
        v
bounded GPU residency     (unchanged: still a separate admission decision)
```

Implementation: `PreparedWeightCache` in `Deep2Engine_GpuForward.cpp`, owned by
the engine via `preparedWeights_` and released explicitly in `~Deep2Engine`
BEFORE the Vulkan transports, because its keys are the model's source tensor
pointers.

Explicitly NOT a switch to `RESIDENT_CACHE`. That mode already existed as an
unbounded map keyed by weight name; adopting it would have made host F32 growth
an implicit invariant and reproduced the admission problem at larger model
sizes. The prepared cache has its own host budget
(`RAWRXD_PREPARED_BUDGET_BYTES`, default 12 GiB) and reports its accounting
separately. Prepared host bytes are never counted against the Vulkan heap.

Keys are the full identity `(source pointer, sourceBytes, ggmlType, elements)`,
not the pointer alone, so a remapped tensor cannot alias a stale prepared entry.

## Measured, same binary, hash stable across both runs

```
EXE_SHA256_PRE_RUN  = 1942706AE5DCBEFC5E1CFE06EBB7FBE30169854B3D9FD05170F064D91AEDC9EA
EXE_SHA256_POST_RUN = 1942706AE5DCBEFC5E1CFE06EBB7FBE30169854B3D9FD05170F064D91AEDC9EA
GIT_HEAD            = 9b843bf039f917040d1c7aeae4eaa3aea090870d
VULKAN              = AMD Radeon AI PRO R9700, vram=34208743424, compute_pipeline=1
```

### The gate

```
llama3.2-3b-Q2_K.gguf, 32 tokens, prompt "The capital of France is"

PREPARED_CACHE acquire=3024 miss=84 hit=2940 evict=0
               cpuDequantCalls=84 cpuDequantBytes=4227858432
ENSURE_F32_STREAM=0
CPU_DEQUANT_REPEAT=0
```

`acquire=3024` is identical to the pre-fix dequant event count: the same 3024
weight uses now happen, but only 84 of them perform a dequantization. The
remaining 2940 are cache hits. Repetition is zero.

84 misses is **consistent with** the model geometry (28 layers x 3 prepared
weights = 84) and is far below the 32-token generation length, which is the
property the gate actually rests on. The arithmetic is a consistency check, not
proof of semantic identity: this receipt does not enumerate the 84 cache keys,
so it does not establish WHICH tensors were prepared.

### Performance, both directions

| Model | Before | After |
|---|---|---|
llama3.2-3b-Q2_K | 0.59 TPS | **6.16 TPS** |
tinyllama-1.1b-Q4_K_M | 11.44 TPS | **12.15 TPS** (control, 4 runs, 11.88-12.40) |

The Q2_K model gained ~10x. The Q4_K_M control did NOT regress, which is the
important half: the fix did not trade a gain on one path for a loss on another.
The Q4_K_M path never entered the dequant branch, so it is served by a different
code path entirely and its numbers are unchanged within noise.

Teardown: 4/4 clean exits, no `TEARDOWN_FAULT`, the RAWRXD_VULKAN_TRANSPORT_LIFETIME_001
fix still holds with the new cache in the teardown order.

## The preserved A/B regression control

```
                     Q4_K_M (1.1B)    Q2_K (3B)
ENSURE_F32_STREAM    0                0            (was 0 / 3024)
cpuDequantCalls      0                84           (was 0 / 3024)
DECODE_TPS           12.15            6.16         (was 11.44 / 0.59)
```

This pair is now a permanent regression benchmark. If B63 regresses,
`cpuDequantCalls` returns toward 3024 on the Q2_K side while the Q4_K_M side
stays at 0. The counter difference collapses before any TPS number is worth
reading.

## Files changed

```
rawrxd/src/deep2/Deep2Engine_GpuForward.cpp   PreparedWeightCache; EnsureF32 now acquires
rawrxd/src/deep2/Deep2Engine.h                 PreparedWeights()/ReleasePreparedWeights(); preparedWeights_ member
rawrxd/src/deep2/Deep2Engine.cpp                release prepared cache before Vulkan transports in ~Deep2Engine
```

## Not closed

- **B62C** duplicate `rawrxd` target at `CMakeLists.txt:303` and `:13971`. With
  `RAWRXD_BUILD_CLI=OFF` only `:13971` generates the target. A fix added to
  `:303` is silently inert; this already cost one wasted build cycle.
- **B62P-RENAME** the artifact-path rename is still unexplained and uncontrolled.
- **B64** native Q2_K Vulkan GEMV. The F32 intermediate is still there: 84
  preparations moved 4.23 GB of F32 through the host this run, and each upload
  is 4 bytes per weight. B63 made the representation persistent; B64 should
  remove it. Expected ceiling is unchanged by B63: a 1.27 GB Q2_K model expanded
  to F32 is ~5 GB, well above the ~139 TPS bandwidth bound, so B64 is required
  to close the remaining gap, not merely to improve it.
- Host prepared bytes peak (~4.2 GB here) are tracked and reported but are not
  yet derived from measured `VK_EXT_memory_budget`, per
  RAWRXD_VULKAN_MEMORY_BUDGET_FAIL_OPEN_FORBIDDEN.