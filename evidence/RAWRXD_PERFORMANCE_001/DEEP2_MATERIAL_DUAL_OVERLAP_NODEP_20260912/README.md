# Deep2 material dual-GPU overlap — no-dependency source drop

This drop turns the earlier **tiny-overlap existence proof** into a fail-closed
mechanism for **material same-token overlap** over real packed product work.

## What changes architecturally

Before:

```text
GPU0 ---- work ----
                 \\ tiny overlap
GPU1              ---- work ----
```

Target:

```text
GPU0 ================= packed local rows ==================\\
                                                           +--> compact reduce
GPU1 ================= packed local rows ==================/
     <----------- material same-token overlap ----------->
```

The key is not "start two threads." The two Vulkan queues must actually execute
the real packed operator at the same time, and the proof must compare intervals
in a **shared clock domain**.

## Why calibrated timestamps are required

The R9700 and RX 7800 XT have independent GPU timestamp counters. Raw query-pool
timestamps from device 0 and device 1 cannot safely be subtracted from each
other. This drop uses `VK_EXT_calibrated_timestamps` to map each device interval
to Windows `QueryPerformanceCounter`, then computes overlap there.

If calibrated timestamps are unavailable, authority fails closed.

## Product bind

For each lane provide:

- product `VkDevice`, `VkQueue`, reusable `VkCommandBuffer`, two-slot query pool;
- Vulkan function pointers already resolved by Deep2;
- `timestampPeriod` and timestamp valid-bit count;
- `record_packed()` callback that records the **real Deep2 packed Q2_K local-row
  dispatch** into the supplied command buffer and reports exact packed bytes.

The runner records timestamps immediately around that callback, fires both queue
submissions from separate host threads behind one start event, waits both fences,
calibrates both GPU clocks to QPC, calls the real compact reducer, and evaluates
the authority conjunction.

`integration/deep2_bind_example.cpp` deliberately returns `-999` until you bind
real product calls. That prevents a source drop or smoke harness from minting
live authority.

## Recommended first gate

```text
DEEP2_PACKED_Q2K_PRODUCT_DUAL_AGGREGATE_001
PRODUCT_LINKED=1
PACKED_Q2K_LIVE=1
FULL_DEQUANT_BUFFER=0
MATERIALIZED_WEIGHT_BYTES=0
GPU0_PACKED_BYTES>0
GPU1_PACKED_BYTES>0
```

Then require, over repeated real decode tokens:

```text
MATERIAL_SAME_TOKEN_OVERLAP=1
OVERLAP/SHORTER_LANE >= 70%
OVERLAP/CRITICAL_SPAN >= 50%
WEIGHT_MIGRATION_BYTES=0
SERIAL_GPU_CHAIN=0
CRITICAL_PATH_NVME_READS_PER_TOKEN=0
DEVICE_LOST=0
COMPACT_REDUCE_REAL=1
```

A single token can only produce `AGGREGATE_BW_CANDIDATE=1`. The supplied repeated-token window evaluator defaults naturally to a strict 16/16 certification policy; only the window may produce `AGGREGATE_BW_AUTHORITY=1`.

## Build

From an MSVC x64 environment:

```bat
build_msvc.bat
```

No Vulkan SDK headers or import library are required by this module. It uses the
function pointers and handles already owned by Deep2.

## Integration order that increases overlap

1. **Partition once** per operator/model load; do not repartition per token.
2. Keep lane-local packed tensor views resident on their owning GPU.
3. Record/reuse lane command buffers or migrate to a persistent graph after the
   authority gate is correct.
4. Remove host work between lane submissions. The launch pair must be adjacent.
5. Do not stage GPU0 output into GPU1. Each lane emits only the compact partial
   required by the reducer.
6. Prefetch N+1 packed ranges while N executes, but keep storage reads outside
   the token critical path.
7. Run a repeated-token window and use the minimum/p05 overlap ratio, not the
   single best token, for production authority.

## What this drop does *not* claim

`LIVE_PRODUCT_RUN=NOT_RUN`. The container used to create this source drop has no
access to the user's two Windows GPUs or RawrXD product tree. The portable core
self-test verifies only the fail-closed interval/authority math.
