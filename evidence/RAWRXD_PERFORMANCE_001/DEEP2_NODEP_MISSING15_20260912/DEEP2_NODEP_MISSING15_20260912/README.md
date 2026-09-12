# DEEP2_NODEP_MISSING15_20260912

Purpose: fill the next 15 missing mechanical pieces after `TARGET=1`, while preserving:

- `FULL_MODEL_TPS_AUTHORITY=0`
- `PROMOTE=0`
- no synthetic decode authority
- no Vulkan SDK/header dependency in this drop
- no heap allocation
- no background threads
- no model-family tables

This is a source-only integration drop. The runtime supplies real Vulkan/GPU operations and observed counters through the ABI.

## Priority-ordered missing 15

1. **Post-forward device survival gate**  
   `d2_post_forward_survival()` — queue-idle → known-safe no-op submit → real embd submit.
   This must close before `TARGET=2`.

2. **Resource accounting snapshots**  
   `D2ResourceSnapshot` + `d2_resource_snapshot_validate()` for the nine requested checkpoints.

3. **GPU resource plateau proof**  
   `D2PlateauState` — detects transient/allocation/command-buffer growth against an observed baseline.

4. **Tier-0 fixed-arena planner**  
   `D2ArenaPlan` — weights + KV + persistent + scratch + ping/pong + command/descriptor reserve + driver reserve.

5. **Ping/pong activation validation**  
   `d2_pingpong_validate()` rejects overlap/overflow.

6. **Bounded descriptor-pool accounting**  
   `d2_descriptor_bound_check()` prevents unbounded per-block descriptor growth.

7. **Bounded command-buffer ring**  
   `d2_command_ring_validate()` rejects more in-flight command buffers than the fixed ring owns.

8. **Bounded submission chunking**  
   `d2_submission_chunk_count()` supports replacing one monolithic 61-block submission with bounded batches.

9. **Fence/semaphore/resource-retirement validation**  
   `d2_sync_validate()` catches reuse/free-before-complete class errors.

10. **Shader/range OOB guard**  
    `D2Range` + `d2_range_validate()` for tensor/scratch/descriptor-bound dispatch ranges.

11. **Late-stage barrier ordering check**  
    `d2_barrier_validate()` ensures producer ≤ barrier ≤ consumer serial ordering.

12. **Queue-family ownership check**  
    `d2_queue_ownership_validate()` validates the declared owner before any release/acquire operation.

13. **64-bit offset/allocation overflow guard**  
    `d2_u64_add_checked()` prevents late-block/expert-range wraparound.

14. **Failure-localization bisection state**  
    `D2BisectState` supports `1/8/16/32/48/56/60/61/+norm/+lm_head` style narrowing without changing authority.

15. **Strict TARGET=2 authority checker**  
    `d2_target2_authority_check()` requires a second real full-block forward, post-Advance embd, position 1, no token-1 sealed-logits reuse, `DEVICE_LOST=0`, and still refuses TPS/promotion authority.

## Suggested integration order

```text
DEEP2_FULL_DECODE_TOKEN_REAL TARGET=1       PASS
    ↓
#01 + #02
DEEP2_POST_FORWARD_DEVICE_SURVIVAL_001
    ↓
#03 + #04 + #05 + #06 + #07
DEEP2_GPU_RESOURCE_PLATEAU_001
    ↓
#08 + #09 + #10 + #11 + #12 + #13 + #14
fault localization / lifetime fix
    ↓
#15
DEEP2_FULL_DECODE_TOKEN_REAL TARGET=2
    ↓
TARGET=4 → 16 → 64
    ↓
FULL_MODEL_TPS_AUTHORITY (separate gate)
```

## Build

MSVC source-only smoke:

```bat
build_smoke.bat
```

The smoke proves only ABI/mechanical logic. It **cannot** mint GPU/device/decode evidence.

## Integration hooks required from Deep2

The host runtime must provide:

- real queue-idle result
- real known-safe GPU no-op submit result
- real embd submit result
- real resource counters at each checkpoint
- actual Vulkan lifetime/barrier/ownership observations
- actual `TARGET=2` counters

No declaration in this drop can convert those observations into runtime evidence by itself.
