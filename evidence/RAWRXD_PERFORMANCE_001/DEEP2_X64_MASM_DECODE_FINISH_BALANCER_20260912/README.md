# DEEP2_X64_MASM_DECODE_FINISH_BALANCER_20260912

Pure x64 MASM, caller-owned state, no CRT/heap/OS/Vulkan dependencies.

## Objective

Balance **absolute decode completion times** for the two GPU lanes, not nominal rows:

```
E0 = S0 + c0*w0
E1 = S1 + c1*w1
w0 + w1 = W
TARGET: E0 ~= E1 and min(max(E0,E1))
```

The planner solves:

```
w0 = (c1*W + (S1-S0)) / (c0+c1)
w1 = W-w0
```

where `c0/c1` are measured Q16 ns/effective-row EWMAs and `S1-S0` is measured start skew. This means launch skew participates directly in the split instead of being misdiagnosed as throughput imbalance.

## Top 15 enhancements

1. Absolute finish-time objective (`END0 ~= END1`).
2. Start-skew compensation in the split equation.
3. Per-token adaptive planning; no permanent 67/33 or 80/20 law.
4. Effective-work costs learned from live duration/rows.
5. Q16 integer EWMA; no floating-point dependency.
6. Fail-closed sample admission on parity/device/product invariants.
7. Same-token-only learning prevents cross-token contamination.
8. Packed-row alignment enforced by the planner.
9. Non-zero work on both devices to preserve concurrency evidence.
10. Best-critical-path retention independent of pretty split ratios.
11. >5% critical-path regression rollback to best-known share.
12. Signed finish-skew state so controller knows which lane is late.
13. Signed start-skew state to distinguish launch delay from work cost.
14. Predicted lane end-times exported with every plan for receipt comparison.
15. Caller-owned 104-byte state machine: no allocation, locks, runtime, or hidden calls.

## Integration

```
D2DbInit(&state)

for each decode token / balanced kernel segment:
    D2DbPlanToken(&state, totalRows, rowAlignment, &plan)
    launch GPU0 plan.rows0
    launch GPU1 plan.rows1
    capture START/END timestamps
    fill D2DB_SAMPLE with parity/device/product flags
    D2DbObserveToken(&state, &sample)
```

Do not independently retain an old `REPS_SPLIT` compensation while also applying the planner's row split. Convert the scheduler to one **effective-work authority** per segment, or the correction can be double-applied.

## Required next receipt

```
GATE=DEEP2_DUAL_AGGREGATE_DECODE_FINISH_BALANCE
PRODUCT_LINKED=1
PACKED_Q2K_LIVE=1
OUTPUT_PARITY=1
DEVICE_LOST=0
SERIAL_GPU_CHAIN=0
WEIGHT_MIGRATION=0

TOKEN=n
ROWS0=x ROWS1=y
GPU0_START_NS=...
GPU0_END_NS=...
GPU1_START_NS=...
GPU1_END_NS=...
START_SKEW_NS=...
FINISH_SKEW_NS=...
CRITICAL_PATH_NS=...
OVERLAP_NS=...

PASS window requires:
  median(CRITICAL_PATH_NS) < baseline
  median(abs(FINISH_SKEW_NS)) materially reduced
  overlap/critical does not regress materially
  parity/device invariants remain clean
```

Status: SOURCE_DROP_NOT_RUN. This archive does not claim product linkage or a measured performance improvement.
