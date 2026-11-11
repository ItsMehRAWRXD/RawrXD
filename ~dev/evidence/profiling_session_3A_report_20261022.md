# Deep2 Sustained Profiling Session 3A

## Scope

- Model: `llama3.2:3b`
- Context: 2048
- Decode lengths: 8, 32, 128, 256
- Repetitions: 3 per length and mode
- Modes: single GPU and opt-in dual GPU
- Validation: exit success, complete requested token count, zero unplanned fallbacks, zero strict violations

## Results

| Decode tokens | Single TPS | Dual TPS | Single mean ms | Dual mean ms | Dual physical GPU |
|---:|---:|---:|---:|---:|:---:|
| 8 | 8.77 | 6.50 | 918.9 | 1293.0 | 3/3 |
| 32 | 12.65 | 10.45 | 2530.4 | 3102.6 | 3/3 |
| 128 | 11.51 | 12.52 | 11779.6 | 10245.7 | 3/3 |
| 256 | 10.62 | 12.75 | 24753.2 | 20084.7 | 3/3 |

All 24 runs completed with zero unplanned fallbacks and zero strict GPU violations.

## Bottleneck conclusion

The current receipts do not contain valid per-dispatch Vulkan timestamp buckets, transfer durations, or fence-wait durations. Therefore the dominant bottleneck is **not certified by this sweep**. The data does establish a workload crossover: dual GPU loses on short sequences and wins on longer sequences, consistent with fixed coordination overhead amortizing over more decode work, but it does not prove whether the remaining cost is dispatch, synchronization, transfer, or kernels.

## Next measurement

Expose the existing Vulkan timestamp-query and counter data through the run receipt, with separate GPU0/GPU1 critical-path intervals, H2D/D2H bytes, queue submissions, fence waits, and per-token wall time. Do not sum overlapping device intervals as wall time. No kernel mutation should be promoted until those buckets are populated.

## Evidence

- `F:\rawrxd\~dev\evidence\profiling_session_3a\profiling_session_3A_20261022_210345.json`
- `F:\rawrxd\~dev\evidence\profiling_session_3a\profiling_session_3A_20261022_210759.json`
- `F:\rawrxd\~dev\tools\rawr_sustained_profile_3a.ps1`

`100+ TPS` remains unachieved and uncertified.
