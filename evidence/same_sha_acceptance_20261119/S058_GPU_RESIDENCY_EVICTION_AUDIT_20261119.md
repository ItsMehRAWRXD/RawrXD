# S058 GPU residency and eviction audit

Retained device-bound runs report bounded working-set telemetry on both AMD devices: 934.8 MB peak/live device bytes, 204 initial allocations, zero steady-state allocations, 402 cache hits, 197 misses, and zero allocation failures. The earlier Qwen27B run also reported stable headroom after per-block reclamation.

These receipts demonstrate bounded behavior for the tested short workloads, but they do not prove long-context eviction, fence-safe retirement, or restoration to a post-unload baseline. The separate allocation-owner audit remains required for those claims.

```ini
S058=SHORT_WORKLOAD_BOUNDED_RESIDENCY_REPORTED_LONG_CONTEXT_OPEN
DEVICE_BYTES_PEAK=934.8_MB_RETAINED_RUNS
STEADY_STATE_ALLOCS=0_RETAINED_RUNS
ALLOC_FAILURES=0_RETAINED_RUNS
LONG_CONTEXT_EVICTION=NOT_VERIFIED
POST_UNLOAD_BASELINE=NOT_VERIFIED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
