# Top 15 missing finishers — DEEP2_ROOFLINE_LOCALITY_001

1. **Warm + exact 64-token authority window** — token 1 remains warm/baseline; tokens 2..65 are the measured 64.
2. **Byte-true weight demand counter** — every requested packed-weight byte is counted, not merely hit/miss events.
3. **Byte-true already-local weight counter** — uses the real residency/cache-hit decision that execution consumes.
4. **KV locality accounting** — separate demanded KV bytes from KV bytes already local to the executing device.
5. **Activation/reduction locality accounting** — count residency-boundary demand without multiplying normal on-device reads.
6. **Checked non-local arithmetic** — `demand - local` with overflow/underflow fail-closed handling.
7. **Host->device transport accounting** — actual copy bytes, separately exposed so they are not double-counted as demand.
8. **Critical-path host-byte attribution** — distinguish unavoidable off-device bytes from asynchronous/background copies.
9. **Inter-GPU traffic accounting** — real GPU0<->GPU1/staged bytes; zero is valid when no cross-device movement occurs.
10. **Per-device forward counts** — GPU0 and GPU1 execution counts are explicit invariants.
11. **True same-token overlap** — intersect timestamp intervals by token ordinal; do not infer overlap from aggregate use.
12. **64 individual token latencies** — P50/P95/MAX plus generation wall time and measured TPS.
13. **Parent-seal regression latch** — BIND16/PERSISTENT/RESIDENCY remain sealed and residency deltas stay zero.
14. **Fail-closed locality policy** — an explicit non-local bytes/token ceiling is required; no source-default authority threshold.
15. **Machine receipt + verifier** — full `CONJ_OPS`, `CERT_EXIT=0|2`, `ROOFLINE_LOCALITY=PASS|FAIL`, always `PROMOTE=0`.

## Deliberately not changed

- The sealed Q6_K content-fingerprint hit-skip.
- BIND16 or persistent-decode logic.
- Weight placement/scheduler decisions.
- Existing `d2_roofline` planner authority rules.
- Promotion law.

This drop is measurement/certification plumbing. It must not make the workload easier merely to pass itself.
