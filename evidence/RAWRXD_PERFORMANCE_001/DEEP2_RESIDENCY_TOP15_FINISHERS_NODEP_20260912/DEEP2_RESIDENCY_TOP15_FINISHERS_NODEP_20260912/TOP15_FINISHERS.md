# Residency Top-15 finishers

1. **Single residency owner** — one canonical owner controls residency state.
2. **Monotonic generation** — stale generations cannot serve a newer request.
3. **Single first-touch winner** — duplicate cold first touch cannot duplicate I/O.
4. **Join/reuse in-flight work** — a competing request reuses the active load.
5. **Failed-first-touch rollback** — failure never leaves a false WARM/HOT state.
6. **Exact-range containment** — resident range must wholly contain requested bytes.
7. **Codec identity preservation** — hits require the same observed packed codec.
8. **Pin/use exclusion** — a pinned/current-use region cannot be evicted.
9. **Explicit demotion** — HOT→WARM and WARM→COLD are counted state transitions.
10. **Zero weight-upload delta** — post-warm decode must retain `wup_d=0`.
11. **Zero reload delta** — no repeated backing reload during the decode window.
12. **Zero device/model recreation** — persistent decode does not rebuild the runtime.
13. **Positive resident byte witness** — sealed residency must represent real bytes.
14. **Parent authority retention** — BIND16 + persistent + dual/resident predicates remain true.
15. **No upward authority mint** — this side drop cannot mint decode/token/promotion authority.

All 15 are regression guards. They do not supersede the live product receipt at
`e80ef647e7` and do not advance the gate beyond `DEEP2_ROOFLINE_LOCALITY_001`.
