# Deep2 Top-15 Missing Generators — no dependency source drop

This drop implements the missing *generator plane*: deterministic, zero-allocation planners that turn live model state into the exact work transactions consumed by Deep2/SsVk. It does **not** replace the already-passing packed Q2_K operator and does not mint live authority.

## Top 15
1. Token transaction generator — canonical N>0 decode order: embed -> full forward -> final norm -> KV advance -> LM head -> sample -> commit -> N+1 prefetch.
2. Dual finish-time work generator — start-skew + measured per-work costs, aligned output, one balancing authority.
3. Persistent command generator — only rebuilds when execution signature changes.
4. Descriptor-bind generator — resource-signature epochs; no per-token blind rebinding.
5. KV advance generator — ring slot/offset/wrap plan without host-copy semantics.
6. Exact-range residency generator — VRAM0/VRAM1/RAM tier request from real free budget.
7. N+1 prefetch generator — bounded next-token exact-range request list.
8. MoE expert locality generator — top-k expert-to-lane placement plan.
9. Quant dispatch generator — Q2_K/Q3_K/Q4_K/Q5_K/Q6_K/Q8_0 packed-native IDs, fail closed on unknown quant.
10. LM-head tile generator — aligned vocabulary-row partition for dual-lane execution.
11. Compact reduce generator — partial-count and compact input/output byte plan.
12. Sampler-commit generator — token commit epoch bound to live logits epoch.
13. UTF-8 stream-chunk generator — never splits a multibyte code point.
14. Cancel/reset/reuse generator — explicit generation epoch transition.
15. Authority receipt generator — conjunction of product/packed/overlap/full-forward/tail/parity plus all fail-closed zero counters.

## Integration law
The generators are plan producers only. Product execution remains in Deep2Engine/SsVk. In particular, the Q2_K dispatcher must resolve to the same 84-byte packed product implementation that produced live aggregate authority; do not route it through a stale alternate geometry, subprocess, or receipt replay.

`d2g_authority_receipt()` is intentionally stricter than a performance benchmark: both GPU forward deltas must be non-zero; all forbidden fallback/host/materialization/storage/device-loss counters must remain zero.

## Build
Windows/MSVC developer shell:

```
build_msvc.bat
```

Portable smoke used to validate this archive:

```
cc -std=c99 -O2 -Wall -Wextra -pedantic d2_generators.c selftest.c -o selftest
./selftest
```

The selftest is synthetic and cannot set `PROMOTE=1`.
