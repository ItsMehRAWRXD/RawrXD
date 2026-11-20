# Same-process model lifecycle (A → B → A) — 2026-11-19

Sprint gate: **is a cache hit valid after a model replacement?**

## Setup

```
exe    F:\rawrxd\build\Release\deep2_lifecycle_probe.exe
SHA256 35AD33643707CFDF0DC638CDA1E86C115BBB3E2DABF55107A2807ADF67BC1B14

A = F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
B = F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf
tokens = 1 450   GPU   Strata expert tracking on
one process, one Vulkan cache instance, A -> B -> A
```

## Result

```
[A2] gpu=310 cpu=0 hits=508 misses=507 evictions=0 (budget=0 trim=0)
     live=2240009208 signature=-20794.4875
DETERMINISM A1_vs_A2 rel=0        PASS
SEPARATION  A1_vs_B  rel=1.61926  PASS (models differ)
LIFECYCLE_STATUS PASS
Vulkan resources cleaned up successfully
exit 0
```

## Interpretation

* **Determinism** — A loaded a second time, after B, reproduces A's logits signature
  *exactly* (`rel = 0`). The 508 hits recorded in phase A2 are therefore **valid
  hits**: they returned model-A values, not stale model-B weights.
* **Separation** — B's signature differs from A by `rel = 1.62`, so the cache does
  not alias entries across models; a reused allocation address did not produce a
  false hit in this run.
* **Same cache instance** — hits/misses accumulated within one process
  (`hits=508 misses=507`), with a clean Vulkan teardown at exit.

## Caveats (not proven by this run)

* `rel = 0` is the strongest available signal, but it does not *force* the allocator
  to reuse an address; pointer-reuse safety is supported, not exhaustively proven.
* No explicit cache-generation identifier exists yet; a test-only generation counter
  would make the invalidation boundary directly observable.
* Two small models, two tokens, single device.

## Next

* Add a cache-generation/ownership id to the eviction record for a direct
  invalidation receipt.
* Phase 1B: `deep2_strata_chat.cpp` (namespace fixed the same way:
  `using namespace RawrXD::Deep2;`).