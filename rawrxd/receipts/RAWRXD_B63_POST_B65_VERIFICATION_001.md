# RAWRXD_B63_POST_B65_VERIFICATION_001

## Purpose

Re-verify the B63 prepared-weight cache after B65/B66/B67 added a native Q3_K
path. B63's gate was `CPU_DEQUANT_CALLS(weight) <= 1`; adding native dispatch
could have changed which tensors reach `EnsureF32` at all.

## Result: B63 still correct, but now DORMANT for every model on disk

```ini
RAWRXD_B63_POST_B65_VERIFICATION_001=PASS
B63_GATE_STILL_HOLDS=1
B63_STILL_EXERCISED=NO   <-- material finding
```

## Tensor type survey, current binary

```ini
tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
   GEMV_NATIVE  type=12 (Q4_K) x402
                type=14 (Q6_K) x60
   PREPARED_CACHE_LINE  = NONE
   F32_GEMV_DISPATCHES  = 0

llama3.2-3b-Q2_K.gguf
   GEMV_NATIVE  type=10 (Q2_K) x224
                type=11 (Q3_K) x168
   PREPARED_CACHE_LINE  = NONE
   F32_GEMV_DISPATCHES  = 0
```

Every projection on both models now executes on the GPU quantized path. No
tensor reaches `EnsureF32` with a quantized type, so **zero** CPU
dequantization and **zero** F32 preparation occur on either model.

```ini
CPU_DEQUANT_CALLS=0     (both models)
F32_PREPARED_BYTES=0    (both models)
PREPARED_CACHE_ACQUIRE=0 (both models)
```

## Consequence

The sequence of gates was:

```text
B63  prepared cache        3024 acquires -> 84 dequant  (0.59 -> 6.16 TPS)
B64  Q2_K native proven    0.59 -> 6.49
B65  Q3_K native proven    6.49 -> 2.01  (regression: FAILED first attempt,
                                          then 3 real defects fixed)
B66  shared unpack         2.01 -> 6.59
B67  dot4                  6.59 -> 6.37  (no gain)
B69  dead stub removed     6.46, parity exact
```

B63's cache is what made B64 and the B65 attempt possible at all: without it,
every quantized weight was re-dequantized per token. But B65-B67 have now
removed the reason to fall back to it. The cache remains correct and remains the
fallback for any quant type outside `{8, 10, 11, 12, 14}`.

Its eviction logic is therefore no longer exercised by any model available on
this machine, and a run with a tight budget (`RAWRXD_PREPARED_BUDGET_BYTES=100
MiB`) produced no `PREPARED_CACHE` or `PREPARED_OVERSIZE` line at all — because
nothing was prepared, not because eviction is known-good.

```ini
B63_EVICTION_PATH_EXERCISED=NO
B63_EVICTION_PATH_VERIFIED=UNVERIFIED
```

This is an honest limit, not a pass. The LRU eviction and oversized-weight
handling in `PreparedWeightCache::Commit` / `EnforceBudget` have not been
observed running. Verifying them requires either a model containing a quant type
outside the native set, or a synthetic test that feeds the cache directly.

## Recommended

Do not treat B63 as retired. It is the safety net for any GGUF whose weights
fall outside the natively-supported set, and those exist. To close the
unverified-eviction gap, either:

1. find or fetch a model with Q5_K (type 13) or Q4_0 (type 2) weights — `PackedQuant`
   does not include Q5_K, so those tensors would route through the cache and
   exercise eviction under a tight budget; or
2. extend `q3k_block_diff.cpp` into a direct `PreparedWeightCache` unit test with
   a synthetic source tensor set and a budget smaller than the working set,
   asserting `evict > 0` and that prepared bytes never exceed the budget.

Option 2 is cheaper and does not depend on acquiring a model.

## Provenance

```ini
EXE_SHA256_PRE  = 354170570D9DA0C4042CC41667FAD91D8882734A4CDE858BD770BDA5A91235AD
EXE_SHA256_POST = 354170570D9DA0C4042CC41667FAD91D8882734A4CDE858BD770BDA5A91235AD
GIT_HEAD        = 9b843bf039f917040d1c7aeae4eaa3aea090870d
B69_PARITY      = B65_EXACT (115 chars, llama3.2-3b-Q2_K, 24 tokens)
```