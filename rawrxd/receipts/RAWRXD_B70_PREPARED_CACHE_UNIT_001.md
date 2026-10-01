# RAWRXD_B70_PREPARED_CACHE_UNIT_001

## Status: PASS — B63 recertification closed

```ini
RAWRXD_B70_PREPARED_CACHE_UNIT_001=PASS
checks=30  failures=0
TOTAL_CPU_DEQUANT_CALLS=7

B63_IMPLEMENTATION_PRESENT=YES
B63_HISTORICAL_PREREQUISITE=YES
B63_EVICTION_CURRENTLY_VERIFIED=YES
B63_OVERSIZED_WEIGHT_CURRENTLY_VERIFIED=YES
B63_KEY_IDENTITY_VERIFIED=YES
B63_GATE=PASS
B63_RECERTIFICATION=COMPLETE
B63_RECERTIFIED_AGAINST=production implementation (shared header)
```

## The gap this closed

B63 shipped a bounded LRU cache verified only through inference:

```ini
acquire=3024  miss=84  hit=2940  evict=0  cpuDequantCalls=84
```

That proved miss/hit accounting. It did NOT prove eviction — the model's whole
working set fit inside the 12 GiB default budget, so nothing was ever evicted.

After B65/B66/B67 added native Q3_K, no model on this machine routes a tensor
through the cache at all:

```ini
tinyllama    type=12(Q4_K) x402  type=14(Q6_K) x60    prepared=0  F32=0
llama3b_q2k  type=10(Q2_K) x224  type=11(Q3_K) x168   prepared=0  F32=0
```

So `evict=0` had become vacuous. A tight-budget model run cannot help either: it
produces no prepared entries, so there is nothing to evict. Testing through
inference would have required forcing the model backward into a representation it
no longer needs.

## Why the test includes the real header

The first draft of this test re-declared the cache class. That would have tested
a copy — the exact defect that let B63 ship with its eviction path unverified.

The cache was therefore **extracted** into
`rawrxd/src/deep2/Deep2_PreparedWeightCache.hpp`, included by both
`Deep2Engine_GpuForward.cpp` and `tools/prepared_cache_unit.cpp`. One
implementation, compiled twice.

```ini
ENGINE_TU   = Deep2Engine_GpuForward.cpp  (includes the header)
TEST_TU     = tools/prepared_cache_unit.cpp (includes the same header)
LINKS_TO    = nothing (no Vulkan, no InferenceEngine, no model)
```

`Acquire()` now takes the dequantizer as a parameter instead of calling
`QuantKernelRegistry` directly, which is what lets the header be self-contained.
The engine passes `GetDequant(wt.type)`; production behavior is unchanged.

## Four properties, all verified

```ini
P1  INSERT + RESIDENCY     11 checks
P2  TOUCH + LRU EVICTION   5 checks
P3  RECREATION STABILITY   4 checks
P4  OVERSIZED POLICY       6 checks
KEY  IDENTITY              1 check
```

P2 is the one that matters and it is discriminating by construction. Insertion
order is A, B; then A is touched; then C is inserted and forces eviction. LRU
must evict **B** (least recently used). FIFO would evict **A** (inserted first).
The touch is what makes the two policies disagree, so the assertion cannot pass
under a broken FIFO implementation.

```ini
P2 exactly one eviction on overflow                       ok
P2 most-recently-used A survived (LRU, not FIFO)          ok
P2 least-recently-used B was evicted, re-request MISSES  ok
P2 recreated B was genuinely re-dequantized              ok
```

Budget invariant `preparedBytesLive <= budget` is asserted in P1, P2, P3 and P4.

## Two failures that were the test's fault, not the cache's

Both are recorded because they are the kind of error that produces a false
closure in the other direction.

**Vacuous eviction.** The original budget was 1 MiB with 256 KiB tensors. Four
tensors fit *exactly*, and `1048576 > 1048576` is false — so no eviction was ever
due and the assertions were testing nothing. Fixed to 640 KiB so that two tensors
fit and a third genuinely overflows.

**Pointer identity as a freshness test.** `pBafter != pB` asserted that a
recreated entry got a new address. The allocator legitimately returned the
address it had just freed, so the assertion failed while the cache was correct.
Recreation is now proven by the MISS counter plus a fresh dequant, which is the
semantically correct check.

```ini
TOTAL_CPU_DEQUANT_CALLS=7   (exactly one per distinct preparation)
```

## Engine regression after the extraction

The refactor touched a live code path, so the engine was rebuilt and re-verified:

```ini
BUILD_EXIT              = 0
EXE_SHA256_PRE          = 87660DC46811E09BECC8303FF5297424D0DA586940989D7772D860759C44252E
EXE_SHA256_POST         = 87660DC46811E09BECC8303FF5297424D0DA586940989D7772D860759C44252E
MODEL                   = llama3.2-3b-Q2_K.gguf
B70_REGRESSION_PARITY   = PASS (115 chars, identical to the B65 oracle)
DECODE_TPS              = 5.04
```

TPS is lower than B69's 6.46. Single-sample decode TPS on this workload has
demonstrated variance of several percent across runs (documented in B66/B67), and
this is one sample; the parity result, not the TPS, is the gate here. A definitive
comparison would need repeated runs, which is not claimed.

## What this changes about B63's status

B63 is no longer "pass, historically". Its eviction, oversized-object and key-
identity behavior are now measured against the production implementation, in a
test that runs in under a second with no GPU and no model.

```ini
B63_IMPLEMENTATION_PRESENT=YES
B63_GATE=PASS
B63_RECERTIFICATION=COMPLETE
B63_CURRENT_NORMAL_PATH=DORMANT   (unchanged — still no model routes here)
```

Dormant remains accurate. The cache is the fallback for quant types outside
`{8, 10, 11, 12, 14}`, and those exist, but no model currently on disk exercises
it in production. What changed is that the subsystem is certified regardless.

## Note on commit separation

Per the standing caution, these receipts certify only what they tested. The B70
extraction is a refactor of live code (`Deep2Engine_GpuForward.cpp`) and its
evidence is the engine rebuild plus the parity run above. It does not certify any
other dirty-tree change.

```ini
B70_COMMITTED=NO
B70_PUSHED=NO
```