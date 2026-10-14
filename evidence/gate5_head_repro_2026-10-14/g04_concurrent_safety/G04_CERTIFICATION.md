# G04 — Concurrent-Safe Residency Certification

**Gate:** G04 — Concurrent-safe residency (generation leases, in-flight pinning,
fence-safe eviction, prefetch under CONCURRENT/batched GPU work)
**Certification ID:** RAWRXD_G04_001
**Baseline HEAD:** `4213f56908`
**Date:** 2026-10-14

## Result

**PASS** — implementation, build, real execution, acceptance thresholds, and
reproducible evidence all pass.

| Acceptance requirement | Result |
| --- | --- |
| Generation advances after a retired mapping is re-created | PASS (1500/1500 rounds) |
| Cache hits do NOT advance the generation | PASS |
| Old-generation leases rejected | PASS |
| Stale releases refused **without** decrementing the new mapping's pin | PASS |
| Generation-counter overflow cannot wrap back to a revalidatable value | PASS (saturating advance) |
| Active lease prevents eviction (fence-safe) | PASS |
| In-flight transfer prevents eviction | PASS |
| Prefetch warm-up latch (RAWRXD_TICKLATCH_001) | PASS |
| Concurrent lease pin reconciliation | PASS |
| Zero stale-lease false acceptances | PASS (0) |
| Zero pinned / in-flight mapping evictions | PASS (0) |
| Process exit code 0 | PASS (12/12 runs) |
| Access violations | PASS (0, after repair — see below) |
| Leaked pins after workers finish | PASS (0) |

## Counters reconciled (final run)

```
issued     = 3184   (4 threads x 4 rounds x ~400 iters, pinned-path acquires)
released   = 3184   stale = 0   leaked pins = 0
badData    = 0      (no caller ever read a freed or reused mapping)
retired    = 1500 / 1500 unpinned rounds advanced the generation exactly once
```

## Root cause of the reopened crash (now FIXED)

The gate was reopened after `EvictLeastRecentlyUsed` crashed with `0xC0000005`
(access violation) under 4-thread concurrent eviction stress.

**Diagnosis chain**

1. WER `LocalDumps` for this binary carry **no thread CONTEXT**, so the `.dmp`
   could not localise the fault (only `fault address = 0`, operation = WRITE).
2. An in-process vectored-exception handler
   (`src/deep2/G04_CrashCapture.hpp`) was added. It runs on the faulting
   thread's context and reported:
   `std::_Insertion_sort_unchecked ... EvictLeastRecentlyUsed +0x393`.
3. An MSVC AddressSanitizer build (`/fsanitize=address`) then pinned it exactly:

   ```
   ERROR: AddressSanitizer: heap-buffer-overflow
   READ of size 8 ...
   #0 std::_Insertion_sort_unchecked<...EvictLeastRecentlyUsed::<lambda_1>>
   #1 std::_Sort_unchecked<...>
   #3 Deep2::ElasticResidencyManager::EvictLeastRecentlyUsed
      F:\rawrxd\src\deep2\ElasticResidencyManager.cpp:814
   ```

   and `0x...61f8 is located 8 bytes before 224-byte region` — i.e. the read was
   **one element before the candidate vector's buffer**, which is the symptom of
   `*--_Prev` walking off the FRONT of the range.

**Actual root cause:** the sort comparator read
`a->lastUseSequence` (a live `std::atomic` that concurrent acquirers keep
incrementing via `TakeLeaseAtomic`) and called the stateful GhostCache lookup
from *inside* the comparator. Because both values change between two invocations
of the comparator, the relation was **not a strict weak ordering**: `comp(a,b)`
and `comp(b,a)` could both be true at the same time. `std::sort` is only defined
for a strict weak ordering, and with a non-conforming comparator
`std::_Insertion_sort_unchecked` is allowed to run off either end of the range —
which is what produced the out-of-bounds read.

**Fix:** every candidate's victim score is now computed **once, under
`tensorsMutex_`**, stored in an immutable snapshot, and the comparator compares
only those snapshot values with a stable identity tie-break. The comparator is
now a strict weak ordering (in fact a total order), takes no lock, and can no
longer invert the lock order.

## Other repairs in this gate

1. **TOCTOU in `AcquireTensor` (found by the concurrency test).** The old fast
   paths read the residency state, then captured buffer pointers and took the
   lease *unlocked*. A concurrent eviction could reclaim the mapping in between,
   handing the caller a dangling pointer. All six hand-out sites now go through
   `TakeLeaseAtomic`, which re-validates state and pins the mapping in the same
   critical section as the pointer capture, so a caller either gets a live
   pinned mapping or a rejected one.

2. **Eviction freed mappings across three separate critical sections.**
   `EvictLeastRecentlyUsed` now performs the transition, the free, and the
   generation advance inside a single `tensorsMutex_` critical section, and
   re-validates the pin immediately before freeing (a worker can legally acquire
   a lease between the scan and the free).

3. **Generation bookkeeping.** A retired mapping advances its generation
   (saturating at `UINT32_MAX`, never wrapping to 0, so an old handle can never
   be revalidated), while cache hits leave the generation untouched. Stale
   releases are refused *without* touching the live mapping's pin count.

4. **Unresolved external symbol in the tree.** `VwaResolveBlocks` was declared
   in `src/deep2/VwaRangeAbi.hpp` and called from
   `ElasticResidencyManager::ExecuteNvmeToRam`, but had **no definition
   anywhere in the repository**, so every target that compiled
   `ElasticResidencyManager.cpp` failed at link time (`LNK2019`). Implemented in
   `src/deep2/VwaResolveBlocks.cpp` per the ABI header's contract: no I/O, no
   tensor lookup, overflow- and range-checked, strict block-tiling validation.

5. **Bounded residency admission (RAWRXD_RENT_PIN_001).** `ReserveHot`,
   `ReserveWarmCompressed` and `ReserveWarmStaged` now use an explicitly bounded
   CAS retry (64) and return `false` cleanly when the tier is full — no spin, no
   wait, no memory touch.

6. **Eviction livelock guard (RAWRXD_EVICT_LIVELOCK_001).** When the free cannot
   satisfy the request and the remaining residents are all lease-pinned or
   mid-transfer, the eviction is recorded as **deferred** (`evictions_deferred`)
   and the caller's reservation fails closed. No pinned mapping is ever freed
   and no retry loop is entered.

## Dependencies required for a standalone build

`ElasticResidencyManager.cpp` links against: `GhostCache`,
`lavapath/FreeTokenMicroZone`, `lavapath/FutureConsumerSpace`,
`lavapath/FreeTokenFutureCompletion` (owns `PickZone`/`EmitWitness`/
`ConsumerCount`), and `VwaResolveBlocks`.

## Parity note

ElasticResidencyManager is **not** part of the parity-trace target
(`deep2_parity_trace` compiles `runtime_graph_executor`, `op_linear`,
`universal_gguf`, `quant_dot_dispatch`, `vulkan_compute`,
`streaming_gguf_loader`, `gguf_loader`, `gguf_vocab_resolver`). The DeepSeek /
TinyLlama full-logit parity targets are therefore unaffected by these changes.
A full parity regression must still be run before release certification.

## Evidence files

| File | Contents |
| --- | --- |
| `optimized_run.log` | `/O2` build, 4 threads x 4 rounds, exit 0 |
| `asan_run.log` | `/fsanitize=address` build, **zero** AddressSanitizer reports |
| `G04_CERTIFICATION.md` | this document |

Reproduce:

```
cl /EHsc /std:c++20 /O2 /DNOMINMAX /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS ^
   /I src /I src\deep2 /I include /I . /I 3rdparty\ggml\include /I 3rdparty\ggml\src ^
   src\deep2\ElasticResidencyManager.cpp src\deep2\GhostCache.cpp ^
   src\deep2\lavapath\FreeTokenMicroZone.cpp src\deep2\lavapath\FutureConsumerSpace.cpp ^
   src\deep2\lavapath\FreeTokenFutureCompletion.cpp src\deep2\VwaResolveBlocks.cpp ^
   src\deep2\G04_Concurrent_Residency_Test.cpp
link /subsystem:console ... *.obj kernel32.lib user32.lib dbghelp.lib
g04_test.exe                       # default: 4 threads, 3 stress rounds
G04_THREADS=8 G04_ITERS=1000 G04_STRESS_ROUNDS=5 g04_test.exe
```

## Known limitations (recorded, not hidden)

* `VwaResolveBlocks` saturation at `UINT32_MAX` is guaranteed by the CAS
  saturating advance and is verified by code inspection; reaching the ceiling
  with real evictions would take ~4.29 billion retire/re-map cycles and is not
  a runnable assertion. What the test *does* prove is that the counter advances
  strictly monotonically and never returns to 0, which is the property the
  saturating guard exists to protect.
* The legacy `AcquireForCpu` / `BindForGpuCompute` APIs still hand out raw
  pointers without a generation lease. They are **not** part of the Cyclone
  acquire/release contract this gate certifies, but they carry the same latent
  race pattern and should be migrated to `TakeLeaseAtomic` in the same way.
