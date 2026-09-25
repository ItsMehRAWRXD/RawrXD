# RawrXD speculative special-graph source drop

Dependency-free C++20 source layer for Deep2 speculative decoding.

## Batches in this drop

1. **SG-01 — Special graph IR**
   - Dense native graph nodes/edges.
   - Deterministic condition routing.
   - Reachability/required-stage validation.
   - Iterative decode cycles are legal by design.

2. **SG-02 — Adaptive speculative batch planner**
   - Draft width min/max/warmup policy.
   - Acceptance EMA.
   - Automatic width grow/shrink.
   - Teacher-forced target/draft comparison.

3. **SG-03 — Transactional executor**
   - Draft → verify → accept → rollback/commit graph.
   - Prefix checkpoint callback.
   - KV rollback and commit hooks.
   - Strict verify underflow handling.
   - Exact token budget enforcement.
   - Stats suitable for certification receipts.

4. **SG-04 — Deep2 adapter state + self-test**
   - Backend-neutral callback ABI.
   - No dependency on llama.cpp/Ollama/Boost/TBB/etc.
   - Deep2 checkpoint/rollback/commit state helper.
   - Standalone deterministic self-test.

## Integration into RawrXD

Add these three `.cpp` files to the existing `RawrXD-Win32IDE` / Deep2 target:

- `SpecialGraph.cpp`
- `SpeculativeBatch.cpp`
- `SpeculativeExecutor.cpp`

Include:

```cpp
#include "deep2/speculative/SpeculativeExecutor.hpp"
```

Wire the callbacks to the existing Deep2 paths:

- `draft` -> small/fast model decode path or reduced-layer draft path.
- `verify` -> target model batched teacher-forced decode.
- `checkpoint` -> capture KV cursor/page-table generation.
- `rollback` -> restore KV cursor and invalidate speculative pages after prefix.
- `commit` -> seal accepted/replacement tokens into live KV state.

The executor itself never touches Vulkan or CPU tensor kernels. That separation is intentional: the existing strict GPU authority remains the authority for where tensor work executes.

## Important correctness rule

The `verify` callback must return the target model's selected token for every proposed position. This drop implements **greedy speculative acceptance**. Sampling-distribution speculative decoding requires a probability-correct acceptance/rejection rule and is deliberately not faked here.

## Build self-test

```powershell
cmake -S . -B build
cmake --build build --config Release
.\build\Release\rawrxd_speculative_selftest.exe
```

Expected final line:

```text
VERDICT=PASS
```

## Additional implemented batches

5. **SG-05 — KV transaction authority**
   - Backend-owned snapshot/capture/restore/seal ABI.
   - Transaction cannot silently commit or rollback without authority.

6. **SG-06 — Verify batch packing**
   - Contiguous token and position vectors for teacher-forced target verification.
   - 32-bit position overflow checks.

7. **SG-07 — Draft route policy**
   - Native decision between same-model early exit and secondary draft model.
   - Acceptance floor and measured latency switch ratio.

8. **SG-08 — Acceptance oracle + GPU command shape**
   - Exact CPU reference oracle for parity.
   - POD command descriptor suitable for translation into the existing Vulkan authority.
   - This layer intentionally does not fake a GPU dispatch.

9. **SG-09 — Dual-GPU overlap planner**
   - Same-device path when possible.
   - Existing RawrXD Case-B staged GPU-DMA path when devices are not in one device group.
   - CPU is not specified as a payload-processing stage.

10. **SG-10 — Strict certification receipt**
    - Requires generated output, parity, verified rollback when used, strict GPU authority, and zero stubs.
    - Emits `RAWRXD_SPECULATIVE_SPECIAL_GRAPH_001`.

## Repo-specific work that still must be wired

The generic source layer is complete, but three integrations require the real RawrXD types and cannot be truthfully fabricated in an isolated drop:

- Map `KvAuthority` to the actual Deep2 KV cursor/page-table structures.
- Map `VerifyBatchView` to the existing Vulkan batched forward dispatch.
- Translate `AcceptanceScanCommand` into the existing Vulkan buffer/compute command path if GPU-resident acceptance is desired.

Those are wiring tasks, not missing speculative-control algorithms.
