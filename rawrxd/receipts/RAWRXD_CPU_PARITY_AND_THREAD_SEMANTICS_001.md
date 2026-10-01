# RAWRXD_CPU_PARITY_AND_THREAD_SEMANTICS_001

Status: PASS (as a parity/semantics gate only)
Date: 2026-10-01
Scope: benchmark-local CPU path (`rawrxd::TransformerRuntime`, `rawrxd::cpu::*`) and the
new CPU K-quant GEMV header. **This receipt does not certify production inference.**
Host: AMD Ryzen 7 7800X3D, Zen 4, 16 logical CPUs, AVX-512F/DQ/BW/VL/VBMI/VNNI.

## Gates admitted

```ini
KQUANT_PARITY_FAILURES=0
KQUANT_PARITY_CHECKS=20
KQUANT_BACKEND=AVX-512F (+FMA)
KQUANT_AVX512_COMPILED=1

CPU_MATH_PARITY_FAILURES=0
CPU_MATH_PARITY_CHECKS=86
CPU_MATH_BACKEND=AVX-512F (+FMA)
CPU_MATH_AVX512F=1
CPU_MATH_AVX2=1
CPU_MATH_FMA=1
CPU_MATH_LOGICAL_CPUS=16

THREAD_SEMANTICS_FAILURES=0
```

`avx512_compiled=1` and `backend=AVX-512F (+FMA)` are load-bearing: they prove the
vectorized paths were exercised, so these are not scalar-fallback passes.

## Canonical thread vocabulary (RAWRXD_B77 / ladder 1-25)

`threads=N` means **N total participants** = (N-1) workers + the calling thread.

```ini
THREADS_1_MEANS=INLINE_CALLER_ONLY
THREADS_2_MEANS=1_WORKER_PLUS_CALLER
EFFECTIVE_PARTICIPANTS=ACTUAL_WORKERS+CALLER_PARTICIPATES
COVERAGE=ROWS_PROCESSED_EXACTLY_ONCE_FOR_REQUESTED_1_2_4_8
OVERSIZED_REQUEST_CLAMPS_TO_WORK=true
```

Verified by `thread_semantics_check.cpp` with a coverage probe (per-row hit counts,
not assertions about intent): every requested value 1/2/4/8 echoes verbatim, has a
distinct worker count, and covers all rows exactly once.

## Defects found and fixed by measurement

| ID | Defect | Observable symptom | Root cause |
|---|---|---|---|
| D1 | Worker-pool chunking deadlock | `[WORKERPOOL] STALL ... pending=4294967295` at `threads=2` | Chunk divided the range across `use` workers instead of `use+1` participants, so the caller took everything and the lone worker got an empty slice it still had to signal completion for |
| D2 | `threads=1` absent from receipts | `GeometryForRequested(1)` returned a zeroed record | Inline path called the tally-free `RecordInlineGeometry(size_t)` instead of `RecordInline(unsigned,size_t)`, and recorded `caller_participates=false` when the caller did all the work |
| D3 | Parallel attention produced wrong output | `argmax_match=0` at depth 1024, `determinism=0` at 4T | Concurrent heads shared one `scores` buffer and one `vsum` scratch; each head overwrote another's softmax input. Fixed with per-head slices (`scores_all`, `vsum_all`) |
| D4 | Cascading decode failures | `REJECTED decode failed` for all threaded configs | KV cache preallocated `max_position_embeddings` (256 MiB per runtime for an 8L/h512 model) regardless of actual depth; ~31.5 GiB of large-block churn across the sweep. Replaced with geometric growth from 256 rows |
| D5 | Q4_K GEMV mis-indexed | 20 parity failures | Upper-half minimums read `s[0..3]` instead of ggml's `s[4..7]` (`get_scale_min_k4` uses `q[j-0]`); AVX-512 path also selected one group scale for both 16-lane chunks. Rewritten around the group rule: group `g` = nibble parity `g&1` of bytes `qs[(g/2)*32]` |

## Test-harness defects fixed (these mattered)

- **Accumulation contract was untested.** `kquant_parity_check` called the kernel once
  into each of two fresh buffers and compared `acc` to `acc`, so it could never detect a
  `y[r] = acc` bug. Corrected to two calls into the *same* buffer; now measures
  `y1=120.507385 y2=241.014771 delta=0`.
- **Poisoned fixtures.** Random bytes were used as fp16 scale fields; fp16 exponent
  `0x1F` is Inf/NaN, which poisoned every accumulator and failed comparisons for reasons
  unrelated to the kernel. Scales are now well-formed finite values.
- **Pure relative error masked a real bug and then manufactured a fake one.** Dot products
  of oscillatory vectors legitimately approach zero, so relative error explodes on correct
  kernels while hiding a real indexing error. Switched to mixed abs/rel tolerance, and kept
  `double` accumulation in the independent reference.

## Evidence boundary — what this receipt does NOT establish

```ini
PRODUCTION_DEEP2_PATH=NOT_CERTIFIED_BY_THIS_RECEIPT
REGIME_SWEEP_REACHES_DEEP2=NO
KQUANT_GEMV_REGISTERED_IN_PRODUCTION=PENDING_VERIFICATION
REAL_Q4_K_INFERENCE=OPEN
RAWRXD_Q4K_GEMV_PARITY_001=OPEN
```

**Correction issued after audit.** An earlier draft of this receipt asserted the CPU path
was "benchmark-local and NOT wired into production." That is wrong and is retracted here.
`src/cpu_inference_engine.cpp:16` holds a `rawrxd::TransformerRuntime` as a member of
`CPUInferenceEngine::Impl` and calls `transformer_.Forward` at `:92`, `:122`, and `:160`
inside `GenerateStreaming`; `CMakeLists.txt:2260-2265` compiles all three TUs into the top
level `set(SOURCES)`. The path is compiled into shipped targets and executed by a
production-shaped engine. Whether the IDE chat path reaches it at runtime was not traced
and remains open.

`regime_sweep.cpp` itself still measures only this path — it includes
`rawrxd_transformer.hpp` and calls `TransformerRuntime::Forward` directly, so it never
exercises Deep2 dispatch. The distinction that matters is **which engine dispatches the
kernels**, not whether the TU is in a binary. `production_regime_sweep.cpp` is the harness
that drives `Deep2Engine` and is the correct instrument for production questions.

`kquant_parity_check.cpp` calls the same `k_quant_gemv_avx512.h` kernel Deep2 uses, but
directly rather than through the engine, so it certifies the kernel and not Deep2's
dispatch of it.

## Superseded decoder — P0 found by audit

An audit of this path found a **P0 correctness defect in `src/gguf_loader.cpp`'s Q4_K
decoder**, which is the decoder the inference path actually calls
(`LoadAllWeights` -> `GGUFTensorView::ToFloat32`). It wrote `out[j]` from the low nibble
of `qs[j]` and `out[j+128]` from its high nibble, which is a different permutation from
ggml's rule that weight group `g` is nibble parity `g&1` of bytes `qs[(g/2)*32]`. That
scrambled **7 of the 8** weight groups, so every Q4_K weight matrix decoded through this
function was garbage. It has been rewritten to the correct group rule, and a cross-check
was added to `kquant_parity_check.cpp` that decodes the same synthetic super-block through
both the loader and an independent reference.

The same audit found the two Q4_K decoders disagreed and that the GEMV parity harness
**could not have caught it**, because `RefGemvQ4K` is a local reference and never touches
`gguf_loader`. The cross-check closes that gap; it is the highest-value addition to the
harness set and should not be removed as redundant with the GEMV test.

## Supersession

`production_regime_sweep.cpp` (drives `Deep2Engine`, links `InferenceEngine`) is the only
harness measuring the path `rawrxd.exe` actually runs, and it had **no receipt** and the
weakest gate of the set (no argmax oracle). It is the highest-value next target: add a
greedy-output oracle and write `RAWRXD_PRODUCTION_REGIME_SWEEP_001`.
