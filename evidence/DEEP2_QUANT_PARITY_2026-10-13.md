# RawrXD / Deep2 — Quantized Kernel Parity and Capability Manifest Evidence

Date: 2026-10-13
Repository: `F:\rawrxd`
Branch: `local-30b-backend`

This ledger records work I performed and verified in this session. Every result
below is tied to a command I actually ran, or to a source line I actually read.
Nothing here is reproduced from an external report.

---

## 1. Immutable verification targets (vendored reference)

All parity comparisons in this session compare Deep2 against the llama.cpp
source that is vendored inside this repository, not against a captured
snapshot. That is what makes the gate permanent: if either side drifts, the gate
fails.

| Reference function | Location read |
| ------------------ | ------------- |
| `quantize_row_q8_K_ref` | `3rdparty/ggml/src/ggml-quants.c:2555` |
| `nearest_int` (round-half-to-even) | `3rdparty/ggml/src/ggml-quants.c:444` |
| `ggml_vec_dot_q4_K_q8_K_generic` | `3rdparty/ggml/src/ggml-cpu/quants.c:550` |
| `ggml_vec_dot_q6_K_q8_K_generic` | `3rdparty/ggml/src/ggml-cpu/quants.c:705` |

I verified line-for-line that `src/deep2/Q8KQuant.h:QuantizeRowQ8K` matches
`quantize_row_q8_K_ref` on all four load-bearing properties: signed-extremum
scale (`iscale = -127/max`), `d = 1/iscale` stored as FP32 (never FP16),
`MIN(127, v)` clamp, and the 16 block sums over 256 signed values.

---

## 2. Commands run and exit codes

```
# Build the parity gate
cl /nologo /EHsc /std:c++17 /O2 /I F:\rawrxd\src\deep2 ^
   F:\rawrxd\src\deep2\test_kquant_dot_parity.cpp
   /link /OUT:F:\rawrxd\src\deep2\test_kquant_dot_parity.exe
-> exit 0

# Run the parity gate
F:\rawrxd\src\deep2\test_kquant_dot_parity.exe
-> exit 0  (PARITY_STATUS=PASS)

# Compile-check the registry edit in its real include configuration
cl /nologo /EHsc /std:c++17 /O2 /I F:\rawrxd\src\deep2 /I F:\rawrxd\src\deep2\modelgenie ^
   /c F:\rawrxd\src\deep2\QuantParityRegistry.cpp
-> exit 0
```

---

## 3. Gate results

```
=== RawrXD K-quant parity gate (Deep2 vs vendored ggml reference) ===
  [PASS] Q8_K_packing   blocks_tested=32  d_mismatch=0  qs_block_diff=0
                        qs_value_diff=0  bsum_block_diff=0  bsum_value_diff=0
                        identical=32
  [PASS] Q4K_dot_Q8K    blocks=8  worst_abs=0  worst_rel=0  tolerance=1e-05
  [PASS] Q6K_dot_Q8K    blocks=8  worst_abs=5.36e-07  worst_rel=5.36e-07
                        tolerance=1e-05
=== VERDICT: PASS (0 failure(s)) ===
PARITY_STATUS=PASS
```

| Gate | Result | Note |
| ---- | ------ | ---- |
| Q8_K activation packing | PASS | 32 blocks byte-identical (d bits, 256 qs, 16 bsums each) |
| Q4_K x Q8_K dot | PASS | exact match, 0 error |
| Q6_K x Q8_K dot | PASS | 5.36e-07 relative, from float summation order only |

Q8_K packing was tested over 4 repetitions = 32 blocks, including a
halfway-tying activation set that exercises ggml's round-half-to-even
`nearest_int` — the exact case where `std::lround` diverged.

---

## 4. Defect found and fixed: Q4_K dispatch was silently zeroing output

**Before:** `src/deep2/QuantKernelRegistry_K.h:vec_dot_kquant` had no
`QTYPE_Q4_K` case, so Q4_K fell through to `default: return 0.0f`. Every Q4_K
GEMV returned zero without any error, which is the most dangerous failure
shape: silent, not fail-closed.

**After:** added `vec_dot_q4_K_q8_K_single` mirroring
`ggml_vec_dot_q4_K_q8_K_generic`, and bound `QTYPE_Q4_K` in the dispatch.

Two details were required for parity, both verified against the reference:

1. **The bsums correction term.** ggml subtracts `dmin * sumi` where
   `sumi = sum_j bsums[j] * mins[j/2]`. Correct Q8_K block sums are therefore a
   prerequisite for Q4_K parity, not a nicety. This is precisely why the Q8_K
   packing fix unblocks the Q4_K dot.
2. **Scale/min extraction** uses ggml's `get_scale_min_k4` packing, which I
   verified is bit-equivalent to ggml's `utmp`/`kmask` decoding of the 12 scale
   bytes (scales[d]=utmp bytes 0-7, mins[m]=utmp bytes 8-15).

I also verified Deep2's existing `vec_dot_q6_K_q8_K_single` scale indexing
against ggml: for a value at aux8 index `e`, Deep2 computes `is = base/16` where
`base = 128*ip + il`, which equals `e/16` = ggml's `scales[e/16]`. Confirmed
correct across all four nibble groups and both 128-element halves.

**Scope note:** this closes the *kernel*. Full-forward Q4_K parity (layer
residuals, logits, argmax) remains unverified and is not claimed here.

---

## 5. Defect found and fixed: stale capability manifest

`src/deep2/QuantParityRegistry.cpp` emitted `"primitive": "mla_decompress"` and
`"note": "ModelGenieExecutor.cpp:1917"` **for every primitive** in the
`primitive_gates` array. An unimplemented primitive was therefore described
using an implemented primitive's provenance, and the manifest looked healthy
regardless of the actual gates. A manifest that cannot identify the primitive
it reports is not evidence.

**After:** added `PrimitiveName(p)` and `PrimitiveBindingNote(p)` as the single
source of truth, and the emitter now derives both from the primitive being
reported. A `binding_status` field was added that distinguishes
`bound` / `declared_unimplemented` / `not_required`.

Two stale comments were also corrected in `src/deep2/modelgenie/ModelGenome.hpp`:
`MlaDecompress // REQUIRED primitive missing` and
`MlaDecompressFwd // FIRST_UNIMPLEMENTED_PRIMITIVE`. MLA is implemented and
bound (dispatched in `ModelGenieExecutor.cpp`), so both comments were wrong.

---

## 6. MatMul -> Linear lowering: verified, not assumed

The concern was that `Universal::Op::MatMul` is lowered onto `OpKind::Linear`,
which might silently execute a projection where a matmul was requested.

Evidence gathered:

| Check | Result |
| ----- | ------ |
| Sites emitting `Op::Linear` in graph producers | 11 (all in `universal_gguf.cpp`) |
| Sites emitting `Op::MatMul` anywhere in `src/` | **0** |
| `MatMul` present in generated ExecutionIR/ModelGenome headers | No (declaration only) |
| Does `OpLinear` fail closed on a non-weight operand? | Yes — `OpLinear:641` returns false on `wslot < 0` |
| Does the line-478 optimization touch MatMul? | No — it requires `op == OpKind::Linear && b >= 0` |

Conclusion: the alias was **unreachable**, so it was not causing incorrect
arithmetic today. But the two operator contracts are genuinely different —
`Linear` is a weight-backed GGUF projection whose `b` operand must resolve to a
ROM weight slot; `MatMul` is a general tensor x tensor product with arbitrary
stride, transpose and broadcast rules. Folding one into the other is a latent
hazard: a future producer could silently compute a projection.

**After:** the lowering now routes `Universal::Op::MatMul` to
`OpKind::Unsupported`, which the bind step converts into an explicit
"unimplemented operators" error and refuses to run. The evidence for this
decision is recorded in the comment at the lowering site so the next reader
does not have to re-derive it.

---

## 7. Permanent regression coverage registered

`CMakeLists.txt` now builds and runs a new gate alongside the existing ones:

```
add_test(NAME kquant_dot_parity COMMAND kquant_dot_parity)
```

joined by the existing `q8k_byte_parity`, `q8k_edge_tests` and
`quant_parity_cert` tests. The new gate covers Q8_K packing plus both Q4_K and
Q6_K dot products against the vendored reference.

---

## 8. What remains open (explicitly not claimed)

I did not verify these, and nothing in this ledger should be read as evidence
that they pass:

- Full-forward Deep2 parity: layer residuals, attention, FFN, logits, argmax,
  and the first-divergence trace.
- The 67-position reference battery on the corrected Q8_K path.
- Multi-token autoregressive parity with KV reuse.
- MatMulFwd's own implementation. `ModelGenieExecutor.cpp` still returns false
  for that primitive. I deliberately did **not** implement it, because no graph
  producer emits it, so an implementation would be unexercised code rather than
  a closed gap. It is reported honestly as `declared_unimplemented`.
- GPU/CPU numerical equivalence and any GPU-only execution claim.
- Full CMake build. I compile-checked individual translation units with the
  include configuration from `CMakeLists.txt:3137-3141`; I did not run a full
  CMake configure+build, nor resolve the long-path checkout failure.
- `ModelGenieEx`, `RawrXD_ParityDrop` and the 134-tool registry were not
  audited this session.

## 9. Minor observation

`src/deep2/QuantParityRegistry.h:36` includes `"../modelgenie/ModelGenome.hpp"`,
while every sibling (15 files) uses plain `"ModelGenome.hpp"`. It compiles only
because `CMakeLists.txt:3140` puts `src/deep2/modelgenie` on the include path.
It is consistent but inconsistent in style; worth normalising, not broken.
