# RAWRXD_Q6K_GEMV_PARITY_001

Status: **PASS — admitted** (CPU half)
Date: 2026-10-30
Harness: `real_q6k_gemv_parity.cpp`, `q6k_block_trace.cpp`, `q6k_row_decisive.cpp`
Model: `F:/~dev/qwen2.5-coder-1.5b-base.gguf` (29 Q6_K tensors)

```ini
Q6K_TENSOR_COUNT      = 29
Q1_GEOMETRY_REJECTED  = 0
Q8_TENSORS_PASS       = 29
Q8_TENSORS_FAIL       = 0
Q8_TENSORS_INVALID    = 0
Q6_WORST_REL_MAX_DIFF = 1.74002748e-05
Q6_WORST_COSINE       = 0.999999999998
Q6_WORST_TENSOR       = blk.7.ffn_down.weight
Q10_NEGATIVE_CONTROL  = DEFECT_DETECTED
GATE_STATUS           = PASS
```

## The two real defects (both in the new kernel, both found by measurement)

**D1 — scalar `GemvQ6K` reused the same activations for every block.**

```cpp
acc += (d * s[is + 0]) * q1 * x[half * 128 + l];   // missing b * 256
```

With 6 blocks per row, blocks 1..5 all read `x[0..255]` instead of
`x[256..1535]`, applying the first 256 activations six times. This is the
entire `0.605` discrepancy. Fixed by hoisting `const float* xb = x + b * kQK;`
— the same structure the Q4_K kernel already used.

**D2 — AVX-512 masked the 2-bit-packed `qh` field with `0x0F` instead of `0x03`.**

`qh` holds four 2-bit fields per byte, so `(h >> 2) & 0x0F` pulled four bits
where the field is two, leaking the neighbouring field into every result.
That is the `85.6x` error. Fixed with a dedicated `m03` mask; the low-nibble
`ql` path correctly keeps `m0F`.

Neither defect was visible from geometry, density, element counts, or block size.
Both produced structurally perfect metadata with wrong values.

## Proof the production path was never at fault

`q6k_block_trace.cpp` traced block 0 of `token_embd.weight` with a snapshot
taken before any decode, and compared four executions:

```ini
QK_K=256 BLOCK_BYTES=210
OFFSETOF_ql=0 OFFSETOF_qh=128 OFFSETOF_scales=192 OFFSETOF_d=208
LAYOUT_MATCHES_KERNEL_ASSUMPTION=1
LIVE_EQUALS_SNAPSHOT_BYTES=1     LIVE_BLOCK_MUTATED=0

A  direct from live pointer   = -0.00743508339
B  direct from 210B snapshot  = -0.00743508339
C_local transcribed algorithm = -0.00743508339
C  production ToFloat32[0]    = -0.00743508339
FIRST_DIFFERENCE = NONE
```

`gguf_loader::ToFloat32` agreed bit-for-bit with an independent decode under
mutation checks, and both matched the pinned upstream `dequantize_row_q6_K`
line for line. The earlier `2x` at element 0 was an **fp16 subnormal error in a
throwaway probe** (`ldexp(m, -24)` instead of the generic normalization),
not in any shipped decoder.

## Registration

`QuantKernelRegistry.cpp` now selects the fused kernel under the same
capability gate as Q4_K:

```cpp
if (hasAVX512) RegisterGEMV(GGML_TYPE_Q6_K, gemv_q6_k_avx512_kernel);
else          RegisterGEMV(GGML_TYPE_Q6_K, gemv_q6_k_scalar);
```

Verified to compile **clean at both `/arch:AVX512` and `/arch:AVX2`**, so the
`#else` scalar fallback is intact for hosts without AVX-512.

## No regression

```ini
Q4_K_SWEEP            = 168 PASS / 0 FAIL / 0 INVALID / 0 geometry rejected
KQUANT_PARITY         = RESULT PASS (0 failures)
MATH_PARITY           = RESULT PASS (0 failures)
Q6_K_SWEEP            = 29 PASS / 0 FAIL
```

## Rules this produced

```ini
REGRESSION_SUITE_MUST_RUN_AFTER_EVERY_KERNEL_FIX
KERNEL_CHANGE_REQUIRES_FULL_SWEEP_ON_REAL_MODEL
A_2X_ERROR_IS_AN_EXPONENT_BUG_NOT_A_GEOMETRY_BUG
NEGATIVE_CONTROL_MUST_KEEP_FIRING_AFTER_ADMISSION
SNAPSHOT_BEFORE_COMPARE  # removes aliasing before inspecting any field
```

## Measured throughput (real model, gate passed first)

`kquant_bench.cpp`, 3 repetitions per kernel, timing only after the cosine gate:

```ini
Q4_K  tensors=168  rows=620032  cols=361984  4.500 bits/elem
      scalar 1021.323 ms   439.51 GFLOP/s
      avx512  208.081 ms  2157.26 GFLOP/s   speedup 4.91x

Q6_K  tensors= 29  rows=177024  cols=148480  6.562 bits/elem
      scalar  560.057 ms    93.86 GFLOP/s
      avx512   55.780 ms   942.43 GFLOP/s   speedup 10.04x
```

Q6_K gains more than Q4_K because its scalar reference was the weaker baseline
(four interleaved groups per half and a 2-bit packed `qh` field), so more of its
cost was scalar arithmetic rather than memory.

Full CPU decode work for this model, i.e. every projection in every layer, now
runs on admitted vector kernels for both quantized types: **~2.1 TFLOP/s** of
GEMV throughput, up from ~440 GFLOP/s.

## Q5_K — added, scalar admitted, vector withheld

The bundled model contains **only** F32(141), Q4_K(168) and Q6_K(29). There are
no Q5_K tensors, so a Q5_K fused kernel could not be proven on real weights here.
It was written from upstream `dequantize_row_q5_K` (`ggml-quants.c:1731`) and
proven **synthetically** against an independent transcription of that routine,
across cols {256,768,2048} x rows {1,5}:

```ini
Q5_K scalar   PASS (6/6)
Q5_K dispatch PASS (6/6)
Q5_K avx512   WITHHELD - does not reproduce the scalar reference
```

The AVX-512 form is compiled but **not dispatched**
(`RAWRXD_Q5K_VECTOR_WITHHELD_001`). Its relative error ranged 0.43 .. 9.45 against
the same reference the scalar passes, so it is a real defect, not a tolerance
question. Shipping it would have meant registering a kernel that cannot reproduce
its own oracle. The assertion is inverted in the parity harness so the gate
**fails if the vector path ever starts matching**, forcing the disposition to be
revisited deliberately.

## Defects found in this work

| ID | Defect | Symptom | Root cause |
|---|---|---|---|
| D1 | scalar `GemvQ6K` reused activations across blocks | `0.605` on every tensor | missing `b * kQK` term; blocks 1..5 all read `x[0..255]` |
| D2 | AVX-512 `GemvQ6K` masked `qh` with `0x0F` | `85.6x` | `qh` is 2-bit packed; mask must be `0x03`, so 4 bits were pulled where the field is 2 |
| D3 | AVX-512 `GemvQ5K` does not match its scalar reference | rel 0.43 .. 9.45 | not yet localized; withheld rather than shipped |

## Verification status

```ini
kquant_parity  RESULT PASS (0 failures)   # Q4_K, Q6_K, Q5_K synthetic
math_parity    RESULT PASS (0 failures)   # CPU kernels, 86 checks
q4k_sweep      168 PASS / 0 FAIL / 0 INVALID / 0 geometry rejected
q6k_sweep       29 PASS / 0 FAIL / 0 INVALID, negative control DETECTED
registry builds: /arch:AVX512 clean, /arch:AVX2 clean
```

## Not claimed

- No GPU result. The device path remains unexecuted (`GPU_HALF=INVALID`).
- No full-model inference result; layers, KV cache, attention and sampling are
  untested end to end.
- Q5_K has no real-model evidence because this model has no Q5_K tensors.
- `block_q6_K` / `block_q5_K` were not transcribed from upstream headers; the
  live layouts are bound from the compiled types and match every offset the code
  assumes.

## Result

```ini
Q6K_TENSOR_COUNT=29
Q1_GEOMETRY_REJECTED=0        geometry is sound
Q8_TENSORS_PASS=0
Q8_TENSORS_FAIL=29
Q8_TENSORS_INVALID=0
Q10_NEGATIVE_CONTROL=DEFECT_DETECTED   gate is discriminating
GATE_STATUS=FAIL
```

The gate does not admit Q6_K. It is recorded as FAIL rather than worked around.

## Finding 1 — AVX-512 Q6_K withdrawn (resolved by removal)

An AVX-512 fused Q6_K GEMV was written. On a single synthetic 210-byte block:

```ini
reference        = 720.736782
scalar GemvQ6K   = 720.736816   ratio 1.000000048   correct
AVX-512          = 61702.3125   ratio 85.610        wrong
```

**Cause.** `qh` packs **two bits per weight with four weights per byte**, so
lanes *l* and *l+1* take their 2-bit fields from different bit positions of the
*same* `qh` byte. Loading `qh` lane-wise and masking with `0x0F` extracts the wrong
field for three of every four lanes. A correct vector path must first expand
64 two-bit fields out of 16 bytes; AVX512-VBMI `_mm512_multishift_epi64_epi8`
produces exactly that expansion, and this host reports `VBMI=1`.

**Disposition: the optimized path is withheld, not shipped.** `GemvQ6KDispatch`
now calls the scalar, which is both the production path and the retained oracle.
Shipping a plausible-but-85x-wrong kernel is precisely the failure mode this
exercise exists to prevent, and the negative control is what caught it.

## Finding 2 — residual disagreement, cause NOT yet established

With AVX-512 withdrawn, `GemvQ6KDispatch` and the scalar oracle are bit-identical
(`rel=0`, `cosine=1.0`), yet the sweep still fails because the GEMV result
disagrees with decode-then-dot via `gguf_loader::ToFloat32`:

```ini
scalar GemvQ6K   vs hand-verified block reference : ratio 1.000000048   PASS
scalar GemvQ6K   vs gguf_loader ToFloat32 + dot   : refrow 0.605        FAIL
```

**I have not established which side is wrong, and I am not going to guess.**

Two candidates remain, and they are not equally likely:

- **(a) a genuine decoder disagreement** — one of the two decoders scrambles a
  nibble or scale field. If `gguf_loader` is the wrong one, inference is
  currently materializing corrupted Q6_K weights for 29 tensors, because
  `LoadAllWeights` reaches Q6_K through `GGUFTensorView::ToFloat32`.
- **(b) a row/column convention mismatch on non-square tensors.** The Q4_K sweep
  used `1536x1536` tensors, which are square, so a transposed interpretation is
  invisible there. The same sweep geometry for `token_embd.weight` produced
  `151936 * (1536/256) * 210 = 191439360`, exactly the reported byte size, which
  established `cols = shape[0]` for that tensor. Whether that convention holds
  for every Q6_K tensor in the file was **not** independently verified, and the
  printed shape `1536x8960` for `ffn_down` is consistent with a transposed
  reading.

A 0.605 relative error is far too large for float drift and too small for
random corruption, which favours (b): a mis-strided but internally consistent
read. But that is an inference from magnitude, not a measurement, and it is not
enough to close the gate.

**Decisive test, not yet run:** for one Q6_K tensor, decode a single row by both
paths and compare element by element, printing the first divergent index. If the
two decoders agree element-wise and only the *dot products* differ, the defect is
the row convention (b). If they diverge element-wise, it is a decoder (a).

## Why this is not a small discrepancy

A 0.605 relative error is not float drift. It is the signature of a scrambled
nibble or scale field — the same defect class as
`RAWRXD_Q4K_NIBBLE_MAP_001`, which was also invisible to structural checks:
geometry, density, and element counts all reconcile perfectly while the values
are wrong. It was caught only because two independent decoders were compared.

That is the second time in this session that a Q-K decoder looked structurally
perfect and was numerically wrong. It argues that the whole Q-K decode surface
should be gated by cross-decoder differential tests rather than by geometry.

## Resolution — Outcome B: decoded rows match; defect is geometry

An authoritative upstream reference was pinned and compared field by field:

```ini
REFERENCE_SOURCE    = ggml-org/llama.cpp, ggml/src/ggml-quants.c (master)
REFERENCE_FUNCTION  = dequantize_row_q6_K          line 1939
PRODUCTION_FUNCTION = rawrxd GGUFTensorView::ToFloat32 -> DequantQ6_K
CANDIDATE           = rawrxd::kquant::GemvQ6K
SHARED_IMPLEMENTATION = NO
```

Upstream, verbatim:

```c
for (int n = 0; n < QK_K; n += 128) {
    for (int l = 0; l < 32; ++l) {
        int is = l/16;
        const int8_t q1 = (int8_t)((ql[l +  0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
        const int8_t q2 = (int8_t)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
        const int8_t q3 = (int8_t)((ql[l +  0]  >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
        const int8_t q4 = (int8_t)((ql[l + 32]  >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
        y[l +  0] = d * sc[is + 0] * q1;
        y[l + 32] = d * sc[is + 2] * q2;
        y[l + 64] = d * sc[is + 4] * q3;
        y[l + 96] = d * sc[is + 6] * q4;
    }
    y += 128; ql += 64; qh += 32; sc += 8;
}
```

Both in-tree decoders match this **line for line** — identical index arithmetic
(`ql[l]`, `ql[l+32]`, low/high nibble split), identical scale pattern
(`sc[is + {0,2,4,6}]` with `is = l/16`, plain `int8_t` scales, **not**
`get_scale_min_k4`), and identical pointer advances (`+128/64/32/8`).

```ini
DECODE_ELEMENTWISE_MATCH=YES
DOT_FROM_IDENTICAL_ROW=YES
DECODER_VERDICT=EXONERATED
SWEEP_REL_ERROR=0.605  ->  NOT A DECODER DEFECT
```

**The ≈0.605 discrepancy is a geometry/stride problem, not a quantisation
problem.** The candidates are now narrowed to exactly: row selection, tensor
orientation, packed row stride, or logical input/output dimension assignment for
Q6_K tensors.

Relevant upstream fact: `get_scale_min_k4` has eight call sites in
`ggml-quants.c`, **all in the Q4_K path** (lines 1508, 1542, 1544, 1605, 1695,
1746, 1748, 1814) and **none in the Q6_K path**. Neither in-tree implementation
routes Q6_K scales through it, which is correct.

`block_q6_K` and `QK_K` are defined in `ggml-common.h`, not `ggml-quants.c`, and
were deliberately not transcribed from memory. The decode arithmetic is fully
pinned; the struct layout is not formally pinned, though both in-tree
implementations independently agree with upstream on every field offset used.

## Superseding decisive test (RAWRXD_Q6K_ORACLE_BISECT_001) — EXECUTED

`q6k_row_decisive.cpp`: one non-square Q6_K tensor, one row, four values, with
the live layout bound from the compiled type rather than assumed.

```ini
TENSOR=token_embd.weight  ROWS=151936  COLS=1536
BLOCKS_PER_ROW=6  ROW_BYTES=1260  ROW_INDEX=0
QK_K=256  BLOCK_BYTES=210
OFFSETOF_ql=0  OFFSETOF_qh=128  OFFSETOF_scales=192  OFFSETOF_d=208
LAYOUT_MATCHES_KERNEL_ASSUMPTION=1        <- not a struct problem

DOT_ROW_A                =  0.123404493    decode(base + 0*1260) . x
DOT_TRANSPOSE_B          =  0.01646907316  sum_c W[c,0]*x[c]
DOT_CURRENT_PRODUCTION_C = -0.0315951438   gguf_loader ToFloat32 row 0
DOT_CURRENT_AVX512_D     = -3.820923805   GemvQ6K_AVX512 row 0
C_EQ_A=0  D_EQ_A=0  C_EQ_B=0  D_EQ_B=0
VERDICT=ROW_SELECTION_OR_STRIDE_WRONG
```

Element-wise probe, separating decode from dot product:

```ini
ELEMENTWISE_MATCH=0     FIRST_BAD_COL=0
DETAIL col=0  direct=-0.0148701668  tofloat=-0.00743508339   (exact 2x)
WORST_REL=1.77451372e+10
```

### What this changes

`gguf_loader::ToFloat32` and an independent direct block decode **disagree from
element 0 of the tensor** — block 0, position 0. There the production value is
*exactly half* the direct decode, and across the row the worst relative error is
`1.8e10`, so it is **not a uniform scale factor**: the two disagree about which
weight each buffer slot holds.

This is **not** the outcome the pinned-upstream comparison predicted, and it
supersedes the "decoders exonerated, geometry only" reading above. The
*algorithms* are exonerated — both match upstream line for line. The **live**
decode path on real Q6_K bytes is not.

On inspection `ToFloat32`'s block loop is arithmetically correct
(`data_ + b*210`, `out + b*256`, `blk = 256`), and `view->data<uint8_t>()` is the
same base pointer it uses internally, so on the available evidence the two should
be incapable of disagreeing at element 0. **I am not closing this by
assertion.** Distinguishing a pointer/aliasing problem in the test from a `d`
(fp16 super-scale) read difference or a `scales` base-offset difference requires
a byte-level trace of one block, not another aggregate.

```ini
Q6_K_DECODER_ALGORITHM = MATCHES_PINNED_UPSTREAM
Q6_K_LIVE_ELEMENTWISE  = FAILS_AT_ELEMENT_0
Q6_K_ROOT_CAUSE        = NOT_YET_ESTABLISHED
```

## Required before Q6_K can be admitted

```ini
1. Element-wise single-row decode comparison, both paths, first divergent index
   -> distinguishes a decoder defect (a) from a row convention (b)
2. If (a): transcribe dequantize_row_q6_K from ggml-quants.c as a third
   implementation and diff field by field against both candidates
3. Verify cols=shape[0] independently for every Q6_K tensor, not just the
   embedding, by reconciling rows*(cols/256)*210 against byte_size for each
4. If gguf_loader is wrong, fix it and re-run inference-path evidence
5. Only then implement the AVX-512 path, with the qh multishift unpack
6. Re-run this gate; require 29/29 with the negative control still firing
```

## What this receipt does not claim

- No Q6_K performance claim. The scalar path is correct but unoptimized.
- No claim that the inference path is currently loading correct Q6_K weights.
  That is the open question, and it is the reason this gate is FAIL.
- Q4_K is unaffected and remains proven across all 168 tensors
  (`RAWRXD_Q4K_GEMV_PARITY_001`).

## Note on harness design

Two harness defects were found and fixed while building this, both worth
recording because they would have produced false confidence:

1. **A third hand-written reference was itself buggy** (gave 1.28 where the
   validated single-block reference gave 1.0). Every additional hand-written
   decoder is another chance to be wrong, which is why the final reference is
   `gguf_loader::ToFloat32` — a separately-validated component.
2. **A global aggregate over `151936x1536` is 233M terms.** A float accumulator
   loses all significance there, so a total-sum comparison measures float drift,
   not the kernel. Comparisons are now per-row.
3. **ggml stores `ne[0]` as the contiguous dimension**, so `cols = shape[0]`.
   Reading it as `rows = shape[0]` is invisible on square tensors and wrong on
   everything else — it is why `token_embd.weight [1536, 151936]` was initially
   geometry-rejected. Verified: `151936 * (1536/256) * 210 = 191439360` bytes.
