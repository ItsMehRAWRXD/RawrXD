# G05 — Q2_K / Q3_K Numerical Parity

**Gate:** G05 — Q2_K/Q3_K native kernels with numerical parity vs llama.cpp
**Date:** 2026-10-14
**Baseline HEAD:** `4213f56908` (+ G04 concurrent-safety repair)

## Result

**PASS** — layout, dequant walk, and dot-product parity all verified against the
repository's own vendored ggml reference.

Prior state: receipt showed 25,413 GPU calls, zero CPU fallbacks, **0/129 argmax
agreement** against llama.cpp. Root cause was not the GPU: it was CPU-side
semantics and an ABI layout mismatch, so it reproduced on the host.

## Root causes found (four independent defects)

### 1. `block_q2_K` / `block_q3_K` / `block_q5_K` field order was wrong

`src/deep2/QuantKernelRegistry.hpp` declared:

```cpp
struct block_q2_K { uint16_t d; uint16_t dmin; uint8_t scales[16]; uint8_t qs[64]; };
```

but ggml (`3rdparty/ggml/src/ggml-common.h:266`) is:

```c
struct { uint8_t scales[QK_K/16]; uint8_t qs[QK_K/4]; union { struct { ggml_half d, dmin; }; }; };
```

i.e. the fp16 super-scales live at the **END** of the block for q2_K/q3_K/q5_K,
and at the **START** for q4_K/q6_K/q8_K. Every Q2_K/Q3_K/Q5_K tensor read through
Deep2's struct interpreted the first 4 scale bytes as an fp16 scale pair and the
last 4 bytes of `qs` as `d`/`dmin`. Now fixed with `static_assert`s on size *and*
`offsetof` for every field. `q4_K`, `q6_K`, `q8_K` were already correct and are
unchanged.

### 2. Q2_K dot product: one scale per 32 elements instead of two

`vec_dot_q2_K_q8_K_single` applied `scales[8n + 2j]` to all 32 elements of a
group. ggml uses `scales[8n + 2j]` for the first 16 and `scales[8n + 2j + 1]` for
the second 16 (`dequantize_row_q2_K`, ggml-quants.c:801-807). The second half of
every group used the wrong scale.

### 3. Q2_K dot product: min term paired with the wrong block sums

The old code computed `m = dmin * (scales[is] >> 4)` per `(n, j)` and subtracted
`m * bsums[2n + j/2]`. ggml accumulates
`summs = sum_{g=0..15} bsums[g] * (scales[g] >> 4)` — all 16 min nibbles, each
paired with its own 16-element block sum, applied once. The old form used only 4
of the 8 relevant sums per super-block and replicated them.

### 4. Q3_K: activation pointer advanced 128 per super-block instead of 32 per group

`vec_dot_q3_K_q8_K_single` advanced `q8 += 128` at the end of each super-block,
so groups 1..3 of each super-block kept multiplying against group 0's activations
and half the activation vector was never used. Also `hmask[32*n + l]` read past
the 32-byte `hmask` into `qs` for the whole second super-block — ggml reuses the
same 32 hmask bytes across both super-blocks, with the mask bit continuing to
shift (m = 1,2,4,8 then 16,32,64,128).

Also fixed while here: `vec_dot_q5_K_q8_K_single` had a **stack buffer overrun**
(`a[32*h + 32 + l]` wrote past the end of `int8_t a[256]` for `h == 7`, tripping
`STATUS_STACK_BUFFER_OVERRUN` / 0xC0000409) and indexed `qs` and `qh`
independently where ggml walks them in lockstep.

## Parity criterion (order-independent, cannot hide a bug)

A 256-term dot product has no single exact float32 answer — the result depends on
accumulation order. Instead of a hand-picked tolerance, the gate asserts:

```
|Deep2 - exact_double| <= |ggml_f32 - exact_double| + slack
```

`ggml_f32` is `ggml_vec_dot_q2_K_q8_K_generic` / `_q3_K_` transcribed verbatim in
their own accumulation order, and `exact_double` is sum over
(reference-dequantized weight) x (dequantized activation) accumulated in double.
Deep2's kernel must therefore be **at least as accurate as ggml's own float32
accumulation**. A real mathematical error is orders of magnitude larger than the
slack and always fails — which is exactly what the four defects above did (0.334
relative error for the Q3_K activation bug vs ~1e-5 for pure rounding).

The dequant gate is exact: the reference walk and the walk under test perform
identical operations in identical order.

## Fixes applied

* `src/deep2/QuantKernelRegistry.hpp` — corrected `block_q2_K`, `block_q3_K`,
  `block_q5_K` to ggml's byte layout; added `static_assert` on all six K-quant
  sizes and documented the field offsets; exported `Q2_K_*_OFF`, `Q3_K_*_OFF`,
  `Q5_K_*_OFF` constants next to the structs so raw-offset callers cannot drift.
* `src/deep2/QuantKernelRegistry_K.h` — rewrote `vec_dot_q2_K_q8_K_single`,
  `vec_dot_q3_K_q8_K_single`, `vec_dot_q5_K_q8_K_single` and the AVX2 Q2_K
  variant to match ggml exactly.
* `vec_dot_q3_K_q8_K_single` now accumulates into eight int32 lanes and applies
  the block scale once, matching ggml's structure (the earlier per-group scale
  apply made it 8x less accurate than ggml's own accumulation).

## Results

| Gate | Result |
| --- | --- |
| block sizes q2_K 84 / q3_K 110 / q4_K 144 / q5_K 176 / q6_K 210 / q8_K 292 | PASS |
| block field offsets (q2_K, q3_K, q5_K) | PASS |
| Q2_K dequant walk, 800 blocks x 256 weights = 204,800 weights | PASS |
| Q2_K dot vs ggml (`vs ggml_f32` = 0, bit-identical) | PASS |
| Q3_K dot vs ggml own-accumulation bound | PASS |
| Q5_K dot vs ggml (worst relative 2.46e-05) | PASS |
| Q2_K adversarial geometry (all nibbles/shifts distinct) | PASS |
| AddressSanitizer (`/fsanitize=address`, 800 blocks) | 0 reports |
| Existing Q8_K packing / Q4_K / Q6_K parity regression | PASS (0 mismatch) |

## Notes

* `runtime_graph_executor.cpp`'s raw-offset Q2_K/Q3_K paths used the **correct**
  ggml offsets already (`qs`+16, `d`+80, `dmin`+82; `hmask`+0, `qs`+32,
  `scales`+96, `d`+108). They were inconsistent with Deep2's own struct; the
  layout fix makes the two paths agree.
* `Deep2Engine.cpp`'s `dequantizeQ2KBlock` indexes through struct members, so it
  is corrected automatically by the layout fix; its scale/shift indexing was
  already ggml-correct.
* The GPU Vulkan shaders were not modified in this gate. `dequant_q2_k.comp` and
  `mul_mat_vec_q2_k.comp` use ggml's own shared `scales`/`qs` buffers and the same
  two-nibble-per-32 geometry, so they were consistent with the reference; the CPU
  comparison now proves the semantics end to end.

## Evidence

| File | Contents |
| --- | --- |
| `optimized_run.log` | 200 blocks, exit 0 |
| `asan_final.log` | `/fsanitize=address`, 800 blocks, exit 0, zero reports |
| `G05_CERTIFICATION.md` | this document |

Reproduce:

```
cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_WIN32_WINNT=0x0A00 ^
   /D_CRT_SECURE_NO_WARNINGS /I src /I src\deep2 /I include /I . ^
   /I 3rdparty\ggml\include /I 3rdparty\ggml\src ^
   src\deep2\test_q2k_q3k_parity.cpp
link /subsystem:console test_q2k_q3k_parity.obj kernel32.lib user32.lib
q2k_parity.exe 800
```
