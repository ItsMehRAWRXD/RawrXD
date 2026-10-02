# RAWRXD_V6_BITACCOUNT_006

Corrected serialized-size accounting for Decoda v6 on real DeepSeek-V2-Lite
expert weights. This supersedes the `MEAN_ALLOCATED_BITS = 0.1774` line in
`RAWRXD_V6_KERNEL_CLOSURE_005`, which was wrong twice over.

## 1. Two errors in the earlier figure

```cpp
const double meanBits = tot ? (0.0*zero + 1.0*one)/double(tot) : 0.0;
```

**Error 1 — the expression omitted M2/M3/M4 entirely.** It computed
`999/5632 = 0.1774`: the M1 block count over the total block count. It was never
a mean over all five buckets.

**Error 2 — units.** `M` is bits **per weight**, not bits per block. From
`beacon_core.cpp` `block_bytes(count,bits)`:

```
residual payload = (count*bits + 7) / 8   bytes, for `count` weights
centroids        = (1 << bits) * 4         bytes
```

For a 256-weight block, `count*bits/8` is exactly `bits` bytes per weight. So
dividing a mean-`M` by 256 double-normalizes it.

```
MEAN_M            = 2.66193
MEAN_RESIDUAL_BPW = 2.66193      (do NOT divide by 256)
```

Neither `0.1774` nor `0.0104` should have been quoted.

## 2. M semantics, read off the serializer

```
M=0 -> code   0 B + centroids  0 B + flag 1 B =   1 B per 256-weight block
M=1 -> code  32 B + centroids  8 B + flag 1 B =  41 B
M=2 -> code  64 B + centroids 16 B + flag 1 B =  81 B
M=3 -> code  96 B + centroids 32 B + flag 1 B = 129 B
M=4 -> code 128 B + centroids 64 B + flag 1 B = 193 B
```

M=0 carries a flag only — no centroids, no code planes. `beacon_core.cpp:92`
assigns `centroids[b]` and `codes[b]` only when `k != 0`.

## 3. Census, this slice

`blk.9.ffn_gate_exps.weight`, expert 0, 256x1408 slice = 360,448 weights,
1408 blocks of 256.

```
M0_BLOCKS=133    M1_BLOCKS=283    M2_BLOCKS=144
M3_BLOCKS=215    M4_BLOCKS=633                  total 1408

MEAN_M = (0*133 + 1*283 + 2*144 + 3*215 + 4*633) / 1408
       = 3748 / 1408 = 2.66193
```

Cross-check: `3748 bits * 32 bytes/bit = 119,936 B`, and
`119936 * 8 / 360448 = 2.66193 b/w`. Consistent.

## 4. Actual serialized bytes

Encoder's own accounting, not a model:

| component | bytes | b/w |
|---|---:|---:|
| residual code planes | 119,936 | 2.6619 |
| **Lloyd centroids** | **51,960** | **1.1532** |
| per-block flags | 1,408 | 0.0312 |
| shared (`52+rows+cols+outliers*6`) | 12,528 | 0.2781 |
| block-index array | 1,408 | 0.0312 |
| **TOTAL** | **187,240** | **4.1557** |
| Q4_K source | 202,752 | 4.5000 |

```
V6_TOTAL_BPW   = 4.1557
V6_VERSUS_Q4K  = 0.9235x      COMPRESSES
COMPRESSION_GAIN = 7.65%
CENTROID_SHARE_OF_V6 = 27.75%
```

## 5. The correction that matters to the architecture

The design target was **3.125 b/w**. What the encoder actually emits on real
weights is **4.1557 b/w**.

It still beats Q4_K, but by **7.65% rather than the ~30% the roadmap assumed.**
A `.dcb6` sidecar buys bandwidth. It is not a step-change in footprint.

The dominant single term is the fp32 Lloyd centroid table at **1.1532 b/w** —
51,960 levels for 360,448 weights. A 256-weight block at M=4 spends 64 bytes of
table, which is 2.00 b/w on that block alone.

## 6. Recorded but deliberately NOT acted on

fp16 centroids would take the table to 0.5766 b/w and the total to ~3.58 b/w
(0.795x Q4_K, a 20.5% reduction). int8 with a per-block scale reaches ~3.40
b/w; the earlier `~3.28` estimate was optimistic about the scale's own width.

**Not implemented.** `RAWRXD_V6_KERNEL_PARITY` is unmeasured, and a rate
improvement on unverified output is worse than no rate improvement. This is
recorded so the branch history shows the option exists, and so it is not
rediscovered as if it were new.

## 7. Scope and limits of this measurement

- **One slice**: expert 0, 360,448 weights = 1/8 of an expert. The 4-expert
  census in `RAWRXD_V6_KERNEL_CLOSURE_005` gave `MEAN_M = 2.65998` against this
  slice's `2.66193`. Per-block costs should hold at full-expert scale, but the
  fixed `52 + rows + cols` overhead amortizes differently and the model-wide rate
  is not yet measured.
- **Size only.** This says nothing about whether `Dot2/3/4` compute the right
  answer. `REAL_DECODA_DOT_CALLS = 4021` proves link and execution.
  `V6_KERNEL_PARITY = NOT_MEASURED` and `DCB6_EXECUTION_BPW = UNMEASURED`
  remain open.
- The kernel was fed raw Q4_K weights as activations, so the 4021 dot calls
  computed a meaningless dot product.

```ini
RAWRXD_V6_BITACCOUNT_006
MEAN_M=2.66193
MEAN_RESIDUAL_BPW=2.66193
RESIDUAL_CODE_BPW=2.6619
CENTROID_BPW=1.1532
OVERHEAD_BPW=0.3405
V6_TOTAL_BPW=4.1557
Q4K_BPW=4.5000
V6_VERSUS_Q4K=0.9235x
SUPERSEDES_MEAN_ALLOCATED_BITS_0_1774=YES
KERNEL_PARITY=NOT_MEASURED
FP16_CENTROID_LEVER=RECORDED_NOT_IMPLEMENTED
```

Reproduction: `cl /std:c++17 /O2 /EHsc /W4 /arch:AVX2 /D_CRT_SECURE_NO_WARNINGS
/I F:\~dev\rawrxd\src /I F:\~dev\rawrxd\src\deep2 bitaccount.cpp
QuantKernelRegistry.cpp psapi.lib`.
