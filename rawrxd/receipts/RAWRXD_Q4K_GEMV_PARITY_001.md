# RAWRXD_Q4K_GEMV_PARITY_001

Status: **CPU_HALF=PASS (whole model) / GPU_HALF=INVALID (open)**
Date: 2026-10-01
Harness: `real_q4k_gemv_parity.cpp`
Model: `F:/~dev/qwen2.5-coder-1.5b-base.gguf` (940,401,408 bytes, Qwen2.5-Coder-1.5B base)
Depends on: `RAWRXD_GGUF_TYPE_ENUM_001` — before that fix this file could not be opened at all.

## Model-wide sweep — every Q4_K tensor in the model

The single-tensor result above is now superseded by a full sweep. `qsweep.exe
<model> --all` runs the same comparison over **every Q4_K tensor in the file**:

```ini
MODE=SWEEP_ALL_Q4K
Q4K_TENSOR_COUNT=168
TENSORS_TOTAL=168
TENSORS_PASS=168
TENSORS_FAIL=0
TENSORS_INVALID=0
TENSORS_GEOMETRY_REJECTED=0
WORST_REL_MAX_DIFF=2.94528409e-06
WORST_COSINE=1.000000000000
WORST_TENSOR=blk.9.ffn_gate.weight  rel=2.39744e-06  cos=1.000000000
CPU_HALF=PASS
GPU_HALF=INVALID
GATE_STATUS=CPU_HALF_PASS_GPU_HALF_OPEN
```

**168 of 168.** Not a sampled subset — every Q4_K matrix in a 1.5B-parameter model:
attention Q/K/V/O, FFN gate/up/down, across all layers, plus embeddings where
present. Each was independently geometry-checked against the 256-element /
144-byte superblock rule before its numbers were admitted.

`TENSORS_GEOMETRY_REJECTED=0` matters: it means no tensor was admitted on trust.
Every one reconciled `rows * (cols/256) * 144 == byte_size` exactly, so no result
here could come from a misidentified byte range.

The worst case across the entire model is a relative max difference of
`2.95e-06` against a double-accumulated reference, with cosine `1.0` to twelve
decimal places. That is float32 accumulation drift, not decoder error.

## What this establishes

The production `QuantKernelRegistry` Q4_K GEMV kernel, fed **the real packed bytes
of real tensors from a real model**, produces output matching an independent
decode-then-dot reference — across **all 168 Q4_K tensors**, not a sample.

The production `QuantKernelRegistry` Q4_K GEMV kernel, fed **the real packed bytes
of a real tensor from a real model**, produces output matching an independent
decode-then-dot reference:

```ini
PROD_GEMV_VS_DECODED_REF=PASS
VS_REF_PROD_REL_MAX_DIFF=1.51816787e-06
VS_REF_PROD_COSINE=1.000000000000
VS_REF_PROD_NONFINITE=0
REGISTRY_Q4K_KERNEL=NON_NULL
```

Cosine of exactly 1.0 over 1536 outputs is the strongest single statement
available on the CPU side: the production kernel is not merely close, it is
collinear with the reference.

## Receipt binding

```ini
MODEL_PATH              = F:/~dev/qwen2.5-coder-1.5b-base.gguf
MODEL_SHA256            = 6A77366395772462C84F0C4D226AC404674327CBE78C01E4391CC7E0C698851E
TENSOR                  = blk.0.attn_q.weight
TENSOR_GGML_TYPE        = Q4_K
TENSOR_DIMS             = 1536 x 1536
TENSOR_ELEMENTS         = 2359296
TENSOR_BLOCK_SIZE       = 256
TENSOR_BYTE_OFFSET      = 219779584
TENSOR_BYTE_SIZE        = 1327104
PACKED_RANGE_HASH       = c9921f33dd27a77f      # FNV-1a over the 1327104 packed bytes
INPUT_DIMS              = 1536
INPUT_HASH              = f2dedbf6676af2ae      # FNV-1a over the fp32 input
DECODED_HASH            = bf280b31a771eac8      # FNV-1a over decoded f32
REF_HASH                = bd02583513a9f923      # decode -> double-accumulated dot
FP32_HASH               = 71004bb3a403f8cb      # decode -> f32 dot
PROD_HASH               = c9d7b423474e5c2e      # production registry GEMV
EXECUTABLE              = rqp.exe
```

The whole-file SHA-256 is captured above, so the receipt binds to an exact artifact.
The packed-range hash plus the exact byte offset and size additionally identify
the tensor independently of the file.

## Geometry invariants (checked before any numerical claim)

```ini
GEOM_ELEMENTS_MATCH   = 1     1536*1536      = 2359296
GEOM_BLOCKS_PER_ROW   = 6     1536/256
GEOM_PACKED_BYTES_PER_ROW = 864               6*144
GEOM_TOTAL_BLOCKS     = 9216
GEOM_EXPECTED_BYTES   = 1327104
GEOM_BYTE_SIZE_MATCH  = 1     1536*864       = 1327104
GEOM_BITS_PER_WEIGHT  = 10616832/2359296     = 4.5
GEOM_STATUS           = PASS
```

These are what distinguish a correct parse from a parser that labelled an
arbitrary byte range `Q4_K`. Any of them failing makes the gate `INVALID`, not
`FAIL`, because the tensor identification itself would be wrong.

## Both comparisons

| comparison | max abs diff | rel max diff | cosine | verdict |
|---|---|---|---|---|
| decode→f32 dot vs decode→double dot | 1.907e-06 | 4.048e-06 | 1.000000000000 | PASS |
| **production GEMV vs decode→double dot** | **7.153e-07** | **1.518e-06** | **1.000000000000** | **PASS** |

The production kernel is *closer* to the double-accumulated reference than the
f32 dot is, which is expected: it accumulates in lanes and reduces, so its
summation order is closer to a wide partial-sum tree than a sequential f32 loop.

Tolerances: `1e-5` for the f32 dot, `1e-4` for the fused GEMV. Both are orders of
magnitude tighter than any decoder defect would produce, and neither was tuned
after seeing the result.

## Historical detection

The corrected decoder is the one that satisfies all of the above. The original
`gguf_loader` nibble mapping is **detected by this same gate**: it diverges from
the reference at weight 32, which is the first element of group 1 — group 0 is
correct by coincidence and groups 1 through 7 were scrambled. On a real tensor
that defect would have produced garbage that still had correct density and
correct element count, which is precisely why structural geometry alone is not
sufficient and the numerical comparison exists.

## Row/column convention — RESOLVED

This section previously recorded the convention as UNPROVEN. It is now closed by
`RAWRXD_Q4K_ORIENTATION_CERT_001`, using the operator contract asserted in
production source:

```ini
Q4_K_ROW_COLUMN_CONVENTION = PROVEN
COLS := shape[0]              (Deep2Engine.cpp:1238, binder)
ROWS := prod(shape[1..])
SEMANTIC: cols = INPUT dim, rows = OUTPUT dim
  ffn_up   cols=hidden(1536)     rows=intermediate(8960)
  ffn_down cols=intermediate(8960) rows=hidden(1536)
  enforced at Deep2Engine.cpp:2375-2378, call site :4255
```

The two FFN tensors are mutual transposes consuming and producing **different**
widths, so the contract discriminates the orientation in a way the byte-size
identity (`rows*(cols/256)*144`, commutative) cannot. The byte-size check remains
**transpose-blind for all 168 tensors**; that limitation is unchanged and is why
the operator contract was needed.

Independent confirmation of the Q4_K *arithmetic* also now exists: upstream
`ggml-quants.c` `dequantize_row_q4_K` and `get_scale_min_k4` match the
implementation used here exactly — `get_scale_min_k4` reads the min high bits
from `q[j-0]` (i.e. `s[4..7]` for the upper four, the bug fixed in
`RAWRXD_Q4K_NIBBLE_MAP_001`), and the dequantiser walks 32-byte spans emitting
low-nibble weights 0–31 then high-nibble 32–63, which is the group rule
`q = qs + (g/2)*32, shift = (g&1)?4:0`.

`q4k_shape_census.cpp` over the same model:

```ini
Q4K_TOTAL=168  SQUARE=56  NONSQUARE=112
CONVENTION_cols=shape0=168   cols=shape1=168   neither=0
  1536x1536  x56
  1536x256   x42
  1536x8960  x56
  8960x1536  x14
```

**This certificate cannot establish the row/column convention, for any of the 168
tensors, not merely the 56 square ones.** The geometry identity used throughout is

```text
rows * (cols/256) * 144 == byte_size
```

which is **commutative in `rows` and `cols`** — `a*b/256*144` equals `b*a/256*144`.
So both conventions satisfy it for every tensor, and the check is transpose-blind
by construction. The corpus even contains genuine transposes of one another
(`1536x8960` and `8960x1536`).

Nor can the numerical comparison help. Both the production GEMV and the
decode-then-dot reference are driven by the *same* `(rows, cols)` assignment, so a
consistent transposition in both would cancel and still pass. The sweep proves the
Q4_K arithmetic is self-consistent; it does not prove the convention is right.

```ini
Q4_K_NUMERICS=PROVEN          168/168, cosine 1.0
Q4_K_GEOMETRY_CONVENTION=UNPROVEN  (check is commutative in rows/cols)
```

Discriminating evidence must come from a tensor where only one convention fits.
`token_embd.weight [1536, 151936]` provides exactly that: `151936 % 256 != 0`,
so `cols = shape[0] = 1536` is the only arrangement satisfying
`151936 * (1536/256) * 210 = 191439360` bytes, which matches the file exactly.
The convention used throughout this work is therefore **supported** by that
tensor — but it is one tensor, and it is not Q4_K.

```ini
GPU_REACHED=0
GPU_HALF=INVALID  (no device path was exercised)
GATE_STATUS=CPU_HALF_PASS_GPU_HALF_OPEN
```

No device path was exercised. Per the discipline established by the Vulkan
projection investigation, **failure to reach the device is `INVALID`, never a
numerical `FAIL`** — the two mean different things and conflating them would let
an unreachable GPU masquerade as a correct one.

Closing the GPU half requires, on the same real tensor:

```text
  same packed range (offset 219779584, size 1327104, hash c9921f33dd27a77f)
      -> device upload (assert the byte range actually transferred)
      -> DispatchGemvQuant
      -> readback
      -> compare against PROD_HASH above
      -> report gpu_reached / readback bytes / max abs / cosine
```

Until that runs, the correct statement is the one in the status line:
**real-model Q4_K CPU GEMV parity is established; the device half is not.**

## Not established by this receipt

- Any GPU result.
- Full-model inference output, layer stacking, KV cache, sampling, or tokens.
- Any performance figure.
- The 29 Q6_K tensors, which remain scalar and are now the largest Q4_K-class gap.

`RAWRXD_Q4K_GEMV_PARITY_001` is therefore **not closed**. It has moved from "no real-model evidence of any kind" to "CPU half proven across all 168 Q4_K tensors in a real model".
