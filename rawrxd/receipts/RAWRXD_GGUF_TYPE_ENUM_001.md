# RAWRXD_GGUF_TYPE_ENUM_001

Status: **FIXED — P0, root cause of "the loader cannot read any real model"**
Date: 2026-10-01
Severity: P0. Every real-model result was impossible before this.

## The defect

`src/gguf_loader.hpp` declared the GGUF metadata-value type enum as:

```cpp
Uint8=0 Int8=1 Uint16=2 Int16=3 Uint32=4 Int32=5 Float32=6
Uint64=7 Int64=8 Float64=9 Bool=10 String=11 Array=12 ...
```

The GGUF specification (and `ggml.h`) defines:

```ini
UINT8=0 INT8=1 UINT16=2 INT16=3 UINT32=4 INT32=5 FLOAT32=6
BOOL=7 STRING=8 ARRAY=9 UINT64=10 INT64=11 FLOAT64=12
```

Everything from `UINT64` onward was shifted by three. `BOOL`, `STRING` and `ARRAY`
were placed where `UINT64`, `INT64` and `FLOAT64` belong.

## Measured consequence

Against `F:/~dev/qwen2.5-coder-1.5b-base.gguf` (940 MB, Qwen2.5-Coder-1.5B, base):

```text
before: MODEL_LOAD=FAIL
after:  MODEL_LOAD=PASS   TENSORS_PARSED=338
```

The mechanism is exact and was confirmed byte-for-byte, not inferred. The first
metadata key in the file is:

```text
offset 24 : key_len   = 20
offset 32 : key       = "general.architecture"
offset 52 : type_byte = 8
```

Type byte 8 is `STRING` in the specification. The old enum called it `Int64`, so
the loader consumed the eight ASCII bytes `llama...` as an integer, the metadata
stream desynchronised from that point, and parsing eventually failed on a
structurally valid 940 MB model.

## Why it survived an entire session of passing tests

The in-tree `GGUFTensorWriter` used the **same wrong enum**. Writer and reader
therefore agreed with each other on a private, non-standard format, so every
synthetic round-trip passed:

```ini
synthetic GGUF written by GGUFTensorWriter -> parsed by GGUFLoader -> PASS
```

Both sides were wrong in the same way, so the differential test had nothing to
differ against. This is the same failure class as the shared-objection harness in
`RAWRXD_CPU_PARITY_AND_THREAD_SEMANTICS_001`, one layer up: an oracle built from
the same assumption as the thing it was checking.

**Every synthetic GGUF result produced before this fix is invalidated as evidence
of real-model compatibility.** The kernel-level parity results
(`kquant_parity_check`) remain valid, because those compare dequantisation
kernels directly and never encode a GGUF metadata stream.

## Fix

```cpp
enum class GGUFType : uint32_t {
    Uint8=0, Int8=1, Uint16=2, Int16=3, Uint32=4,
    Int32=5, Float32=6, Bool=7, String=8, Array=9,
    Uint64=10, Int64=11, Float64=12,
    // writer-side conveniences only; never valid on the wire
    Uint32Array=13, Int32Array=14, Float32Array=15,
    Uint64Array=16, Int64Array=17, Float64Array=18,
    BoolArray=19, StringArray=20
};
```

The array subtypes are not part of the specification at all — an array is `ARRAY`
plus an element type plus a length, which the reader already handles. They are
retained only so the writer's convenience types keep compiling, and are documented
as never appearing on the wire.

## Post-fix verification

```ini
MODEL_LOAD=PASS
ARCH=qwen2
TENSORS_PARSED=338
TYPE_F32=141  TYPE_Q4_K=168  TYPE_Q6_K=29    (sums to 338 exactly)
MODEL_MAGIC=GGUF  GGUF_VERSION=3
TARGET blk.0.attn_q.weight  Q4_K  1536x1536
TARGET_BYTE_SIZE=1327104   TARGET_ELEMENTS=2359296
TARGET_DECODE_OK=1  TARGET_NONFINITE=0
TARGET_NONZERO=2359182 / 2359296  = 99.99517% density
```

Geometry reconciles exactly, which is what distinguishes a correct parse from a
parser that merely labelled an arbitrary byte range:

```ini
1536 * 1536                      = 2359296   == reported elements
1536/256 = 6 blocks/row, *144 B  = 864 B/row
1536 * 864                       = 1327104   == reported byte size
1327104 * 8 / 2359296            = 4.5 bits/weight
```

## Regression status

Both parity suites re-run green after the enum change:

```ini
kquant_parity_check  RESULT PASS (0 failures)
math_parity_check    RESULT PASS (0 failures)
```

## Rule this establishes

```ini
ORACLE_MUST_NOT_SHARE_ASSUMPTIONS_WITH_SYSTEM_UNDER_TEST
SELF_ROUND_TRIP_THROUGH_SHARED_WRITER=NOT_EVIDENCE
MINIMUM_EVIDENCE=ONE REAL_THIRD_PARTY_ARTIFACT
```

A writer/reader pair that share an encoding cannot detect an encoding error. This
repository generated its own GGUF files and therefore could never notice it had
invented a format. The probe that found this
(`real_gguf_probe.cpp`) requires only that a real model exist on disk.

## Follow-up

`GGUFTensorWriter` is now self-inconsistent with the specification it claims to
write. It works only because the reader was wrong in the same way. Either correct
it against the spec or mark it explicitly as a test-only format with a distinct
magic, so it can never again be mistaken for GGUF.
