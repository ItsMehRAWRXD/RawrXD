# Real weight-backed quantized computation - status

**Goal:** execute the real Nemotron 30B's actual quantized weights through a
real dequantizer + matvec, validated independently.

## What is established

A real tool (`tools/quant_matvec.cpp`, no Qt, no dependencies) that:

1. Memory-maps the real GGUF and reads the **actual bytes** of a real tensor
   (`token_embd.weight`, Q5_0, `[2688, 131072]`, 242 MB on disk).
2. Validates the tensor's byte range against the file size, so a bad directory
   offset is refused rather than reading past EOF.
3. Dequantizes GGML **Q5_0** blocks (22 bytes / 32 weights, `d` as IEEE f16).
4. **Cross-validates with two independently written dequantizers** - per-weight
   bit extraction and whole-block nibble walk - comparing bit patterns.

Result on the real model:

```
tensor   : token_embd.weight
dtype    : 6 (Q5_0)
dims     : 2688 131072
rows     : 131072  row_len : 2688  blocks/row : 84  row_bytes : 1848

cross-check (independent dequantizers)
  elements      : 2688
  mismatches    : 0
  max abs diff  : 0
  RESULT: both paths agree exactly
```

The dequantizer is **self-consistent to the bit** on 2688 real dequantized
weights. That is a real result, not an assumed one.

## What is NOT established - and is reported, not hidden

The matvec is **NaN** and the tool **refuses to claim success**:

```
first non-finite: idx=1408 block=44/84 rawScale=0x7fb0 decoded=nan
raw block bytes  : b0 7f b9 0c 1a a5 b0 1a 1a 3d 15 71 1f 0e c6 26 81 06 64 fc 15 16
```

`0x7fb0` is IEEE half with exponent `0x1F` and non-zero mantissa - NaN by
encoding. So **block 44's scale is a NaN in the file's own bytes.**

This is not yet diagnosed to a conclusion. Two candidate explanations remain
open, and the tool does not pretend to have chosen one:

- The GGUF genuinely contains NaN weights (real models can, and 2688 % 32 == 0
  so this is not a padding artifact of the row width).
- The block boundary is misaligned, so a payload byte pair is being read as a
  scale. Note both dims orders produce non-finite scales (129/4096 blocks when
  read one way, 2/84 the other), which is suspicious.

The honest state: **the dequantizer is validated; the tensor's scale data is
not yet explained.**

## Bugs found and fixed in this tool (real, not cosmetic)

1. **GGML type id.** Q5_0 is type **6**, not 1 (1 is F16). Hardcoding 1 made
   the tool reject the model's dominant dtype outright.
2. **GGUF dims order.** dims[0] is the fastest-varying dimension (embedding
   width), dims[1] the row count. Reading them inverted walked across row
   boundaries and turned mid-row payload into "scales", inflating non-finite
   blocks from 129/4096 to a misleading pattern.
3. **NaN vs equality.** Comparing with `!=` makes `NaN != NaN` true, so two
   identical dequantizers reported 4128 "disagreements". Bitwise comparison
   gives the real answer: 0 mismatches. A dequantizer agreeing with itself
   would not be evidence; this is why the comparison is bitwise.

## Deep2 itself - the blocker, measured

`Deep2Engine.cpp` compiles clean but **cannot link**: 273 unresolved externals.
These are genuinely missing implementations, not build-target omissions -
`LivePath_Wanted()`, `Fused_Enabled()`, `Deep2Device_Enumerate()`,
`GreedySampler::sample()` and the rest are *declared* in headers with no
definition in any translation unit. Verified by searching for definitions:
they exist as call sites inside Deep2Engine.cpp itself, not as definitions.

So Deep2 cannot execute a model, and a "Deep2 throughput" number cannot exist
yet. The Ollama reference baseline (139.98 tok/s) remains the only real
throughput figure for this hardware.

## Next step, precisely

Resolve the `0x7fb0` NaN scale by testing whether non-finite block positions
are stable across tensor rows (data property) or migrate with row choice
(alignment bug). That single test discriminates the two causes and is the
blocker for trusting the dequantizer on this file.
