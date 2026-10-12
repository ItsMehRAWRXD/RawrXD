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

## Non-finite scale census - the discriminating test

The reviewer's first diagnostic was run: inspect scale validity at the same
block indices across multiple rows.

```
non-finite scale census (512 rows x 84 blocks)
  rows containing any NaN scale : 479 / 512
  total NaN scales              : 1363
  NaN scale positions           : blk0(12) blk1(18) blk2(15) blk3(15) ...
  VERDICT: NaN positions VARY between rows -> ADDRESSING fault.
```

That verdict is NOT reliable and is recorded as such. Randomly distributed NaN
scales would also produce varying positions, so this test does not actually
discriminate the two causes. It was worth running and it was worth saying so.

### Data-section base sweep (measured, not assumed)

Sweeping the base +-64 bytes, counting non-finite Q5_0 scales at 4096 blocks:

```
base+0  : 129 / 4096      base+5  :  20 / 4096
base-16 :  33 / 4096      best    : -61 with 20 / 4096
NOT RESOLVED: no base in [-64,+64] yields all-finite scales.
```

No byte offset produces zero non-finite scales. If the fault were a simple
mis-based data section, the correct base would read all-finite. It does not.

### The address arithmetic is independently confirmed

131072 rows x 84 blocks/row x 22 bytes = 242,221,056 bytes, which matches the
tensor byte span reported from the GGUF directory exactly. So the row count,
block stride and element width are all correct - the tensor occupies precisely
the region being read.

### What this leaves

The scales being read are real scale bytes (the byte span is exact), and about
3% of them decode to IEEE NaN/Inf (0x7fb0 observed: exponent 0x1F with a
non-zero mantissa). Random 2-byte pairs form NaN/Inf patterns only ~0.003% of
the time, so 3% is roughly ten times too high for pure noise, yet no offset
corrects it.

The cause is NOT resolved. The single decisive test outstanding is the
reviewer's third one: compare against an independently parsed GGML reference.
Without it, "the file has NaN scales" and "my block layout is subtly wrong"
indistinguishable from inside this tool alone.

### What is still solid

Two independently written dequantizers agree bit-for-bit on 2688 real
dequantized weights (0 mismatches, max abs diff 0). That is evidence the
implementation matches its own specification, and it is not evidence of parity
with GGML - which is why the reference comparison is called out as the next
step rather than skipped.