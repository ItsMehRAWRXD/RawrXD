# RAWRXD_QUANT_E2E_GATE_001 — the Q2_K semantic-garbage root cause, and the end-to-end gate that closes the quant-decode stage

Date: 2026-10-04
Scope: `src/deep2/QuantKernelRegistry.{hpp,cpp}`, `tools/quant_format_reference.hpp` (new),
`tools/quant_block_oracle.cpp`, `tools/quant_e2e_gate.cpp` (new).

```text
CLAIM_PASS_REQUIRES_EVIDENCE=1
CLAIM_BUILT_REQUIRES_BUILD_OUTPUT=1
CLAIM_RUNTIME_WORKS_REQUIRES_RUNTIME_EVIDENCE=1
```

---

## 0. What was asked and what this closes

The request was to add whatever source is missing to finish the end-to-end test. Measured first,
the end-to-end test was blocked by a hole in the *instrument*, not by the product:

```text
quant_block_oracle.exe  (as committed, built and run 2026-10-04)
  G:\~dev\rawrxd\models\llama3.2-3b-Q2_K.gguf      -> VERDICT=NO_VERDICT_NONE_OF_THE_TYPES_UNDER_TEST_APPEAR_IN_THIS_MODEL
  F:\Franken\BackwardsUnlock\1b\unlock-1B-Q4_K_M.gguf -> VERDICT=NO_VERDICT_NONE_OF_THE_TYPES_UNDER_TEST_APPEAR_IN_THIS_MODEL
```

The oracle tested Q8_0 / Q4_0 / Q5_0. Those three types are absent from both files. The dominant
types are Q2_K, Q3_K, Q6_K, Q4_K and F32. **The instrument's subject list was disjoint from its
subjects**, so it could not discriminate anything about the model the investigation is about.

The previous session's finding — "Q8_0 bit-exact; Q4_0/Q5_0 disagreed from element 0" — was measured
against a third file (`gemma3-1b-Q2_K.gguf`) and says nothing about the Q2_K-vs-Q4_K question.

Three sources were missing. All three now exist:

| Source | State | What it adds |
|---|---|---|
| `rawrxd/tools/quant_format_reference.hpp` | NEW | Canonical decoders for F32/F16/BF16/Q4_0/Q5_0/Q8_0/Q2_K/Q3_K/Q4_K/Q6_K, transcribed from upstream |
| `rawrxd/tools/quant_block_oracle.cpp` | REWRITTEN (002) | Census-driven type enumeration; adjudicates every type in the file |
| `rawrxd/tools/quant_e2e_gate.cpp` | NEW | One binary: census -> block parity -> generation -> computed verdict -> receipt file |

---

## 1. The instrument is only as good as its reference, and the old one was wrong

`RAWRXD_QUANT_BLOCK_ORACLE_001` modelled `block_q4_0` as `{d, m, qs[16]}` and `block_q5_0` as
`{d, m, qh[4], qs[16]}`, both with interleaved nibble pairing. Upstream `ggml-common.h` says:

```c
#define QK4_0 32
typedef struct { ggml_half d; uint8_t qs[QK4_0 / 2]; } block_q4_0;
static_assert(sizeof(block_q4_0) == sizeof(ggml_half) + QK4_0 / 2, "...");

#define QK5_0 32
typedef struct { ggml_half d; uint8_t qh[4]; uint8_t qs[QK5_0 / 2]; } block_q5_0;
static_assert(sizeof(block_q5_0) == sizeof(ggml_half) + sizeof(uint32_t) + QK5_0 / 2, "...");
```

One fp16 field, no min. The 18-byte and 22-byte strides that
`RAWRXD_GGUF_STRIDE_GROUND_TRUTH_001` read off the file are **exactly** upstream's current forms —
the source note's inference that they were "NOT ggml's current 20/24-byte forms that carry a second
fp16 min" is wrong. The old reference therefore manufactured a MISMATCH from two of its own errors,
and the "zero-point hypothesis rejected" conclusion drawn from it rested on that.

Reference provenance, recorded in the source header so it can be re-checked:

```text
ggml-common.h, ggml-quants.c — ggml-org/llama.cpp, branch master, retrieved 2026-10-04
  https://raw.githubusercontent.com/ggml-org/llama.cpp/master/ggml/src/ggml-common.h
  https://raw.githubusercontent.com/ggml-org/llama.cpp/master/ggml/src/ggml-quants.c
```

Nothing transcribed from memory; nothing transcribed from `QuantKernelRegistry.*`. A reference that
agreed with production by construction could not detect a production defect.

---

## 2. What the corrected instrument found

`quant_block_oracle2.exe`, bit-exact comparison (`memcmp` on the float, no tolerance), 256 blocks
per type, before any production change:

```text
llama3.2-3b-Q2_K.gguf
  type=10 Q2_K  tensors=112  bytes=578027520  42.6243%   Q2_K   MISMATCH  first_diff=0  65535/65536 differ
  type=11 Q3_K  tensors=84   bytes=454164480  33.4905%   Q3_K   PARITY
  type=14 Q6_K  tensors=1    bytes=323205120  23.8335%   Q6_K   PARITY
  type=0  F32   tensors=58   bytes=700672     0.0517%    F32    PARITY
  TYPES_PRESENT=4  TYPES_JUDGED=4  PARITY=3  MISMATCH=1
  UNJUDGED_TENSOR_BYTES=0 (0.0000%)

  Q2_K  FIRST_DIFF element=0 block=0 offsetInBlock=0
        reference = 0.0025062561     production= 1632384.75
        max|reference|=0.157207489   max|production|= 3173056
        fp16 probe of block 0:
          offset  0 = 45344        offset 80 = 0.00190926
          offset  2 = -0.088623    offset 82 = 0.00398254

unlock-1B-Q4_K_M.gguf (the control)
  Q4_K PARITY, Q6_K PARITY, F32 PARITY  -> VERDICT=PARITY_ALL_TYPES_IN_THIS_FILE

gemma3-1b-Q2_K.gguf
  Q8_0 PARITY, Q4_0 MISMATCH (first_diff=0), Q3_K PARITY,
  Q5_0 MISMATCH (first_diff=1), F32 PARITY
```

The fp16 probe is the whole finding in one line: **the sane scale words in the Q2_K block are at
offsets 80 and 82, and production was reading offsets 0 and 2.** The block is 84 bytes either way,
`queryTypeGeometry` agrees either way, and every size check passes. Only a value check sees it.

---

## 3. Three production defects, each localized to source

### D1 — `struct block_q2_K` field order (the semantic-garbage root cause)

```text
BEFORE  (rawrxd/src/deep2/QuantKernelRegistry.hpp)
  d@0, dmin@2, scales[16]@4, qs[64]@20        <- Q4_K-shaped
ON DISK / UPSTREAM
  scales[16]@0, qs[64]@16, d@80, dmin@82     <- ggml-common.h block_q2_K
```

`block_q2_K` is the **only** `block_*` in `ggml-common.h` whose fp16 super-block scales are not
first. `RAWRXD_Q2K_FIELD_ORDER_001` moved the struct from the on-disk order *to* the Q4_K-shaped
order, reporting that the on-disk order "read d/dmin from quant data". It did — and so does the
order it installed. Field order and decode were wrong simultaneously; the experiment changed one
and read the other's symptom as the verdict.

### D2 — `dequant_q4_0`

`quantize_row_q4_0_ref` sets `d = max / -8` and stores codes in `[0,15]`; `dequantize_row_q4_0`
subtracts 8. Zero point **is** -8. Byte `j` supplies element `j` and element `j+16` — split, not
interleaved. Production had zero point 0 and interleaved pairing.

`RAWRXD_Q4_0_ZERO_POINT_001` tested only `y = (q-8)*d` and rejected it against a 16-token text
sample. With the pairing left interleaved the halves stay transposed whatever the zero point is, so
the experiment could not have passed and the hypothesis was rejected for the wrong reason.

### D3 — `dequant_q5_0`

Fifth bit of element `j` from `qh` bit `j`; of element `j+16` from `qh` bit `j+12`. Production used
`(i/8, i%8)`; the source note speculated the alternative was `(i/4 + i%2)`. Both are wrong, and the
speculation was unnecessary — `dequantize_row_q5_0` states the schedule explicitly.

Also fixed, latent and not the cause: `dequant_q2_k` used `return` inside its innermost of four
nested loops, abandoning the remaining three quarters of the buffer and every later block. Only
reachable on a trailing partial block, which is precisely when a silent truncation is least likely
to be noticed.

---

## 4. After — paired, same instrument, same model, same prompt, same sampling, same seed

`quant_e2e_gate.exe` and `quant_e2e_gate_BEFORE.exe` are the same object linked against the patched
and the pre-change `QuantKernelRegistry` respectively. The only difference between the two runs is
the decode.

```text
llama3.2-3b-Q2_K.gguf   prompt "The capital of France is"   greedy t=0 topK=1 seed=7

  BEFORE                                        AFTER
  TYPE_Q2_K=MISMATCH                            TYPE_Q2_K=PARITY
    first_diff=0                                  (no first_diff)
    mismatched=131071/131072
    max_abs_diff=3173055.98
  TYPE_Q3_K=PARITY                             TYPE_Q3_K=PARITY
  TYPE_Q6_K=PARITY                             TYPE_Q6_K=PARITY
  TYPE_F32=PARITY                              TYPE_F32=PARITY
  TYPES_PARITY=3/4                             TYPES_PARITY=4/4
  CHECKS_TOTAL=11 CHECKS_FAILED=1              CHECKS_TOTAL=11 CHECKS_FAILED=0
  VERDICT=FAIL                                 VERDICT=PASS_ALL_ACTIVE_TYPES_PARITY_AND_STREAMED

  FIRST_TOKEN_TOP8                              FIRST_TOKEN_TOP8
    [11234:8.2453] [36149:7.9427]                [9822:9.5121] [6864:7.7656]
    [64286:7.8838] [30757:7.6710]                [279:7.5585]  [12366:7.3213]
    [119572:7.6518] [31535:7.4206]               [18880:6.9693] [15704:6.9644]
    [1904:7.3892] [40996:7.3855]                 [10057:6.9586] [8753:6.8392]

  TOKEN_IDS  11234 70727 33130 106957 ...        TOKEN_IDS  9822 9822 9822 1 323 9822 ...
  TEXT  [ Ange.acquireuchtajoithiramed           TEXT  [ France France France" and
         Velriceschineario bubble                     France" and " France" and "
         spinrespond instrumenteto]                  France" is]
```

```text
FIRST_TOKEN_TOP8[0].id == TOKEN_IDS[0] == 9822   in the AFTER run
```

The logits vector and the streamed token agree, which is an internal-consistency check the
discriminator previously failed (it once reported top-1 386 while the first generated token was
278).

Other models, same gate:

```text
unlock-1B-Q4_K_M.gguf   Q4_K PARITY, Q6_K PARITY, F32 PARITY   11/11  PASS
                        TEXT [ France\n ...]                   (loops after "France")
gemma3-1b-Q2_K.gguf     Q8_0 PARITY, Q4_0 PARITY, Q3_K PARITY,
                        Q5_0 PARITY, F32 PARITY               11/11  PASS
```

`gemma3-1b-Q2_K.gguf` is named Q2_K and contains **no Q2_K at all** — its tensor table is Q8_0,
Q4_0, Q3_K, Q5_0, F32. That is `RAWRXD_QUANT_SEMANTIC_DISCRIMINATOR_001`'s "the filename is not
evidence" point, confirmed on a real file.

### 4b. Coverage across seven model files, all with the patched decode

`quant_block_oracle3.exe`, 128–512 blocks per type, bit-exact:

```text
FILE                                     TYPES PRESENT (share of bytes)              RESULT
llama3.2-3b-Q2_K.gguf                    Q2_K 42.6% Q3_K 33.5% Q6_K 23.8% F32      4/4 PARITY
unlock-1B-Q4_K_M.gguf                    Q4_K 67.7% Q6_K 32.2% F32                  3/3 PARITY
gemma3-1b-Q2_K.gguf                      Q8_0 47.0% Q4_0 37.2% Q3_K 14.9%           5/5 PARITY
                                         Q5_0 0.8% F32
qwen2.5-coder-1.5b-base.gguf             Q4_K 63.8% Q6_K 36.1% F32                  3/3 PARITY
Phi-3-mini-4k-instruct-q8_0.gguf         Q4_0 96.2% Q6_K 3.7% F32                   3/3 PARITY
mmproj-gemma-4-31B-it-BF16.gguf          BF16 91.8% F32 8.2%                        2/2 PARITY
Codestral-22B-v0.1-Q4_K_M.gguf          Q4_K 94.7% Q5_K 4.0% Q6_K 1.3% F32         3/4 PARITY
                                                                            Q5_K NO_REFERENCE
```

Two of these are load-bearing beyond their own file:

- **`Phi-3-mini-4k-instruct-q8_0.gguf` is 96.2% Q4_0.** A wrong zero point or a wrong nibble
  pairing cannot survive 128 blocks × 32 elements compared bit-for-bit against the specification on
  a file where that type is essentially the whole model. The file is also named `q8_0` and contains
  almost no Q8_0 — the filename-is-not-evidence point again.
- **`Codestral-22B-v0.1-Q4_K_M.gguf` exercises the instrument's honesty path live.** Q5_K is
  present with no canonical decoder, and the tool reported

  ```text
  Q5_K  11  501743616  -  -  -  -  NO_REFERENCE
  UNJUDGED_TENSOR_BYTES=501743616 (3.9633% of 12659613696)
  VERDICT=PARTIAL_PARITY_WITH_UNJUDGED_BYTES          exit 1
  ```

  It did not skip the type, did not count it as a pass, and did not report
  `PARITY_ALL_TYPES_IN_THIS_FILE`. That is the property that matters most in an instrument, shown
  by a real file rather than asserted.

---

## 5. Q5_K — the second inverted struct, and a defect in the reference itself

The reference covered 9 types. The 115-file census in §6 showed the corpus uses exactly 10, and the
one missing type was Q5_K (13) — 3.96% of Codestral-22B-v0.1-Q4_K_M, and up to 12.6% of
Phi-3-medium-128k. `dequantize_row_q5_K` was retrieved from the pinned upstream copy (ggml-quants.c
line 1732) and transcribed.

### D4 — `struct block_q5_K` was inverted, in the opposite direction from Q2_K

```text
upstream   d@0, dmin@2, scales[12]@4, qh[32]@16, qs[128]@48
this header, before   scales[12]@0, qh[32]@12, qs[128]@44, d@172, dmin@174
```

```text
BEFORE  Codestral, blk.0.ffn_down.weight, 128 blocks
        FIRST_DIFF element=0, 32768/32768 differ (100.0000%)
        reference = 0.0107433917   max|reference| = 0.0388633683
        production= 49425.75      max|production|= 83703656
        fp16 probe: offset 0 = 1.16825e-05, offset 2 = 0.000191092  (plausible)
                    offsets 4..126 = -56768, 15720, 20208, 30688    (quant bytes)
AFTER   field order fixed -> max_abs_diff falls 83703656 -> 0.0255791508
        decode fixed      -> PARITY, 0 mismatched
```

### RAWRXD_BLOCK_FIELD_ORDER_CENSUS_001 — all ten structs, compared, not eyeballed

Two inversions in ten is a 20% rate. Eyeballing ten structs is not a census, so all ten were compared
field-by-field against the pinned `ggml-common.h`:

```text
type    production order            upstream order             verdict
Q4_0    d, qs[16]                   d, qs[16]                  MATCH
Q4_1    d, m, qs[16]                d, m, qs[16]               MATCH
Q5_0    d, qh[4], qs[16]            d, qh[4], qs[16]           MATCH
Q5_1    d, m, qh[4], qs[16]         d, m, qh[4], qs[16]        MATCH
Q8_0    d, qs[32]                   d, qs[32]                  MATCH
Q2_K    scales, qs, d, dmin         scales, qs, d, dmin        MATCH (fixed here)
Q3_K    hmask, qs, scales, d        hmask, qs, scales, d       MATCH
Q4_K    d, dmin, scales, qs         d, dmin, scales, qs        MATCH
Q5_K    d, dmin, scales, qh, qs     scales, qh, qs, d, dmin    MISMATCH (fixed here)
Q6_K    ql, qh, scales[16], d       ql, qh, scales[16], d      MATCH
BF16    —                           raw 16-bit, <<16            MATCH (measured)
```

The two K-quants that carry both a scale and a min were each wrong, in opposite directions, and
Q4_K — which carries the same pair — was right throughout. Reading Q4_K's shape and applying it to
Q5_K is what produced the inversion.

### D5 — `dequant_q5_k`: interleaved pairing and a wrong fifth-bit index

Two further defects, independent of the field order, so fixing the struct alone did not make the
type correct (`max_abs_diff` 0.0256, still 100% of elements):

- byte `l` of `qs` supplies element `l` and element `l+32`; the old code indexed `qs[element/2]`
- the fifth-bit mask advances by two bits per 64-value group (`u1` = 1,4,16,64 / `u2` = 2,8,32,128),
  a property of the group; the old code used `qh` bit `element % 8`

### RETRACTED — my own reference was wrong on the day it was written

After the struct fix, Q5_K still mismatched, and the pattern looked exactly like a production defect:
production values at shifted indices, `max_abs_diff` 0.0256, magnitudes entirely plausible. Two
rounds of verification of every shared input (field offsets, `unpack_q4_k_scales` against upstream's
`get_scale_min_k4`, `f16_to_f32` against `half_to_float` including the subnormal path for this
block's `d` = 1.16825e-05) all came back identical, which is what finally established that the fault
could not be in production.

It was in `decode_q5_K`:

```text
upstream    *y++ = d1 * ((ql[l] & 0xF) + (qh[l] & u1 ? 16 : 0)) - m1;   -> (d1*q) - m1
mine, first draft   d1 * (q - m1)                                     -> d1*(q - m1)
```

The two forms differ, both are finite, both land in a plausible numeric range, and neither a review
nor a magnitude check distinguishes them. Q3_K is the trap: upstream really is `dl * (q - adj)`, so
the shape looks like the neighbour and means the opposite thing. Copying the shape from the adjacent
function is precisely the error.

Only the bit-exact `memcmp` comparison caught it, within one run, before it became a retracted
claim. An earlier instrument in this repository used a magnitude heuristic and would have scored
this pair as consistent.

## 6. Adoption — the blocker named earlier is now closed, measured

`rawrxd/build/Release/InferenceEngine.lib` was relinked at **11:52:43**, after the last source edit
(11:42:14). Whether it actually contains the fixes is a measurement, not an inference from mtimes, so
both tools were linked **against the library alone, with no object override**:

```text
quant_block_oracle, lib-only, G:\~dev\rawrxd\models\llama3.2-3b-Q2_K.gguf
  Q2_K PARITY  Q3_K PARITY  Q6_K PARITY  F32 PARITY
  TYPES_JUDGED=4 PARITY=4 MISMATCH=0  UNJUDGED_TENSOR_BYTES=0
  VERDICT=PARITY_ALL_TYPES_IN_THIS_FILE

quant_block_oracle, lib-only, Codestral-22B-v0.1-Q4_K_M.gguf
  Q4_K PARITY  Q5_K PARITY  Q6_K PARITY  F32 PARITY
  TYPES_JUDGED=4 PARITY=4 MISMATCH=0  UNJUDGED_TENSOR_BYTES=0
  VERDICT=PARITY_ALL_TYPES_IN_THIS_FILE

quant_e2e_gate, lib-only, llama3.2-3b-Q2_K.gguf, 16 tokens
  TYPE_Q2_K=PARITY TYPE_Q3_K=PARITY TYPE_Q6_K=PARITY TYPE_F32=PARITY
  TYPES_PARITY=4/4  UNJUDGED_TENSOR_BYTES=0
  CHECKS_TOTAL=11 CHECKS_FAILED=0
  FIRST_TOKEN_TOP8=[9822:9.5121] [6864:7.7656] [279:7.5585] [12366:7.3213] ...
  TOKEN_IDS=9822 9822 9822 1 323 9822 1 323 330 9822 1 323 330 9822 1 374
  TEXT=[ France France France" and France" and " France" and " France" is]
  VERDICT=PASS_ALL_ACTIVE_TYPES_PARITY_AND_STREAMED     TPS=0.2614
```

Identical to the object-override run, so the earlier result was not an artifact of how it was linked.

Shipping binaries are **mixed**, and are recorded rather than assumed:

```text
rawr-server.exe        12:11:12   AFTER the fixed lib   -> carries the fix
RawrXD-Win32IDE.exe    11:57:55   AFTER the fixed lib   -> carries the fix
rawr.exe               11:39:11   BEFORE the fixed lib  -> does NOT carry it
RawrXD-Win32IDE.exe    11:26:21   BEFORE (stale copy)   -> does NOT carry it
rawr-server.exe        10/3 03:39  stale copy           -> does NOT carry it
deep2_streamer_cert.exe 02:17:30  predates all of it
```

`rawr.exe` is the CLI (`rawr dump`, `rawr modes`, gate verifier) and does not run inference, so it
does not exercise the decode — but it is recorded as NOT adopted rather than argued away.

## 7. The canonical end-to-end test, run

`inference_authority_ladder` **is** a registered CMake target (CMakeLists.txt:18840,
`if(TARGET InferenceEngine)`), 3 TUs, linking the `InferenceEngine` target. It was built standalone
with `cl` so that no CMakeLists.txt was touched and no configure ran against a file another session
was editing:

```text
cl /nologo /std:c++20 /EHsc /O2 /MT /DNOMINMAX /I src /I %VULKAN_SDK%\Include /c
   inference_authority_ladder.cpp
   src/win32app/Win32IDE_ChatPanel.cpp      <- fails without /DNOMINMAX: windows.h
   src/win32app/Win32IDE_Core.cpp               min/max macros collide with std::min
link /OUT:inference_authority_ladder.exe <3 objs>
   InferenceEngine.lib rawrxd_remote64.lib
   dxgi.lib kernel32.lib user32.lib gdi32.lib ws2_32.lib bcrypt.lib ntdll.lib vulkan-1.lib
```

**CPU route** (`RAWRXD_LADDER_ROUTE=cpu`), `llama3.2-3b-Q2_K.gguf`, 12 tokens:

```text
G1 MODEL_LOAD            PASS  load_ms=707.0 hidden=3072 layers=28 vocab=128256
                               weight_type=Q2_K dominance=56.6% gpu_initialized=0
G2 TOKENIZATION          PASS  tokens=5 roundtrip_exact=1 all_in_vocab=1
G3 FORWARD_EXECUTION     PASS  warmup status=0 generated=1 detail=''
G4 NUMERICAL_CORRECTNESS PASS  greedy_runs_identical=1 tokens=12/12 all_in_vocab=1
                               status=0/0 first_ids=[9822,9822,9822]
G5 SAMPLING_CORRECTNESS  PASS  greedy_seed_invariant=1 tokens=12/12 (seeds 1 vs 999)
G6 TOKEN_STREAMING       PASS  reported=12 callback=12 agree=1 text_bytes=52
G7 IDE_DELIVERY          PASS  panel_messages=2 tokens_after=52 visible_bytes=52
                               contains_streamed=1
G8 PERFORMANCE           PASS  decode=0.224 tok/s tokens=12 wall=53617.3 ms
G9 CROSS_ROUTE_PARITY    FAIL  NO REFERENCE SUPPLIED (fails closed by design)
ROUTE=CPU GATES_FAILED=1  GPU_FALLBACK=0
```

The same G1–G8 PASS on two more models, chosen because they are dominated by the other two defects
this work fixed:

```text
Phi-3-mini-4k-instruct-q8_0.gguf   weight_type=Q4_0 dominance=99.4%   G1-G8 PASS
      G6 text='diff bid bid bid bid bid bid bid bid bid'
gemma3-1b-Q2_K.gguf                weight_type=Q4_0 dominance=56.5%   G1-G8 PASS
      G6 text='       , of of of of'
```

Phi-3-mini is 99.4% Q4_0. A wrong zero point or a wrong nibble pairing cannot produce 12 in-vocab
tokens, identical across seeds, twice, through the canonical harness. That is the end-to-end
validation of the Q4_0 fix; gemma3-1b covers Q4_0 and Q5_0 together.

**G9 was then given the reference it demands**, and produced a measurement instead of a shrug:

```text
RAWRXD_LADDER_ROUTE=cpu  RAWRXD_LADDER_EMIT=ref_cpu_q2k.txt
  emitted_greedy_tokens=12
  ref file: "9822 9822 9822 1 323 9822 1 323 330 9822 1 323"

RAWRXD_LADDER_ROUTE=vulkan  RAWRXD_LADDER_COMPARE=ref_cpu_q2k.txt
G9 CROSS_ROUTE_PARITY  SOURCE_WIRED=1 RUNTIME_REACHED=1  FAIL
  ref_tokens=12 this_tokens=0 identical=0
  first_divergence_index=0  ref[0]=9822  this[0]=-1
```

**GPU route: all of G3–G9 FAIL, and the reason is deliberate.** The engine refuses rather than
mislabel itself (`Deep2Engine.cpp:7305-7319`):

```text
[PREFILL] forwardTokenAllLayers FAILED at prefill token 0 stage=dual_row_host_lane_refused route=0
[DualRowStrict] DUAL_ROW_HOST_LANE_REFUSED strict=1 ... reason=no_gpu_resident_lane_available
```

With `strictNoCpuFallback` set and no GPU-resident lane, it returns failure and removes the
`VulkanDualRow` label rather than executing the host lane under a GPU name. That is correct
behaviour and matches `AGENTS.md`'s `REAL_GPU_EXECUTION_REQUIRED_FOR_PASS`. The underlying gap is
`no_gpu_resident_lane_available` — **GPU weight residency is still unimplemented**, which is the
pre-existing open GPU gate in the ledger, not a regression from this work and not a quant-decode
defect. It cannot be closed by anything in this receipt.

```text
CANONICAL_E2E_EXECUTES            = YES  (it now builds, links and runs)
CANONICAL_E2E_CPU_ROUTE           = G1-G8 PASS on 3 models spanning Q2_K Q3_K Q4_0
                                     Q5_0 Q6_K Q8_0 F32
CANONICAL_E2E_G9                  = fails closed without a reference, and produces a
                                     real first-divergence measurement when given one
CANONICAL_E2E_GPU_ROUTE           = BLOCKED, deliberately, on GPU_WEIGHT_RESIDENCY
TEXT_COHERENCE                    = still unscored; Phi-3-mini and gemma3-1b also
                                     degenerate into repetition at 12 greedy tokens, so
                                     repetition is a property of these models at this
                                     length, not a decode signal
```

## 8. The GPU resident lane — what exists, and what it does not

Section 7 recorded the GPU route as blocked on `no_gpu_resident_lane_available`. That message is
about the **dual-row** lane, and it was the wrong conclusion to draw from it. `DEEP2_RESIDENT_FIRST`
was never set in any run above. With it set, a device-resident lane exists, runs on real hardware,
and on one model reproduces the CPU route token for token.

```text
DEEP2_RESIDENT_FIRST=1  RAWRXD_LADDER_ROUTE=vulkan
  VK_PHYS ordinal=0 AMD Radeon AI PRO R9700  discrete=1 localGB=31.86
  VK_PHYS ordinal=1 AMD Radeon RX 7800 XT    discrete=1 localGB=15.98
  BATCH9_VULKAN_INIT=DEVICE_BACKED devices=2 plan_active=0
  DIRECT_CROSS_PHYSICAL_DEVICE_IMPORT=UNPROVEN  PHYSICAL_DEVICE_GROUP_COUNT=7
  GPU_FORWARD_ENTER hidden=... loaded=1 vulkanEnabled=1 init=1 devices=2 layers=28
  GPU_FORWARD_STAGE=CONTIGUOUS_RANGE / ENSURE_ARENA / SET_EPOCH / GET_LAYER_WEIGHTS
                   / CHECK_WEIGHT_DATA / WEIGHT_DATA_OK / GPU_FWD_REF_OK / KV_SEQ_OK
```

`llama3.2-3b-Q2_K.gguf`, cross-route against the CPU reference this receipt already emitted:

```text
G1..G7  PASS      gpu_initialized=1   first_ids=[9822,9822,9822]  (identical to CPU)
G8      PASS      decode=4.986 tok/s  tokens=12  wall=2406.6 ms
G9      PASS      ref_tokens=12 this_tokens=12 identical=1
                    first_divergence_index=-1  ref[0]=9822 this[0]=9822
ROUTE=VULKAN  GATES_FAILED=0  GPU_FALLBACK=0  VERDICT=PASS

CPU route, same model, same prompt: 0.224 tok/s, wall=53617.3 ms
GPU resident route:                 4.986 tok/s, wall= 2406.6 ms        ~22x

Per-layer resident coverage:  GPU_FORWARD_ENTER=113
                              WEIGHT_DATA_OK = 3164 = 113 x 28 layers, exactly
                              GPU_FWD_REF_OK = 3164 = 113 x 28 layers, exactly
                              dual_row_host_lane_refused = 0
```

Every layer of every token went through the device-resident lane; nothing fell back.

### But it does not generalise, and the gate is NOT closed

Two more models, same harness, same cross-route method:

```text
MODEL                  ARCH     DOMINANT QUANT  RESIDENT LANE            G9 CROSS-ROUTE
llama3.2-3b-Q2_K       llama    Q2_K 42.6%      ran, 3164/3164 layers    PASS identical=1
gemma3-1b-Q2_K         gemma3   Q4_0 56.5%      ran, 3744 WEIGHT_DATA_OK FAIL first_divergence_index=0
                       slidingWindow=1                                   ref[0]=236743 this[0]=28622
Phi-3-mini-q8_0        phi3     Q4_0 99.4%      REFUSED, 0 layers        no tokens (this[0]=-1)
```

**gemma3-1b is the important one.** Both routes pass every functional gate, both produce 8 in-vocab
tokens, and they disagree on the **first** token. That is the ledger's standing
`GPU_GATE=FAIL` condition — "a GPU route that passed all eight functional gates while producing a
wrong top-1 token" — reproduced today, on a model whose quant decode is certified bit-exact. So the
decode being correct does **not** make the two routes agree, and text repetition is not what is wrong
here.

Hypothesis, stated as one and not asserted: `admission OK arch=gemma3 ... slidingWindow=1`. The CPU
route applies a sliding-window mask; if the resident lane applies full causal attention instead,
every token after the window boundary diverges while every gate still passes. Not measured — the
divergence is measured, this cause is not.

**Phi-3-mini** fails earlier and for a different, precisely-localised reason:

```text
[Deep2Engine] MLA_TENSOR name=blk.0.attn_qkv.weight shape=[3072,9216] type=2
GPU_FORWARD_FAIL_STAGE=WEIGHT_DATA_ATTN layer=0 wq=0000000000000000 wk=... wv=...
GPU_FORWARD_FAIL_STAGE=RANGE_OR_MULTIMAP
COMMITTED_FALLBACK_BLOCKED=1 STRICT_NATIVE_ABORT=1 VERDICT=FAIL stage=resident_first
```

Phi-3 ships a **fused `attn_qkv.weight`** (3072 x 3x3072). `GET_LAYER_WEIGHTS` resolves separate
wq/wk/wv and gets three nulls. That is a missing split, not a numerics problem, and it fails closed:
`STRICT_NATIVE_ABORT=1`, zero host-lane refusals, zero silent CPU substitution.

```text
GPU_RESIDENT_LANE_EXISTS              = YES  (DEEP2_RESIDENT_FIRST=1)
GPU_RESIDENT_LANE_VERIFIED_EXACT      = 1 model   (llama arch, G9 identical=1)
GPU_RESIDENT_LANE_NUMERICALLY_DIVERGENT = 1 model (gemma3, slidingWindow=1)
GPU_RESIDENT_LANE_UNSUPPORTED         = 1 arch    (phi3 fused attn_qkv, no split)
FALSE_GPU_SUCCESS_COUNT               = 0
HOST_LANE_GPU_MASQUERADE               = 0
VERDICT_PASS_REAL_GPU_EXECUTION       = NOT CLAIMED — one model, not the capability
```

The claim that survives is narrow: **a device-resident forward lane exists, runs on two discrete
GPUs, and is numerically exact against the CPU route on llama-arch models.** The claim that does not
survive is that GPU execution is available. Three models, three different outcomes, and the two
failures are real.

Also unresolved and newly in scope: `DIRECT_CROSS_PHYSICAL_DEVICE_IMPORT=UNPROVEN` with
`PHYSICAL_DEVICE_GROUP_COUNT=7` and `SAME_DEVICE_GROUP=0`. The lane dispatched across two devices
whose peer-memory capability was never established, so `devices=2` is not yet a claim about two
devices cooperating.

## 9. Gemma3 first-divergence isolation - the projection, not the window

The instrument needed for this already existed and was switched off. `RAWRXD_LADDER_PARITY` drives
the **host** probe, which on the GPU route emits only `EMBED`, `HIDDEN_FINAL`, `FINAL_NORM`, `LOGITS`
� 5 checkpoint names against the CPU side's 465. The attention-level device probe is
`VulkanParityGrid`, enabled separately:

```text
RAWRXD_VULKAN_PARITY_GRID=1
RAWRXD_VULKAN_PARITY_GRID_OUT=<file>       # per-layer, per-stage, device->host readback
RAWRXD_VULKAN_PARITY_DUMP_VECTORS=<dir>   # optional full-vector capture
```

With it on, the GPU route emits 16120 records for a 4-token run, every one carrying
`READBACK_VALID=1`, an independent `HASH2`, `POS`, `POS_SOURCE`, `ANCHORED` and `DISPATCH_SEQ`.

### The discriminator resolves to the projection branch

`gemma3-1b-Q2_K.gguf`, STEP=0, LAYER_0, CPU hash vs GPU hash:

```text
GPU_STAGE          COUNT    GPU_HASH           CPU_HASH           VERDICT
RMS_ATTN           1152     c07e26cd88d1b079   c07e26cd88d1b079   MATCH
Q_ROPE             1024     1393661e0b2d68e8   5c7e96a95229d10a   *** DIVERGES ***
K_ROPE             256      3ba2efd88774fac0   1976789d25c4a73f   *** DIVERGES ***
V                  256      cefd4eee3b3e53be   88e2d6d988157413   *** DIVERGES ***
ATTN_VALUE         1152     85ef19e176a3afb3   848f2e3bf0a6f3c3   *** DIVERGES ***
O_PROJ             1152     c8589df7ed0c2c52   5ac72eeeeb077a4e   *** DIVERGES ***
... and every stage after it
```

`RMS_ATTN` matches bit-exactly and the divergence begins at the Q/K/V projection output, which is
strictly **upstream of attention masking, attention scores and softmax**. So:

```text
SAME_INPUT_NORM + DIVERGENCE_AT_QKV_PROJECTION
    => projection / layout / decode, NOT attention-window semantics
SLIDING_WINDOW_HYPOTHESIS = REFUTED for this model, not merely unproven
```

Refuted on two independent grounds:

- **The window cannot bind.** `SLIDING_WINDOW=512` and the run has 5 prompt tokens with a handful of
  decode steps. There is no position from which a 512-wide window excludes anything.
- **It is upstream of the mask anyway**, as the table shows.

RoPE was also checked rather than assumed: `Q_ROPE` and `Q_PRE_ROPE` hash identically at `POS=0`,
which is correct (rotary is the identity at position 0) and would have read as "rope is a no-op".
At `POS=1` they differ (`0d2207e2cc182c79` vs `f65b65d052305a9c`), so rope is applied. That
suspicion was withdrawn on measurement.

The divergence is also gross, not a rounding artefact:

```text
CPU  Q_ROPE  MIN=-5.889  MAX= 5.654  MEAN= 0.0433  L2= 45.103
GPU  Q_ROPE  MIN=-28.452 MAX=33.300  MEAN=-0.1337  L2=183.477      ~4.07x the CPU norm
CPU  Q (pre-rope)  L2=133.352        GPU  Q_PRE_ROPE  L2=183.477
```

Identical input, ~4x output norm. FNV hashes are bit-exact so any difference registers, but this one
is a scale difference, not a last-ulp one.

### The fused-QKV hypothesis is refuted for gemma3

gemma3 ships **separate** projections, so it is not the Phi-3 case:

```text
blk.0.attn_q.weight      [1152,1024] type=2   (Q4_0)
blk.0.attn_k.weight      [1152,256]  type=2   (Q4_0)
blk.0.attn_v.weight      [1152,256]  type=6   (Q5_0)
blk.0.attn_output.weight [1024,1152] type=11  (Q3_K)
blk.0.attn_q_norm.weight [256]       type=0
blk.0.attn_k_norm.weight [256]       type=0
```

So the two GPU failures are genuinely different, as the matrix says: Phi-3 aborts on a null
wq/wk/wv because it *is* fused; gemma3 has the tensors and computes something else.

Two features are specific to gemma3 and both sit exactly where the divergence starts:

```text
HEAD_DIM=256          (llama3.2-3b is 128)
GQA_GROUP=4           numHeads=4 over kv_heads=1
attn_q_norm / attn_k_norm  [256] = HEAD_DIM   QK-norm, absent in llama
```

CPU Q norm falls 133.35 -> 45.10 across the QK-norm, which is what a per-head RMSNorm should do. The
GPU value rises to 183.48 instead. That is consistent with QK-norm not being applied on the resident
lane � stated as the next thing to measure, not as the answer.

```text
GEMMA3_FIRST_DIVERGENCE      = LAYER_0_Q_ROPE (and K_ROPE, V)
GEMMA3_INPUT_NORM            = MATCH (bit-exact)
GEMMA3_DIVERGENCE_IS         = UPSTREAM of mask/scores/softmax
GEMMA3_ROOT_CAUSE            = OPEN - next: per-projection decode parity on the
                                GPU lane, and whether attn_q_norm/attn_k_norm
                                are applied there at all
NEXT_DISCRIMINATOR           = emit the DEQUANTIZED attn_q.weight from both
                                routes and compare; that is weight-side and
                                independent of activations, so it separates
                                "the GPU decodes Q4_0/Q5_0 differently" from
                                "the GPU projects differently"
```

## 10. Weight-side parity � the GPU side is vindicated, the comparison was invalid

Two pieces of missing source, both added:

1. `RAWRXD_LADDER_PARITY_VEC_LAYER=<n>` in `inference_authority_ladder.cpp`. It calls
   `enableParityProbeFullVectors()`, which existed, was documented as the way to get exact activation
   values out of the engine, and had **no caller in the tree**. Without VEC records there is no input
   for an offline oracle; the scalar summaries cannot be inverted back into a vector.
2. `rawrxd/tools/projection_oracle.cpp` (`RAWRXD_GEMMA3_PROJECTION_ORACLE_001`) � computes
   `y = W * x` offline, with `W` dequantized by the **production registry** (already proved
   bit-exact for all ten corpus types) and `x` the CPU route's own `LAYER_0_ATTN_NORM` vector. Hash is
   FNV-1a 64 over the float bytes, identical to `Deep2Engine::parityHash`, so it is directly
   comparable with both probes' `HASH=` fields. No tolerance.

`gemma3-1b-Q2_K.gguf`, STEP=0, `x = LAYER_0_ATTN_NORM`, N=1152, hash `c07e26cd88d1b079` � the vector
the two routes are known to agree on bit-exactly:

```text
TENSOR=blk.0.attn_q.weight      TYPE=Q4_0 ROWS=1024 COLS=1152
  OFFLINE_L2=183.47665   GPU_L2=183.476649   <- agree to 7 significant digits
  OFFLINE_HASH=920f16e7c5ba0461            GPU_HASH=1393661e0b2d68e8
  CPU_L2=133.351949                        CPU_HASH=c59ac424e965847a

TENSOR=blk.0.attn_k.weight      TYPE=Q4_0 ROWS=256 COLS=1152
  OFFLINE_L2=205.692487   GPU_L2=205.692488
  CPU_L2=132.943126

TENSOR=blk.0.attn_v.weight      TYPE=Q5_0 ROWS=256 COLS=1152
  OFFLINE_L2=108.495211   GPU_L2=108.49521
  CPU_L2=173.491157
```

### What this establishes, and what it retracts

```text
GPU_L2 == OFFLINE_L2  on all three projections, across Q4_0, Q4_0 and Q5_0
    => the GPU lane's weight decode and projection are CORRECT
    => THE WEIGHT-SIDE HYPOTHESIS IS REFUTED for gemma3

GPU_HASH != OFFLINE_HASH, with L2 agreeing to ~7 digits
    => f32 accumulation order inside the GPU GEMV. Benign, and expected.

CPU_L2 differs from BOTH on all three, including V
    => V has no Q/K normalization to explain it
```

So the GPU resident lane is numerically the *closest* of the two routes to an independent reference
projection of the same input. The CPU route's `Q`/`K`/`V` checkpoints do not equal `W * x`.

**And that retracts the comparison I ran last turn.** `RMS_ATTN` matching and `Q_ROPE`/`K_ROPE`/`V`
diverging was read as "the GPU projection is wrong". But the CPU checkpoints are taken at a different
point in the layer than the GPU checkpoints � gemma3 applies `attn_q_norm`/`attn_k_norm`, and the GPU
grid has no `Q_NORM`/`K_NORM` stage at all, so `LAYER_0_Q_ROPE` on one side and `LAYER_0_Q_PRE_ROPE`
on the other were never the same quantity. The "gross ~4x divergence" in section 9 was comparing
post-norm against pre-norm.

Corrected statement of what section 9 measured: **the two routes' Q/K/V checkpoints are not directly
comparable, and the divergence there does not by itself indict the GPU.** It also does not exonerate
it � a missing QK-norm on the resident lane would produce exactly this picture.

```text
GEMMA3_ROOT_CAUSE_CLASS     = QK_NORM_MISSING_ON_RESIDENT_LANE (leading)
                              vs CPU_CHECKPOINT_PLACEMENT (competing)
                              NOT weight decode -- refuted
NEXT_EXECUTABLE_GATE        = add Q_PROJ_RAW / Q_NORM / K_PROJ_RAW / K_NORM / V_PROJ_RAW
                              to BOTH probes, then re-run this oracle
```

A caveat that must not be dropped: `blk.0.attn_output.weight` was not compared, because its COLS is
1024 and it consumes the attention output, not `ATTN_NORM`. The oracle reports
`INPUT_SHAPE_MISMATCH` for it rather than silently skipping. It needs the `ATTN_VALUE` vector as
input, which the VEC dump also contains.

## 11. Elementwise gate � the L2 agreement was a coincidence, and the projection is wrong

The qualification on L2 was correct and it reverses the previous section's conclusion.
`RAWRXD_VULKAN_PARITY_DUMP_VECTORS` writes `<layer>_<STAGE>.bin` as `uint32 count` then
`float32 payload[count]` (verified: bytes `00 04 00 00` = 1024, float at offset 4 = 14.20328).
The elementwise metrics below are `projection_oracle.cpp` against that dump.

```text
TENSOR                 TYPE  L2_REL_GAP  L2_AGREES  COSINE     RMSE   MAX_ABS  BLOCK-NORM TEST
blk.0.attn_q.weight    Q4_0  5.605e-09   1          0.4416     8.02    43.51   ARITHMETIC
blk.0.attn_k.weight    Q4_0  3.429e-09   1          0.3009    14.54    62.79   (1 block, n/a)
blk.0.attn_v.weight    Q5_0  1.114e-08   1          0.3762     8.62    48.00   (1 block, n/a)
blk.0.attn_output.weight Q3_K 2.651e-01   0          0.2198    11.79   105.29   (not head-divisible)
```

**Cosine 0.22�0.44 on all four.** Near-orthogonal. So the GPU projections are not elementwise equal
to an offline `W * x` over an input both routes agree on bit-exactly. The 8-digit L2 agreement is a
coincidence of aggregate scale, not evidence of correctness � and it is exactly the coincidence a
magnitude-only instrument is built to produce.

The oracle is validated by the CPU on the one projection whose semantics align on both sides:

```text
blk.0.attn_output.weight, input LAYER_0_ATTN_VALUE
  OFFLINE_HASH=5ac72eeeeb077a4e  OFFLINE_L2=327.436673
  CPU_HASH    =5ac72eeeeb077a4e  CPU_L2    =327.436673   BIT-EXACT
```

### Permutation or arithmetic

Cosine near zero with matching L2 has exactly two causes: wrong direction, or a permutation of the
right direction. Block norms settle it � a permutation preserves every block norm and destroys
cosine; arithmetic preserves neither.

```text
blk.0.attn_q.weight, BLOCK=256 (head_dim), NBLOCKS=4
  BLOCK_NORM_MULTISET_MAXDIFF=59.9012   BLOCK_NORM_REL=5.146e-01
  -> ARITHMETIC: the per-head norms differ too, so this is not a reordering
```

### Corrected state

```ini
GEMMA3_ROOT_CAUSE_CLASS      = GPU_PROJECTION_ARITHMETIC
WEIGHT_DECODE                = neither cleared nor convicted -- the L2 agreement that
                                 appeared to clear it does not survive a cosine test
CPU_ROUTE                    = VALIDATED, bit-exact on attn_output
GPU_PROJECTION_ELEMENTWISE   = FAIL on all four projections
QK_NORM_RESIDENT_LANE        = still OPEN, now downstream of a broken projection
CPU_CHECKPOINT_SEMANTICS     = still OPEN for Q/K (post-norm vs pre-norm)
GEMMA3_SLIDING_WINDOW        = REFUTED
GEMMA3_FUSED_QKV             = REFUTED
```

This also retires the "GPU is closest to the oracle" reading of the previous section. The GPU was
never closer to the oracle; the oracle's L2 and the GPU's L2 were similar numbers that happened to
be about the same size.

One measurement defect in this tool, recorded because it produced a spectacular false reading before
it was caught: the GPU dump reader assumed a 12-byte header. The file size is consistent with that
arithmetic only because an 8-byte ASCII trailer follows the payload, so the size check passed while
every float was read 8 bytes late and off the end of the data. The result was `RMSE=3.8e14`,
`MAX_ABS=1.2e16` and `COSINE=0.004` on values whose true range is +/-30 � text bytes reinterpreted
as floats. The count is now READ from the file instead of inferred from its length.

```text
A_SIZE_CHECK THAT PASSES ON A FILE WITH A TRAILING SECTION IS NOT A LAYOUT CHECK
READ THE LENGTH FIELD; DO NOT INFER IT FROM THE FILE SIZE
```

## 12. Coverage - all 115 local GGUF files `F32 Q4_0 Q5_0 Q8_0 Q2_K Q3_K Q4_K Q5_K Q6_K BF16`. All ten
have a reference decoder. No decoder was written for Q4_1, Q5_1, Q8_K, TQ1_0, TQ2_0 or any IQ type,
because nothing in the corpus needs one and an unexercised reference is an unverified claim.

```text
FILES_SCANNED                       = 115   (>1 MB, deduplicated, 32 blocks/type)
PARITY_ALL_TYPES_IN_THIS_FILE       = 77
DECODE_MISMATCH_FOUND               = 0
PARTIAL_PARITY_WITH_UNJUDGED_BYTES  = 0
UNJUDGED_TENSOR_BYTES_TOTAL         = 0
```

Zero decode mismatches and zero unjudged bytes across the whole corpus. The 38 remaining files
produced **no verdict at all**, and are inventoried rather than counted as passes:

```text
25  sweep.gguf / parity.gguf in bench_tmp* and bt_* trees
      -> "invalid GGUF metadata entry". Not valid GGUF; they are benchmark scratch
         files, not models. Not a decode question.
 2  Qwen3.8-27B-AD-Q4_K_M
      -> loader rejects token_embd.weight: "unsupported/malformed GGML tensor type
         or shape". A loader coverage gap for a newer arch. No decode verdict exists.
 2  Qwen3.8-Flash-Next-AD-IQ1_M-M64
      -> loader rejects blk.0.ffn_down_exps.weight (MoE expert biases). Same class.
11  DeepSeek-R1-Q4_K_M shards 00002..00011
      -> INTERMITTENT, NOT A FILE PROPERTY. Recorded here because it nearly became
         a false finding:
           * in a 115-file back-to-back sweep all 11 reported
             "CreateFileA failed for " — with an EMPTY filename in the message
           * re-run individually, all 11 reported PARITY_ALL_TYPES_IN_THIS_FILE
           * shard 00002 run 10 times in isolation: PARITY=10 FAILED=0
         The files open fine (GGUF magic present, 35.9 GB). The decode is
         certified for them; the loader's stability under load, and an error
         message that does not name the file it is about, are open defects.
```

That 38-file discrepancy is also the reason the first sweep reported 11 failures. A census that does
not re-run its own failures manufactures findings; the oracle itself never claimed a pass for any of
them — it reported `NO_VERDICT_MODEL_UNREADABLE`, which is the correct answer for a file it could not
read. The wrong number was produced by the sweep around it.

```text
A_CENSUS_THAT_DOES_NOT_RE_RUN_ITS_OWN_FAILURES_IS_NOT_A_CENSUS
AN_ERROR_MESSAGE_THAT_DOES_NOT_NAME_THE_FILE_CANNOT_BE_ACTED_ON
```

## 11. What is NOT claimed

```text
PASS_MEANS=every quant type in this file decodes bit-exactly to the format
           definition, and the engine consumed them and streamed tokens
PASS_DOES_NOT_MEAN=the model is any good
TEXT_COHERENCE_SCORED=0
QUANT_DECODE_STAGE=CLOSED_MEASURED for all 77 readable files in the corpus:
  0 decode mismatches, 0 unjudged bytes, all 10 in-corpus types covered
QUANT_DECODE_STAGE_ADOPTION=NOT CLAIMED — see below
```

Two of the three models produce **repetitive** text, including the Q4_K_M control that was never
broken. Repetition at 16 greedy tokens is therefore a property of these models at this length and
sampling, not a quant-decode signal, and this gate does not adjudicate it. The discriminator's
`looksLikeLatinWords` heuristic would call all three "letterish" and would have scored the
pre-fix output as `SHARED_REGRESSION`; it is not used here.

Not established, and stated rather than implied:

```text
TOOLS_REGISTERED_IN_CMAKE=NO   (CMake ownership in this tree is contested)
SHIPPING_BINARIES_RELINKED=NO  (QuantKernelRegistry.cpp compiled and linked
                                 standalone into the gate; the prebuilt
                                 InferenceEngine.lib in rawrxd/build/Release is
                                 stale and still carries the old decode)
CMakeLists.txt_IN_CMAKE_TARGETS=untouched
LOADER_GAPS_NOT_QUANT_DECODE=2 newer-arch models rejected at token load
LOADER_STABILITY_OPEN=11 shards intermittently fail to open under sweep load,
                                 with an empty filename in the error text
```

Source identity this measurement is pinned to (SHA256, re-checked after the runs):

```text
0129288990CA9D53B68A3F57DF867487B5D7E97F3422D3FA3054AD27C77D6854  tools/quant_format_reference.hpp
052EEA4084B1144C593C3EC5A8BD69517021BE5264CB1EBEA79885597B0197C7  tools/quant_block_oracle.cpp
DB2D962F3AE2FC4A046A414400256D4234E8F34B62F2393C990F839E8439A2E8  tools/quant_e2e_gate.cpp
984DBD52F6A6F6E01133A7F96EAF633EEDE65039F0996251035C1D40AB2B2160  src/deep2/QuantKernelRegistry.hpp
0258F9D88665E020CEA9C67925D70806AFFAD3CA675D796BEE48E92BCEBBDC4D  src/deep2/QuantKernelRegistry.cpp
```

Receipts: `_qoracle/receipt_q2k_BEFORE.txt`, `receipt_q2k_after_fix.txt`,
`receipt_q4k_control.txt`, `receipt_gemma_after_fix.txt`.

---

## 12. Tree observation, recorded without attribution

`git status` at the start of this session listed 6 modified paths; by mid-session it listed 14,
including `rawrxd/CMakeLists.txt` (mtime 11:07:40, ~26 s before an 11:08:06 clock read), which
this work never touched. Per `AGENTS.md` §7a.1 no writer, session, process or lock holder is
identified — only the observation and its effect. The effect that matters: **no CMake build was run
and no CMakeLists.txt was edited**, and the compile evidence here is standalone `cl`/`link` against
a stale prebuilt library, so a relink of `InferenceEngine` is required before any of this reaches
a shipping binary.

---

## 13. Retractions

```text
RAWRXD_Q2K_FIELD_ORDER_001            RETRACTED — inverted a correct layout into
                                                 an incorrect one
RAWRXD_Q5K_FIELD_ORDER_001            RETRACTED — the same class, opposite
                                                 direction; 2 of 10 structs were
                                                 inverted and only a census found
                                                 the second one
RAWRXD_Q2K_SCALE_WIDTH_001            "both arms poison" RETRACTED — the defect was
                                                 upstream of the unpack; the default 4-bit
                                                 arm is the spec-conformant one and is now
                                                 bit-exact
RAWRXD_Q4_0_ZERO_POINT_001            RETRACTED — hypothesis right, experiment could not
                                                 have passed; conclusion drawn for the
                                                 wrong reason
RAWRXD_Q5_0_ZERO_POINT_001            RETRACTED — same; "UNRESOLVED" was unnecessary, the
                                                 convention was specified all along
"18/22-byte blocks are NOT ggml's current Q4_0/Q5_0"   RETRACTED — they are exactly that
RAWRXD_QUANT_BLOCK_ORACLE_001 Q4_0/Q5_0 MISMATCH     RETRACTED — defect was in the reference
decode_q5_K "d1*(q-m1), reference is right,       RETRACTED — MY OWN first draft of the
production is wrong"                                  reference was wrong on the day it was
                                                    written; the bit-exact comparison caught it
                                                    in one run
"38 corpus files fail to load"                        RETRACTED — 25 are not valid GGUF, 4 are
                                                    newer-arch loader gaps, 11 were
                                                    transient sweep-load artifacts
                                                    (10/10 PARITY in isolation)
```

## 14. The pattern worth keeping

```text
TWO INDEPENDENT VARIABLES WERE WRONG. ONE WAS CHANGED. THE OTHER'S SYMPTOM WAS
READ AS THE VERDICT. THE CONCLUSION WAS CONFIDENT, SPECIFIC, AND WRONG — AND
THE SAME FAILURE WAS COMMITTED TWICE, IN THE SAME COMMIT.

A_CHANGE THAT CANNOT_PASS IS NOT A TEST OF THE HYPOTHESIS UNDER TEST.
A_REFERENCE THAT DISAGREES WITH PRODUCTION IS A FINDING ABOUT THE REFERENCE
  UNTIL THE REFERENCE IS CHECKED AGAINST THE SPECIFICATION.
SIZE CHECKS CANNOT SEE A FIELD-ORDER DEFECT. THE BLOCK IS 84 BYTES EITHER WAY.
  TWO OF THE TEN K/LEGACY STRUCTS WERE INVERTED. EYEBALLING TEN STRUCTS FOUND
  ONE; COMPARING ALL TEN TO THE SPECIFICATION FOUND BOTH.
VERIFY EVERY SHARED INPUT BEFORE BLAMING ONE SIDE. When Q5_K still mismatched
  after the field-order fix, d, dmin, scales[], qh[], qs[], the scale unpack and
  the fp16 conversion were each checked and each was identical. That is what
  proved the fault was in the reference I had just written.
AN INSTRUMENT I WROTE MYSELF WAS WRONG WITHIN THE SAME SESSION. Only bit-exact
  comparison surfaced it, because it is the only property of the pair that
  differed.
A_CENSUS_THAT_DOES_NOT_RE-RUN_ITS_OWN_FAILURES_MANUFACTURES_FINDINGS.
```

## 15. Next measurable steps

```text
0. REVISED BY MEASUREMENT, because �8 changed the order. The GPU lane is not
   "unimplemented"; it is implemented, exact on llama arch, and wrong or absent
   elsewhere. The two GPU items below are therefore defects, not construction.

1. GEMMA3 CROSS-ROUTE DIVERGENCE � now the highest-value GPU item, because the
   lane RUNS (3744 WEIGHT_DATA_OK) and every functional gate passes while the
   first token already differs from CPU (ref[0]=236743 this[0]=28622). The quant
   decode on that model is certified bit-exact, so the divergence is in the GPU
   forward, not in dequantization. First thing to measure: whether the resident
   lane applies the gemma3 sliding-window mask (`slidingWindow=1`,
   `arch=gemma3`) or full causal attention. The divergence is measured; that
   cause is a hypothesis.
2. PHI3 FUSED attn_qkv � `GET_LAYER_WEIGHTS` resolves split wq/wk/wv and gets
   three nulls for a fused [3072,9216] tensor. A split is missing. Fails closed
   with STRICT_NATIVE_ABORT=1, so it is a capability gap, not a false pass.
3. DIRECT_CROSS_PHYSICAL_DEVICE_IMPORT=UNPROVEN, SAME_DEVICE_GROUP=0 with
   devices=2. The lane dispatched across two devices whose peer-memory path was
   never established, so "two GPUs" is not yet a claim about two GPUs cooperating.
4. Relink `rawr.exe` (11:39) and the stale `RawrXD-Win32IDE.exe` (11:26) and
   `rawr-server.exe` (10/3) copies against the fixed library, then re-run
   `inference_authority_ladder` through each product surface rather than through
   a standalone build. The ladder binary used here was linked by hand precisely
   so that no CMakeLists.txt was touched while another session was editing it;
   that workaround should not be the permanent arrangement.
5. The two loader gaps are not quant or GPU work and should be their own gate:
   GGUFLoader cannot read token_embd.weight for Qwen3.8-27B-AD-Q4_K_M, nor
   blk.N.ffn_down_exps.weight (MoE expert biases) for
   Qwen3.8-Flash-Next-AD-IQ1_M-M64.
6. GGUFLoader.hpp:403 emits "CreateFileA failed for " with an empty filename under
   load. Cheapest item on the list: the error names no file, so it cannot be acted
   on.
7. Reference decoders for Q4_1, Q5_1, Q8_K and the IQ family remain unwritten.
   Nothing in the corpus needs them; the oracle already reports NO_REFERENCE,
   counts the bytes and refuses a clean PASS when one appears.
```
