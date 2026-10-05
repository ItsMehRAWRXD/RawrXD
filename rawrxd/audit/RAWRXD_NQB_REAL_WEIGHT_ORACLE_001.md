# RAWRXD_NQB_REAL_WEIGHT_ORACLE_001 â€” measured state

Date: 2026-10-04
Model: `G:\~dev\rawrxd\models\llama3.2-3b-Q2_K.gguf`
Artifact: `G:\~dev\rawrxd\models\llama3.2-3b-real-q0.nqb` (12,857,017,048 B)
Prompt: `The capital of France is`

```
OBJECTIVE   = first real-weight numerical oracle over shared source-tokenizer IDs
STATUS      = weights proven bit-identical across all 255 tensors
              logit parity still FAILS, localised to COMPUTE/METADATA
              all numbers below now reproduced from an identified build
```

## RAWRXD_CERT_BINARY_BUILD_IDENTITY_001

Every certification binary now carries a content-derived identity and prints it
before it measures anything:

```
CERT_NAME=nqb_weight_parity_probe
GIT_HEAD=b5b2796725c0630c11f50e6c83a1323dca64b59b
TREE_DIRTY=dirty
SOURCE_COUNT=9
SOURCE_MANIFEST_SHA256=ea3aa703552edf4fcbfc7a71c5dc5c340579bca394709975f6e89307b1b62576
BUILD_COMMAND_SHA256=...
BUILD_ID=148c6c8efb3e234f79e6f6f1787baabf6fb77fc21b1e7fc867cb870538eb2b04
FEATURE_MARKER_COUNT=5
```

The manifest is a SHA256 over the **content** of every source the target
compiles, not a timestamp. Every participating source is registered as a
`CMAKE_CONFIGURE_DEPENDS` entry, so editing one re-triggers configure and the
embedded identity changes with it.

**Falsification.** Appending one comment line to `Deep2Engine.h`:

```
MANIFEST_BEFORE   = eb7384868a68634d29cf1f9499a638ae49f903b464fed5b3b700651e8fe1d29e
MANIFEST_AFTER    = 46bf245e55f08fa63a0a3a3869b567f8439b49c1f0854b3448b417b27533f1b1
MANIFEST_CHANGED  = True
MANIFEST_RESTORED = eb7384868a68634d29cf1f9499a638ae49f903b464fed5b3b700651e8fe1d29e
RESTORE_MATCHES_ORIGINAL = True     (source length 92988 -> 92988)
```

Two implementation notes, both of which were silent failures first:

- `string(SHA256)` returns an **empty string with no diagnostic** on this CMake.
  Every manifest and build id would have been `""`, which compares equal for
  every input, so every binary would have certified itself against every other.
  `rawr_sha256_string()` stages the text to a file and uses `file(SHA256)`.
- A `.hpp` added via `target_sources` does not put its directory on the include
  path; the generated header must be added with `target_include_directories`.

Feature markers are the human-readable half, emitted as literals so a byte scan
of the finished exe can confirm the code was linked in:

```
RAWRXD_FEATURE_NQB_REVERSE_STREAM_V1
RAWRXD_FEATURE_NQF32BIND_V1
RAWRXD_FEATURE_HEADDIM_DERIVE_OR_FAIL_V1
RAWRXD_FEATURE_CONTEXT_GEOMETRY_REPORTED_V1
RAWRXD_FEATURE_CONVERTER_COMPUTED_VERDICT_V1
```

## Authority ladder, re-run from an identified build

| Step | Result |
|---|---|
| `BUILD_IDENTITY` | **PASS** â€” git head + content manifest embedded and printed |
| `CURRENT_TREE_COMPILE` | **PASS** â€” clean after the `LayerWeights` fix |
| `nqb_exec_defect_regression` | **11/11 PASS** |
| `nqb_weight_parity_probe` (all) | **255/255, `MAX_ABS=0`, `WEIGHT_DATA_PATH=PASS_ALL_TENSORS`** |
| `nqbraid_real_weight_oracle` | **`FAIL_LOGIT_DIVERGENCE`** â€” cosine 0.829853463 |

The sealed build reproduces the earlier F32 run **to every printed digit**:

```
LOGIT_COSINE=0.829853463   LOGIT_RMSE=2.06984302   LOGIT_MAX_ABS=8.17513943
REF_ARGMAX=9822            NQB_ARGMAX=12366       ARGMAX_MATCH=0  TOP5_OVERLAP=2
```

So `CURRENT_SOURCE_REPRODUCES_THOSE_RESULTS` moves from UNPROVEN to **PASS**.
The BF16 refutation and the 255/255 weight result are now statements about
reproducible source, not about whatever binary happened to be on disk.
`FIRST_BAD_STATE_001` is no longer blocked.

## Chain of gates, all measured

| Gate | Result |
|---|---|
| `q2k_layout_discriminator` (3 tensors, ~1536 blocks) | layout d-last **ADMISSIBLE**, d-first rejected |
| `q2k_dequant_probe` (attn_q / attn_k / ffn_gate) | 3/3 PASS, 0 NaN, 0 Inf, byte coverage exact |
| `gguf_to_nqb_converter` | 255/255 tensors, 3,212,749,888 elements, `FAILURES=0` |
| `nqb_reopen_parity_probe` | 255/255 reopened, 0 non-finite, `BYTE_COVERAGE=PASS` |
| `nqb_weight_parity_probe` **ALL 255** | `MAX_ABS=0`, `MIN_COSINE=1.0`, `ARGMAX_MATCH=255/255` |
| `nqbraid_real_weight_oracle` | runs both paths, **VERDICT=FAIL_LOGIT_DIVERGENCE** |

```
MODE=ALL_TENSORS declared=255
TENSORS_EXPECTED=255   TENSORS_COMPARED=255
TENSORS_MATCH=255      TENSORS_FAIL=0
ARGMAX_MATCH=255/255
MIN_COSINE=1.000000000 DEGENERATE_ALL_ZERO_TENSORS=0
MAX_MEAN_ABS=0         MAX_ABS=0
WEIGHT_DATA_PATH=PASS_ALL_TENSORS   VERDICT=PASS
```

`MAX_ABS=0` is not a tolerance result: the two paths hold **bit-identical**
weights for every tensor. The earlier cosine of 0.9999985 was entirely the
reader's bfloat16 narrowing, and that narrowing is now gone.

## Converter receipt (measured, verdict computed)

```
HEAD_DIM_DERIVED value=128 from hidden=3072 / heads=24 (key llama.attention.head_dim absent)
GGUF_TENSORS=255            CONVERTED=255          SKIPPED=0
ELEMENTS_TOTAL=3212749888   SOURCE_NONFINITE_VALUES=0
Q2K_SCALE6_FALSIFICATION_CONTROL=0
VOCAB_PRESENT_IN_GGUF=1     VOCAB_ENTRIES=128256   VOCAB_BYTES=5984600
FILE_SIZE_DECLARED=12857017048   FILE_SIZE_ONDISK=12857017048
READER_BF16_MAX_ABS_ERR=0.0417309
FAILURES=0                  VERDICT=PASS
```

## Oracle result

```
TOKEN_IDS_IDENTICAL=1 count=5
LOGIT_CAPTURE=PASS size=128256
FIRST_DIVERGENCE_STAGE=LOGITS
LOGIT_COSINE=0.830625132   LOGIT_RMSE=2.03173014   LOGIT_MAX_ABS=8.11559963
REF_ARGMAX=9822            NQB_ARGMAX=12366
ARGMAX_MATCH=0             TOP5_OVERLAP=2
VERDICT=FAIL_LOGIT_DIVERGENCE
```

## What was fixed, and what it moved

| Change | LOGIT_COSINE | RMSE | TOP5 |
|---|---|---|---|
| baseline (stale binaries) | â€” | â€” | â€” |
| `headDim` 64 â†’ 128 (derived, not defaulted) | 0.298 â†’ **0.831** | 2.64 â†’ **2.03** | 0 â†’ **2** |

`llama.attention.head_dim` is not emitted by llama.cpp's GGUF writer, so the
converter silently wrote its default 64 into the file while the weights it
carried were 128-wide. Every structural check still passed: well-formed file,
255/255 tensors, all values finite, byte coverage exact. The damage appeared
only in logits.

## Weight identity (the localisation)

| Tensor | cosine | argmax match |
|---|---|---|
| `token_embd.weight` (394,002,432 el) | 0.999998393 | âœ“ |
| `blk.0.attn_q.weight` | 0.999998469 | âœ“ |
| `blk.0.attn_k.weight` | 0.999998466 | âœ“ |
| `blk.0.attn_v.weight` | 0.999998458 | âœ“ |
| `blk.0.attn_output.weight` | 0.999998467 | âœ“ |
| `blk.0.ffn_gate.weight` | 0.999998456 | âœ“ |
| `blk.0.ffn_down.weight` | 0.999998447 | âœ“ |
| `output_norm.weight` | 1.000000000 | âœ“ |

`COMPARED=8 MISMATCHED=0 VERDICT=PASS`

The GGUF path and the NQB path hold the same numbers to BF16 narrowing, so
**the residual logit divergence is in COMPUTE, not in DATA.** The next gate must
compare hidden states per layer/stage, not logits.

## RAWRXD_NQB_FIRST_BAD_STATE_001 â€” FIRST_BAD_STATE_IDENTIFIED

`nqb_first_bad_state` (already present; wired to build identity this session)
uses the parity records `Deep2Engine` already emits from ~40 forward-pass sites
via `parityEmitLayer()`, keyed `STEP` + `CP=LAYER_<n>_<STAGE>`, plus
`enableParityProbeFullVectors(layer)` for element-wise pass 2. No engine change
was required.

```
EXACT_HASH_MATCHES=848  HASH_MISMATCHES=1626  COUNT_MISMATCHES=0
COARSE_FIRST_BAD_STEP=1  COARSE_FIRST_BAD_LAYER=0  COARSE_FIRST_BAD_STAGE=ATTN_PROBS
STAGE_MATCH=1 STEP_MATCH=1 LAYER_MATCH=1
FIRST_BAD_LAYER=0  FIRST_BAD_STAGE=ATTN_PROBS
VERDICT=FIRST_BAD_STATE_IDENTIFIED
```

### The pass-2 vectors show the real boundary is earlier than the verdict line

`FIRST_BAD_STAGE=ATTN_PROBS` is the first checkpoint whose cosine crossed the
reporting threshold, on a **5-element** vector â€” the noisiest statistic in the
set. The element-wise data shows a much sharper boundary:

| Stage | n | cosine | rmse | max_abs |
|---|---:|---:|---:|---:|
| `LAYER_0_ATTN_NORM` | 3072 | **1.000000** | **0** | **0** |
| `LAYER_0_Q` | 3072 | **1.000000** | **0** | **0** |
| `LAYER_0_K` | 1024 | **1.000000** | **0** | **0** |
| `LAYER_0_V` | 1024 | **1.000000** | **0** | **0** |
| `LAYER_0_K_ROPE` | 1024 | 0.834130 | 0.996580 | 8.50575 |
| `LAYER_0_Q_ROPE` | 3072 | 0.859680 | 0.966950 | 11.3875 |
| `LAYER_0_ATTN_SCORES` | 5 | 0.989867 | 2.543180 | 4.25631 |
| `LAYER_0_ATTN_PROBS` | 5 | 0.900139 | 0.185615 | 0.343851 |

Attention norm, and all three projections, are **bit-identical**. The first
transform that changes anything is **RoPE**:

```
ATTN_NORM_OUTPUT_HASH_MATCH=1
Q_OUTPUT_HASH_MATCH=1     Q_ROPE_OUTPUT_HASH_MATCH=0
K_OUTPUT_HASH_MATCH=1     K_ROPE_OUTPUT_HASH_MATCH=0
V_OUTPUT_HASH_MATCH=1

FIRST_BAD_TRANSFORM=ROPE          (not ATTN_PROBS)
```

Everything downstream â€” scores, probs, value, residual, FFN, all 28 layers, the
logits â€” inherits that. `ATTN_PROBS` is where the divergence first became
*visible*, not where it began.

### Candidate cause, consistent with the evidence

llama3.2-3b carries **llama3 RoPE scaling** (`rope.freq_base=500000` plus a
scaling factor and an `original_context_length`). The braid arch meta carries
`ropeTheta` but **no rope scaling factor or original context length** â€” the
writer's own comment concedes the meta "does not carry" fields of that kind. A
route applying frequency scaling and a route applying bare theta would produce
exactly this signature: Q/K/V bit-identical, Q_ROPE/K_ROPE not.

This is a HYPOTHESIS. It is the next thing to test, and it is testable by adding
rope scaling to the arch meta and re-running. It is not established by the
measurement above, which localises the transform but not the cause.


- **`RAWRXD_NQB_DENSE_F32_PRESERVE_F32_001`** â€” the reader used to narrow every
  tensor to bfloat16, including files that stored 32 bits per weight. Measured
  cost across the 3.21B weights: max abs error 0.0417309. Dense F32 now reaches
  the engine as float32; quantised formats still materialise as bfloat16.
- **BF16 was NOT the cause of the logit divergence.** Measured directly by
  removing the narrowing and re-running the oracle:

  | | BF16 reader | F32 reader |
  |---|---|---|
  | LOGIT_COSINE | 0.830625 | 0.829853 |
  | LOGIT_RMSE | 2.0317 | 2.0698 |
  | REF_ARGMAX | 9822 | 9822 |
  | NQB_ARGMAX | 12366 | 12366 |

  Same argmax, cosine identical to three decimals. The narrowing was a real
  defect and is fixed on its own merits, but it is not this failure. Anyone
  about to spend time on precision here should not.
- `RAWRXD_Q2K_SCALE6` switches the Q2_K scale unpack in a shipping kernel. The
  converter records which branch ran and refuses when it is active.
- Both engines now report the same geometry (hidden 3072, 28 layers, 24/8
  heads, headDim 128, ffn 8192, rope_theta 500000). One field still differs:
  `maxSeqLen` 2048 on the GGUF engine versus 131072 on the braid engine.

## Process defect found and worked around

Every binary in this chain was **older than its source** and MSBuild reported
them up to date:

- `nqb_reopen_parity_probe.exe` 17:02 vs `.cpp` 17:14
- `q2k_dequant_probe.exe` 16:31 vs `.cpp` 16:40
- `Deep2Engine.obj` predating both the `initialized = true` and `headDim`
  fixes, so `[NQBRAID] LOADED:` printed without `initialized=1` and `headDim=64`
- `nqb_weight_parity_probe.obj` at 17:58 against an `.exe` at 17:53 â€” MSBuild
  compiled the translation unit and never relinked

**The tree did not compile at all.** `Deep2Engine.cpp:1219` referenced
`lw.ffnGate`, `lw.ffnUp`, `lw.ffnDown`; the members are `wGate`, `wUp`,
`wDown`. A stale object file had been masking that for the entire session, so
every result above was produced by binaries that **could not be reproduced from
the current source**. Fixed, and the tree now compiles clean.

A consequence worth stating plainly: any gate certified in this tree before that
fix was certified against an implementation the source no longer describes. That
is the `BUILD_IDENTITY_AUTHORITY` item, and it is not theoretical here â€” it
reproduced four times in one session.

## Process failures in this session, recorded

Three produced confident wrong answers, and a fourth was mine:

1. **Stale object files.** Four separate instances. `Deep2Engine.obj` predated a
   source edit and the link succeeded, hiding the fact that the source did not
   compile at all (`lw.ffnGate`/`lw.ffnUp`/`lw.ffnDown` vs the real `wGate`/
   `wUp`/`wDown`). Closed by RAWRXD_CERT_BINARY_BUILD_IDENTITY_001.
2. **`size_t`-truncated accumulator.** `minCosine` declared inside a `size_t`
   list, so `MIN_COSINE=0.000000000` was reported while every tensor was at
   1.0. Caught only by cross-checking against named-mode output.
3. **Comparison of two never-populated operands.** An edit silently failed to
   apply (wrong working directory for `[IO.File]`), so a manifest comparison
   compared `""` against `""` and reported `RESTORE_MATCHES_ORIGINAL=True`.
4. **I overwrote a tracked source file.** I wrote a replacement
   `tools/nqb_first_bad_state.cpp` without first checking whether one existed.
   It did; the existing implementation was better than mine (it already used
   `parityEmitLayer` and therefore needed no engine change, and it already
   carried admissibility rules and a "zero records is FAIL, never PASS"
   constraint). I had also declared Phase 2/3 INCOMPLETE on the false premise
   that no activation taps existed. Restored from git before anything was built
   or measured from it.

Items 1-3 share one structure, which is now `include/authority/Measured.hpp`
(`RAWRXD_INPUT_AUTHORITY_001`):

    comparison logic
          |
          v
    reports something sensible
          |
          X
    inputs did not represent what the receipt claimed

`Measured<T>` makes `populated` the only thing that authorises reading `value`,
and `compareVectors`/`compareScalars` return `InvalidInput` rather than a
verdict when either arm was never observed. `InputAuthority` blocks a gate from
reaching PASS until presence, non-vacuity, provenance and coordinate agreement
are all independently established.

## Still open

- **RoPE scaling is the leading candidate but is UNPROVEN.** See the
  FIRST_BAD_STATE section above.
- `bitsPerWeight=3.20` for a dense-F32 artifact that stores 32 bits/weight:
  `OPEN / FINDING_VALID=1 / BLOCKS_CURRENT_EXECUTION_PARITY=0 /
  MUST_CLOSE_BEFORE_FORMAT_CERTIFICATION=1`
- `maxSeqLen` 2048 (GGUF engine) vs 131072 (braid engine) remains unexplained,
  and is now a secondary candidate given that RoPE is implicated.
- `seekTensor` / `loadTensor` are declared but not implemented.
- Phase 1 runtime geometry (effective context, KV stride, mask context) is not
  yet observed from inside either engine, so `MAX_SEQ_LEN_CAUSAL_FOR_THIS_REPLAY`
  is UNRESOLVED rather than assumed NO.

---

## RAWRXD_ROPE_LAYOUT_SELECTION_001 — ROOT CAUSE FOUND AND FIXED

### The defect

`Deep2Engine.cpp` selected the RoPE pairing convention from an architecture
table whose two categories were **transposed**:

```cpp
// BEFORE -- asserted the opposite of llama.cpp
//   NeoX rotated-half: llama/qwen/mistral/gemma
//   GPT-J adjacent:    gpt-neox/phi (legacy GGUF conversions)
const bool archIsNeoxRoPE =
    arch == "llama" || arch == "qwen" || ... ;
modelWeights.ropeNeoxStyle = archIsNeoxRoPE;      // TRUE for llama
```

llama.cpp derives this from the architecture id in `src/llama-model.cpp`:

| constant | meaning | architectures |
|---|---|---|
| `LLAMA_ROPE_TYPE_NORM` | adjacent / consecutive pairs `(i, i+1)` | **LLAMA**, Qwen2/3, Mistral, Baichuan, Yi, StarCoder2 |
| `LLAMA_ROPE_TYPE_NEOX` | rotated half `(i, i+rot/2)` | GPT-NeoX, StableLM, OLMo, Phi |

So `LLM_ARCH_LLAMA` was being given the GPT-NeoX convention. The braid path
never assigns `ropeNeoxStyle` at all, so it kept its default `false` and used
adjacent pairs — which is why the *braid* route matched llama.cpp and the *GGUF*
route did not. The two routes shared one `applyRoPE`, so the divergence was
purely in which branch they took.

### The fix

The table is now explicit rather than a silent default, is printed at load time
so it can be audited instead of trusted, and gained a **two-way** override
(`DEEP2_ROPE_LAYOUT=normal|neox`) — the previous override could only turn NeoX
off, so the incorrect default could never be observed as a deliberate choice.

```
[ROPE_LAYOUT_SELECTION] arch=llama resolved=NORMAL_ADJACENT_PAIR
                         expected_for_arch=NORMAL_ADJACENT_PAIR neox=0
```

### Measured effect — end to end

| Metric | Before | After |
|---|---:|---:|
| `LOGIT_COSINE` | 0.829853463 | **0.999981482** |
| `LOGIT_RMSE` | 2.06984302 | **0.0224236874** |
| `LOGIT_MAX_ABS` | 8.17513943 | **0.103215933** |
| `REF_ARGMAX` | 9822 | **12366** |
| `NQB_ARGMAX` | 12366 | 12366 |
| `ARGMAX_MATCH` | 0 | **1** |
| `TOP5_OVERLAP` | 2 | **5** |
| verdict | FAIL_LOGIT_DIVERGENCE | **PASS_WITH_TOLERANCE** |

Note `REF_ARGMAX` moved 9822 -> 12366: the **reference** was the wrong side.
Both routes now agree on 12366.

### First-bad-state, before and after

| | Before | After |
|---|---:|---:|
| `EXACT_HASH_MATCHES` | 848 | **2472** |
| `HASH_MISMATCHES` | 1626 | **2** |
| `COARSE_FIRST_BAD_STEP` | 1 | **4** |
| `COARSE_FIRST_BAD_LAYER` | 0 | **-1 (none)** |
| `COARSE_FIRST_BAD_STAGE` | ATTN_PROBS | **(none)** |
| step 0 (494 records) | DIVERGED | **BIT_EXACT** |
| step 1 (494 records) | DIVERGED | **BIT_EXACT** |
| step 2 (494 records) | DIVERGED | **BIT_EXACT** |
| step 3 (494 records) | DIVERGED | **BIT_EXACT** |
| step 4 (498 records) | DIVERGED | 497 exact / **1 diverged** |

All five prompt prefill steps are now bit-exact at every checkpoint.

### What remains

`FIRST_BAD_STATE_001` now exits 1 with a real, much smaller target:

```
STEP_CENSUS step=4 records=498 hash_match=497 hash_mismatch=1 DIVERGED
```

One record out of 498, in the **decode** phase rather than prefill. That is the
residual source of `LOGIT_RMSE=0.0224` / `MAX_ABS=0.103` — not BF16, not weights
(those are bit-identical), and not prefill. `STEP_KEYING_DEFECT` also remains
open: the coarse key still collapses records across steps, which is why step
keying is `STILL_OPEN_IN_PROBE`.

The `2048` vs `131072` context difference is demoted: it cannot explain a
divergence that was present at position 1 with identical theta and identical
pre-RoPE vectors, and prefill is now bit-exact regardless.

### Fifth stale-binary instance, caught by the mechanism built for it

The first oracle run after the fix returned the old numbers with no
`ROPE_LAYOUT_SELECTION` line at all. A byte scan settled it without reference to
timestamps:

```
nqbraid_real_weight_oracle : HAS_ROPE_LAYOUT_SELECTION=False
nqb_first_bad_state         : HAS_ROPE_LAYOUT_SELECTION=True
```

The oracle exe had linked the pre-fix `InferenceEngine.lib`. Relinked and
re-ran, and the numbers above are from the binary that verifiably contains the
change. This is the fifth stale-binary instance in this session and the first one
caught by content inspection rather than by noticing a number looked wrong.

---

## Bleeding stopped — two defects closed, residual localised

### CLOSED 1: `bitsPerWeight` metadata (was `OPEN / FINDING_VALID=1`)

The artifact announced `bitsPerWeight=3.20` while physically storing 32 bits
per weight. Diagnosis, by measurement rather than inspection:

```
[NQBRAID] BPW payload_bytes=12850999552 params=3212749888
          derived_bpw100=3200 header_bpw100=3200 MATCH
HEADER_BITS_FIELD_RAW=3200        FILE_SIZE_DECLARED=12857017048
FAILURES=0  VERDICT=PASS
```

The **writer was already correct** — a control conversion of
`tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf` produced `derived_bpw100=3200
header_bpw100=3200 MATCH`. The llama artifact had been written at 17:57 by a
converter binary that predated the fix; the source comment in
`tools/gguf_to_nqb_converter.cpp` records the whole history — *"THREE different
answers for bitsPerWeight on a dense-F32 file (160, 320, 0)"*.

Re-converted. Now:
```
[NQBRAID] OPEN: params=3212749888 bitsPerWeight=32.00 tensors=255
```
and the oracle is unchanged at `LOGIT_COSINE=0.999981482`,
`VERDICT=PASS_WITH_TOLERANCE` — no regression.

**Sixth stale-binary instance.** Same class as the previous five: correct source,
old binary, confidently wrong number. Caught by writing a measurement rather
than by reading the existing receipt, which is the argument for instrumenting
derived telemetry rather than trusting it.

`Nanof32BraidWriter::finalize()` now also prints payload bytes, param count,
derived bpw and header bpw side by side, so this class is visible in any
conversion receipt instead of needing a separate investigation.

### CLOSED 2: RoPE layout selection

See `RAWRXD_ROPE_LAYOUT_SELECTION_001` above. Logit cosine 0.8299 -> 0.99998,
argmax now matches.

### The residual, precisely bounded

```
EXACT_HASH_MATCHES=2472  HASH_MISMATCHES=2  COUNT_MISMATCHES=0
COARSE_FIRST_BAD_STEP=-1  COARSE_FIRST_BAD_LAYER=-1  COARSE_FIRST_BAD_STAGE=(none)

STEP_CENSUS step=0..3  records=494 each  hash_match=494  BIT_EXACT
STEP_CENSUS step=4    records=498        hash_match=497  hash_mismatch=1  DIVERGED

GGUF_NON_LAYER_RECORDS=94   NQB_NON_LAYER_RECORDS=94
NON_LAYER_DIVERGED=1        NON_LAYER_FIRST_STAGE=LOGITS
NARROW_TO=FINAL_NORM_OR_LM_HEAD_OR_LOGIT_POSTPROCESS
VERDICT=DIVERGENCE_AT_NON_LAYER_RECORD
```

Every layer output is bit-exact at every step, for all 28 layers. Of 94
non-layer records exactly one diverges, and it is `LOGITS`, by
`MAX_ABS=0.103` / `RMSE=0.0224` against logits of order 10 (~1%).

With tied embeddings (`TIE_EMBED=1`) and a bit-identical `token_embd`
(`MAX_ABS=0`, `ARGMAX_MATCH=255/255`), the remaining candidates are the lm_head
matmul, its logit postprocess, or float accumulation order. That is a far
smaller target than where this investigation started: a whole-model numeric
divergence has been reduced to one record out of 2,970 compared.

`STEP_KEYING_DEFECT` remains open and still limits how precisely the step-4
residual can be read.

### Still open, in closure order

1. `STEP_KEYING_DEFECT` — coarse key collapses records across steps
2. lm_head / logit postprocess divergence (`LOGITS`, 1 record)
3. `maxSeqLen` contract: GGUF engine 2048 vs model-declared 131072
4. `seekTensor` / `loadTensor` declared but not implemented
5. `AUTHORITY_REPLACEMENT_WITHOUT_DISCOVERY` — procedural, needs the
   discover -> inspect -> extend -> create sequence enforced

---

## Second bleeding round

### CLOSED 3: `RAWRXD_NQB_ROPE_TYPE_DERIVE_001` — the same defect in the metadata

Fixing the engine alone was not enough, and the intermediate state REGRESSED:

```
LOGIT_COSINE=0.829517   ARGMAX_MATCH=0   (was 0.999981 / 1)
```

Cause: `Nanof32BraidStreamer` gained a mapping from the format field
(`modelWeights.ropeNeoxStyle = (archMeta.ropeType == 1)`), and the converter was
writing

```cpp
archMeta.ropeType = 1; // NeoX for Llama-style models
```

— the *same transposed belief* the engine fix had just corrected. Field enum is
`0=none 1=NeoX 2=GPT-J(adjacent) 3=MLA`, so writing 1 for llama pointed the
braid route at rotated-half while the corrected GGUF route used adjacent pairs.
The divergence did not shrink; it changed sides. That is what a one-sided fix
looks like when the other side was carrying the error in metadata rather than in
code, and it is why the metadata had to be fixed before the parity could be
trusted.

Now derived from architecture and printed:

```
ROPE_TYPE_DERIVED arch=llama ropeType=2 resolved=NORMAL_ADJACENT_PAIR
```

Result: `ROPE_NEOX=0` on both routes, `LOGIT_COSINE=0.999981482`,
`ARGMAX_MATCH=1`, `TOP5_OVERLAP=5`, `VERDICT=PASS_WITH_TOLERANCE`, and the
layer census is unchanged (`2472` exact / `2` mismatched, steps 0-3 BIT_EXACT).

**Lesson recorded:** an architecture-derived constant has to be corrected in
every place it is expressed. This one existed as a C++ table in the engine AND as
an integer literal in a file format written by a converter; fixing one left the
other asserting the old truth.

### CLOSED 4: `RAWRXD_ARCH_CONTEXT_CONTRACT_001`

`loadModel` had:

```cpp
if (config.maxSeqLen == 0 || modelContext < config.maxSeqLen)
    config.maxSeqLen = modelContext;
```

which can only ever SHRINK the operational context toward the model's declared
value. With the EngineConfig default 2048 and a model declaring 131072, neither
branch fires, so the engine silently ran at 2048 and nothing reported the gap —
the same "default quietly promoted to architectural fact" class as `headDim`.

The value is unchanged in behaviour (a cap below the model's ceiling remains a
legitimate choice) but is now stated rather than implied:

```
[CONTEXT_CONTRACT] MODEL_MAX_CONTEXT=131072 REQUESTED_RUNTIME_CONTEXT=2048
                  EFFECTIVE_RUNTIME_CONTEXT=2048
[CONTEXT_CONTRACT] OPERATIONAL_CAP_BELOW_MODEL_CEILING effective=2048 model=131072 ratio=0.0156
```

So the 64x difference is now a visible decision rather than an accident.

### Already resolved by prior work (verified, not assumed)

- `loadTensor` — removed, with the reason recorded: its `const bfloat16_t*` return
  type hardcoded the narrowed representation, so it could never have been a
  lossless accessor for a DENSE_F32 payload
- `seekTensor` — defined at `Nanof32BraidStreamer.cpp:457`, with
  `tools/nqb_seek_tensor_verify.cpp` as its check
- converter header completeness + census cross-checks — present, and they are
  what caught the stale `bitsPerWeight` artifact

### Residual, unchanged and still small

```
EXACT_HASH_MATCHES=2472  HASH_MISMATCHES=2
STEP_CENSUS step=0..3  BIT_EXACT
STEP_CENSUS step=4    497/498, 1 diverged
NON_LAYER_DIVERGED=1   NON_LAYER_FIRST_STAGE=LOGITS
VERDICT=DIVERGENCE_AT_NON_LAYER_RECORD
```

One record in 2,970. All 28 layers bit-exact at every step; `LOGITS` differs by
`MAX_ABS=0.103` / `RMSE=0.0224`. Weights bit-identical (`MAX_ABS=0`,
`ARGMAX_MATCH=255/255`), RoPE layout now agreeing, context contract now explicit.
Remaining candidates are the lm_head matmul, its logit postprocess, or float
accumulation order — plus `STEP_KEYING_DEFECT`, which still limits how precisely
the step-4 record can be isolated.

---

## Residual characterised: broad and uniform, not bad rows

`RAWRXD_NQB_LOGIT_RESIDUAL_LOCALISATION_001` — the oracle now reports the shape
of the per-element logit difference, because cosine/RMSE/max-abs say how far
apart two vectors are but not whether the gap is a few outlier rows (bad data)
or a broad bias (arithmetic). Those have different causes.

```
LOGIT_RESIDUAL elements=128256 exact=2 mean_abs=0.0177074
                   p50=0.0147095 p90=0.0369313 p99=0.0596490 p999=0.0764081
LOGIT_RESIDUAL_COUNT over_1e-1=2 over_1e-2=82618 over_1e-3=123537

LOGIT_WORST_ROW rank=0 idx=61487 ref= 3.33244681 nqb= 3.22923088 absdiff=0.103216
LOGIT_WORST_ROW rank=1 idx=83384 ref=-5.74254942 nqb=-5.84466600 absdiff=0.102117
LOGIT_WORST_ROW rank=2 idx=  4845 ref=-0.754498839 nqb=-0.655311286 absdiff=0.099188
LOGIT_WORST_ROW rank=3 idx=87194 ref=-5.80484867 nqb=-5.70612955 absdiff=0.098719
LOGIT_WORST_ROW rank=4 idx=  2389 ref= 1.48482919 nqb= 1.58176017 absdiff=0.096931
```

**96% of all logits (123,537 of 128,256) differ by more than 1e-3. Only two are
exact.** The worst row (0.1032) is barely worse than P99 (0.0596) — a factor of
1.7 — so this is a smooth distribution across the whole vector, not a few
damaged rows.

The differences are also not proportional to logit magnitude
(0.103/3.33 = 3.1%, 0.097/1.48 = 6.6%, 0.099/0.75 = 13%) and their signs are
mixed, so it is not a scale factor and not a constant bias.

Conclusion: this is a **broad, roughly absolute perturbation of order 1e-2**,
which is far too large for float32 accumulation noise over a 3072-term dot
product and far too uniform for corrupt data.

### What that rules in and out

Ruled out:
- weight differences (`MAX_ABS=0`, `ARGMAX_MATCH=255/255`)
- RoPE convention (now agreeing, `ROPE_NEOX=0` both sides)
- bad lm_head rows (the difference is not concentrated)
- per-row data corruption (uniform distribution)

Not yet ruled out, and now the leading candidates:
- the final-norm output is **not captured** by any parity record, so the last
  hidden state before the LM head is unverified. `FIRST_BAD_STATE` says
  `NARROW_TO=FINAL_NORM_OR_LM_HEAD_OR_LOGIT_POSTPROCESS`, and with all 28 layer
  outputs bit-exact, the divergence must be introduced after the last one.
- LM-head matmul dispatch differing between the two engines
- a logit postprocess applied on one route only

### Single next action

Emit a parity record for `FINAL_NORM`. It is the one boundary between
"everything verified" (last layer output, bit-exact) and "the first divergence"
(logits), and it is currently invisible. That is a three-line engine change plus
a rebuild; it converts the last open branch from a list of three into a single
measurement.

---

## RAWRXD_NQBRAID_FINAL_NORM_PARITY_001 — INSTRUMENTED, RESULT NOT YET ADMISSIBLE

### Authority boundary (restated precisely)

```
LAST_PROVEN_EQUAL      = LAST_LAYER_OUTPUT
FIRST_PROVEN_DIFFERENT = LOGITS
UNMEASURED_BOUNDARY    = FINAL_NORM
CANDIDATES             = FINAL_NORM | LM_HEAD_GEMV | LOGIT_POSTPROCESS
```

No claim is made that FINAL_NORM is bit-exact or that it is not.

### What was added

`parityEmitLayer(-1, "FINAL_NORM", layerTemp, H)` immediately before
`LinearW(modelWeights.lmHead, layerTemp, nullptr, logitsOut, V)`, so the captured
tensor is the actual buffer consumed by the LM head and not a recomputation.
Additive; `parityEmit(ParityCheckpoint::FinalNorm, ...)` left in place.

### What was observed — and why it is NOT a result

The record exists and is well formed:

```
STEP=4 CP=LAYER_-1_FINAL_NORM COUNT=3072 MIN=-26.7030811 MAX=10.9089365
       MEAN=0.00355748628 L2=82.1998049 HASH=a0212aaa596d007d
STEP=4 CP=FINAL_NORM            ... identical values and hash ...
```

Two problems make this inadmissible as evidence:

1. **Both records are at STEP=4 only.** The site is evidently reached once, not
   per step, so this does not give a per-step series. The deduped
   `parityEmit` also first fired at step 4, which means the final-norm path is
   not being taken during prefill at all. That is itself unexplained.

2. **`fbst_nqb.txt` does not exist.** Only `fbst_gguf.txt` is present
   (1,716,235 bytes, 21:31:39). Yet the run reported
   `GGUF_NON_LAYER_RECORDS=94` and `NQB_NON_LAYER_RECORDS=94`. Either the NQB
   parity file is written elsewhere, or the comparison consumed a file that is
   no longer there. Until that is explained, "both routes report 94 records" is
   not trustworthy, and neither is any per-stage comparison derived from it.

Reporting this rather than a parity verdict is deliberate: a gate whose inputs
silently fail to populate has produced confident wrong PASSes three separate
times in this session, and this is that shape.

### Next actions, in order

1. Resolve where `fbst_nqb.txt` is written and why it is absent.
2. Explain why the final-norm site is reached only at STEP=4 — whether prefill
   takes a different logits path, which would also mean the prefill LOGITS
   records come from elsewhere.
3. Only then re-run and read FINAL_NORM parity.

The double-precision reference dot-product gate
(`RAWRXD_NQBRAID_RESIDUAL_LM_HEAD_ACCUMULATION_001`) stays OPEN and is still
the right next *numeric* test — but it is worthless until the two parity files
above are accounted for, because it would be comparing operands whose provenance
is currently unverified.

---

## RAWRXD_NQBRAID_FINAL_NORM_PARITY_001 — PASS

### The provenance defect that preceded it (NEXT_1, NEXT_2)

The compare phase is COMPARE-ONLY: it does not run either route, it parses
whatever capture files are already on disk. That made a stale file
indistinguishable from a fresh one. Measured directly — a run whose NQB route
died mid-materialisation (`EXIT=-1`) left no `fbst_nqb.txt`, and the comparison
still printed a complete-looking

```
GGUF_NON_LAYER_RECORDS=94    NQB_NON_LAYER_RECORDS=94
```

from whatever was lying around. Both halves of that pair could not be true.

Fixed in `tools/nqb_first_bad_state.cpp`:

- each route now names its own sink after running
  (`PARITY_SINK_ROUTE/PATH/EXISTS/BYTES`, absolute path)
- the comparison **hard-fails before parsing** unless both captures exist and are
  non-empty, printing `COMPARE_INPUT_*` and returning
  `VERDICT=INVALID_MISSING_CAPTURE` with **exit 2** — deliberately distinct from
  a numeric verdict, because it is a statement about the instrument

Verified live: with the NQB capture absent the gate refuses instead of
reporting parity.

### FINAL_NORM parity — measured on the actual LM-head input

`parityEmitLayer(-1, "FINAL_NORM", layerTemp, H)` fires on the line immediately
before `LinearW(modelWeights.lmHead, layerTemp, ...)`, so this is the buffer the
kernel consumes, not a recomputation.

```
GGUF  STEP=4 CP=LAYER_-1_FINAL_NORM COUNT=3072 MIN=-26.7030811 MAX=10.9089365
      MEAN=0.00355748628 L2=82.1998049 HASH=a0212aaa596d007d
NQB   STEP=4 CP=LAYER_-1_FINAL_NORM COUNT=3072 MIN=-26.7030811 MAX=10.9089365
      MEAN=0.00355748628 L2=82.1998049 HASH=a0212aaa596d007d
```

**Bit-identical.** Same hash, same min/max/mean/L2, same first eight values.

```
RAWRXD_NQBRAID_FINAL_NORM_PARITY_001 = PASS
EXACT_MISMATCH_COUNT                 = 0
MAX_ABS                              = 0
```

### The boundary has moved

```
IDENTICAL_LM_HEAD_INPUT   = 1     FINAL_NORM, 3072 elements, HASH equal
IDENTICAL_LOGICAL_WEIGHTS = 1     255/255 tensors, MAX_ABS=0, ARGMAX 255/255
DIFFERENT_LOGITS          = 1     123,537 of 128,256 differ by >1e-3,
                                  P50=0.0147, P99=0.0596, MAX=0.1032

NARROW_TO = LM_HEAD_GEMV_OR_LOGIT_POSTPROCESS
```

So: **LAST_PROVEN_EQUAL is now `FINAL_NORM`, not `LAST_LAYER_OUTPUT`.**
Nothing remains unmeasured between the two proven-equal points. Whatever
separates the routes is inside the LM-head computation itself, and the double
precision reference dot-product gate
(`RAWRXD_NQBRAID_RESIDUAL_LM_HEAD_ACCUMULATION_001`) is now decisive rather than
exploratory: it will say whether one route is closer to the reference, or
whether the two simply straddle it by ordinary floating-point error.

### Also settled: the STEP=4 semantics

`FINAL_NORM` appears exactly once, in BOTH captures, at STEP=4 — and
`parityEmitLayer` contains no `emitted[]` dedup (it checks only `stepMode`), so
one record means the site genuinely executed once. The final-norm + LM-head block
is therefore a decode-step path; prefill logits for steps 0-3 originate
elsewhere. That is a real finding about the forward lifecycle rather than an
instrumentation artifact, and it is now recorded as such.
