# RAWRXD_NQB_REAL_WEIGHT_ORACLE_001 — measured state

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
| `BUILD_IDENTITY` | **PASS** — git head + content manifest embedded and printed |
| `CURRENT_TREE_COMPILE` | **PASS** — clean after the `LayerWeights` fix |
| `nqb_exec_defect_regression` | **11/11 PASS** |
| `nqb_weight_parity_probe` (all) | **255/255, `MAX_ABS=0`, `WEIGHT_DATA_PATH=PASS_ALL_TENSORS`** |
| `nqbraid_real_weight_oracle` | **`FAIL_LOGIT_DIVERGENCE`** — cosine 0.829853463 |

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
| baseline (stale binaries) | — | — | — |
| `headDim` 64 → 128 (derived, not defaulted) | 0.298 → **0.831** | 2.64 → **2.03** | 0 → **2** |

`llama.attention.head_dim` is not emitted by llama.cpp's GGUF writer, so the
converter silently wrote its default 64 into the file while the weights it
carried were 128-wide. Every structural check still passed: well-formed file,
255/255 tensors, all values finite, byte coverage exact. The damage appeared
only in logits.

## Weight identity (the localisation)

| Tensor | cosine | argmax match |
|---|---|---|
| `token_embd.weight` (394,002,432 el) | 0.999998393 | ✓ |
| `blk.0.attn_q.weight` | 0.999998469 | ✓ |
| `blk.0.attn_k.weight` | 0.999998466 | ✓ |
| `blk.0.attn_v.weight` | 0.999998458 | ✓ |
| `blk.0.attn_output.weight` | 0.999998467 | ✓ |
| `blk.0.ffn_gate.weight` | 0.999998456 | ✓ |
| `blk.0.ffn_down.weight` | 0.999998447 | ✓ |
| `output_norm.weight` | 1.000000000 | ✓ |

`COMPARED=8 MISMATCHED=0 VERDICT=PASS`

The GGUF path and the NQB path hold the same numbers to BF16 narrowing, so
**the residual logit divergence is in COMPUTE, not in DATA.** The next gate must
compare hidden states per layer/stage, not logits.

## RAWRXD_NQB_FIRST_BAD_STATE_001 — FIRST_BAD_STATE_IDENTIFIED

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
reporting threshold, on a **5-element** vector — the noisiest statistic in the
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

Everything downstream — scores, probs, value, residual, FFN, all 28 layers, the
logits — inherits that. `ATTN_PROBS` is where the divergence first became
*visible*, not where it began.

### Candidate cause, consistent with the evidence

llama3.2-3b carries **llama3 RoPE scaling** (`rope.freq_base=500000` plus a
scaling factor and an `original_context_length`). The braid arch meta carries
`ropeTheta` but **no rope scaling factor or original context length** — the
writer's own comment concedes the meta "does not carry" fields of that kind. A
route applying frequency scaling and a route applying bare theta would produce
exactly this signature: Q/K/V bit-identical, Q_ROPE/K_ROPE not.

This is a HYPOTHESIS. It is the next thing to test, and it is testable by adding
rope scaling to the arch meta and re-running. It is not established by the
measurement above, which localises the transform but not the cause.


- **`RAWRXD_NQB_DENSE_F32_PRESERVE_F32_001`** — the reader used to narrow every
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
- `nqb_weight_parity_probe.obj` at 17:58 against an `.exe` at 17:53 — MSBuild
  compiled the translation unit and never relinked

**The tree did not compile at all.** `Deep2Engine.cpp:1219` referenced
`lw.ffnGate`, `lw.ffnUp`, `lw.ffnDown`; the members are `wGate`, `wUp`,
`wDown`. A stale object file had been masking that for the entire session, so
every result above was produced by binaries that **could not be reproduced from
the current source**. Fixed, and the tree now compiles clean.

A consequence worth stating plainly: any gate certified in this tree before that
fix was certified against an implementation the source no longer describes. That
is the `BUILD_IDENTITY_AUTHORITY` item, and it is not theoretical here — it
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
