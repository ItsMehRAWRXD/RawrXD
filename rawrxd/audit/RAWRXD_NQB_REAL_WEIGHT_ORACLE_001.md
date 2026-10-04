# RAWRXD_NQB_REAL_WEIGHT_ORACLE_001 — measured state

Date: 2026-10-04
Model: `G:\~dev\rawrxd\models\llama3.2-3b-Q2_K.gguf`
Artifact: `G:\~dev\rawrxd\models\llama3.2-3b-real-q0.nqb` (12,857,017,048 B)
Prompt: `The capital of France is`

```
OBJECTIVE = first real-weight numerical oracle over shared source-tokenizer IDs
STATUS    = ORACLE RUNS AND MEASURES.  LOGIT DIVERGENCE IS REAL AND LOCALISED
            TO COMPUTE.  Weights are proven identical between the two paths.
```

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

## Standing caveats

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
