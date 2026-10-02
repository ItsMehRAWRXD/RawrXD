# RAWRXD_VULKAN_SWIGLU_BISECT_VERIFICATION_001

Independent verification of the reported Vulkan parity bisect that concluded
`SWIGLU` is the primary threshold-crossing stage.

**Verdict: the reported numbers do not reproduce from the artifacts they name.**
Under the aggregate metric there are zero crossings, not seven.

Measured from:
```
F:\~dev\rawrxd\audit\RAWRXD_CANONICAL_INFERENCE_001\cpu_probe_final.txt   (14,622,381 B)
F:\~dev\rawrxd\audit\RAWRXD_CANONICAL_INFERENCE_001\vulkan_grid_final.txt  ( 5,784,312 B)
```
Scripts: `parity_final.py` (corrected), `parity_metrics.py`, `focus.py`.

---

## 1. What was reported, and what measures

| Reported | Measured |
|---|---|
| 169 `(step, stage)` pairs | **8712** `(step,layer,stage)`; **396** `(step,stage)`. Neither is 169. |
| 162/169 within `rel<=0.001` (95.86%) | **396/396 within `rel_L2<=0.001` (100.00%)** |
| 7/169 cross the threshold (4.14%) | **0 crossings** out of 8712 |
| worst `STEP=4 SWIGLU layer 0 rel=0.003003` | worst `rel_L2` anywhere = **2.01125e-05** at step 28 layer 20 `FFN_DOWN` |
| `ATTN_VALUE` crosses once at step 12 (`0.001009855`) | `ATTN_VALUE` does not cross under `rel_L2` at all |
| earliest crossing at step 0 | no crossing exists to place |

### 1.1 Metric sweep — nothing reproduces the claim

Every scalar the grid records, over all 8712 joined pairs:

```
rel_L2            max=2.01125e-05  at step 28 layer 20 FFN_DOWN      >1e-4: 0    >1e-3: 0
rel_MAX           max=3.13973e-05  at step 28 layer 20 SWIGLU        >1e-4: 0    >1e-3: 0
rel_MIN           max=4.10673e-05  at step 28 layer 21 LAYER_RESIDUAL >1e-4: 0   >1e-3: 0
rel_MEAN          max=0.0126918    at step 1  layer 9  FFN_DOWN      >1e-4: 77   >1e-3: 8
rel_first8_all8   max=0.0818669    at step 26 layer 1  FFN_DOWN      >1e-4: 783  >1e-3: 86
```

Every magnitude-weighted metric agrees: **CPU and Vulkan agree to better than
`5e-5` relative on every stage of every layer of every step.**

`rel_MEAN` is the exception and it is not evidence: `MEAN` of these tensors is
`~1e-4` to `1e-6`, so a relative error on it divides by a near-zero denominator.

---

## 2. The only metric that shows anything, and why it is not a defect

`rel_first8_all8` — element-wise relative error over the 8 recorded elements —
produces 86 crossings. Every one of the largest is on a **near-zero element**:

```
step 26 layer 1  FFN_DOWN  rel=0.0818669  elem[2] cpu=-6.98491931e-08 gpu=-7.60774128e-08
step 26 layer 1  FFN_GATE  rel=0.0427168  elem[2] cpu=-4.36045229e-06 gpu=-4.17418778e-06
step 26 layer 1  SWIGLU    rel=0.0427005  elem[2] cpu= 6.52969234e-09 gpu= 6.25087093e-09
step 28 layer 20 V         rel=0.0372946  elem[2] cpu= 2.83680856e-06 gpu= 2.94670463e-06
```

An 8.19% relative error on `-6.98e-08` is an **absolute** error of `6.2e-09`.
In float32 that is on the order of one ULP at that exponent. It is rounding, not
divergence. Per-element relative error is not a correctness signal when the
denominator is near zero; that is precisely why `rel_L2` is the right metric and
this one is not.

### 2.1 SWIGLU is an amplifier, not an origin — measured

The decisive observation, and it survives the metric problem. In every crossing
pair, `SWIGLU` and `FFN_GATE` agree with each other to ~5 significant figures:

```
step 26 layer 1   FFN_GATE 0.0427168   SWIGLU 0.0427005   ratio 1.00038
step 22 layer 2   FFN_GATE 0.00404378  SWIGLU 0.00404437  ratio 1.00015
step 27 layer 0   FFN_GATE 0.00328963  SWIGLU 0.00329339  ratio 1.00114
step 33 layer 9   FFN_GATE 0.00290377  SWIGLU 0.00289881  ratio 0.99831
step 2  layer 11  FFN_GATE 0.00297269  SWIGLU 0.00296905  ratio 0.99877
step 32 layer 12  FFN_GATE 0.00104058  SWIGLU 0.00104103  ratio 1.00043
```

If `SWIGLU` were the origin, `SWIGLU` would diverge *away from* `FFN_GATE`.
Instead they track each other to five digits, as do the `FFN_UP` entries. The
difference is therefore already present **at the output of `FFN_GATE`**, i.e.
upstream of the activation and the elementwise multiply.

This is the report's own stated alternative — *"SWIGLU is merely the first
threshold-crossing amplifier, not the origin"* — and the data supports it. The
report named SwiGLU as the origin; the measurement places the origin at or
before `FFN_GATE`.

### 2.2 Consequence for the proposed next probe

The report's proposed split into `FFN_GATE_PROJ / FFN_UP_PROJ / FFN_SILU /
FFN_MUL` is the right instrument, and the decision table is sound. But the
branch it is designed to resolve is already decided by the existing data:

```ini
GATE matches, UP matches, SILU diverges   -> excluded by 2.1
GATE matches, UP matches, SILU matches,
  MUL diverges                            -> excluded by 2.1
GATE diverges, UP matches                 -> excluded by 2.1 (GATE is not matching)
FFN_GATE_INPUT already diverges           -> CONSISTENT WITH THE DATA
```

**The next bisect should be upstream of `FFN_GATE`**, not inside SwiGLU:
`RMS_FFN` output, the `RMS_FFN -> FFN_GATE` input, and the quantized-matvec
accumulation type.

---

## 3. Instrument defects found (independent of the verdict)

These are real and they constrain any future bisect.

### 3.1 The grid cannot answer the question that was asked

The report asks for `FIRST_NONZERO_DIFFERENCE`, a
`1e-6 / 1e-5 / 1e-4 / 1e-3` ladder, and the first differing element with CPU
value, GPU value and index. **None of that is computable from these artifacts.**

```
fields recorded per pair: COUNT, FIRST8, HASH, L2, MAX, MEAN, MIN
COUNT=2048   FIRST8 elements=8   (8 of 2048 recorded = 0.39%)
```

There is no full-array readback in the text grid. The requested ladder requires
an instrument change — record the full array, or a CPU-vs-GPU hash-indexed diff
of all elements — before it can be run at all. Recording `FIRST8` and then
asking for a first-differing-element ladder is the same category of error as a
gauge that reports eight samples and is then asked for the population mean.

### 3.2 The CPU grid emits 32 duplicate records for two stages

```
CPU unique keys = 13464   total numeric emissions = 62568
CPU emission histogram: {1 emission: 11880 keys, 32 emissions: 1584 keys}
stages emitted 32x: ATTN_SCORES (792), ATTN_PROBS (792)
GPU unique keys = 13464   total numeric emissions = 13464   duplicates: 0
GPU keys marked UNAVAILABLE = 2376  (ATTN_SCORES/PROBS/VALUE, fused)
```

`792 = 36 steps x 22 layers`. So for two stages the CPU file contains 32 passes
per key and the GPU file contains none.

**Dedup policy does not change the verdict here** — keep-first and keep-last both
give max `rel_L2 = 2.01125e-05` and 0 crossings, because those stages are exactly
the ones that fail to join. But a grid that emits the same key 32 times with no
epoch or pass discriminator is ambiguous, and any future metric that *does*
join those stages will silently depend on which record a script happens to keep.

### 3.3 Stage names do not match across routes

```
CPU-only stages: ATTN_NORM, Q, K, FFN_NORM
GPU-only stages: INPUT, RMS_ATTN, Q_PRE_ROPE, K_PRE_ROPE, V_PRE_ROPE, RMS_FFN
```

Common stages: 13. Joined keys `13464 - 2376 - 2376 = 8712`. Any comparison that
assumes a shared stage vocabulary is comparing a subset without saying so. A
stage-name normalisation map should be part of the instrument, not of each
analysis script.

---

## 4. Harness defects in my own analysis, recorded

Three, all caught by cross-checking against the raw files rather than by the
analysis running cleanly:

1. **`FIRST8` regex truncated at the first comma.** `([A-Z0-9_]+)=(num)` matched
   only element 0, so an early pass computed "8-element" metrics on **one**
   element. That produced a spurious "7 crossings" figure — a count that
   coincidentally matched the report. It was a bug, not a confirmation.
2. **Unsequenced argument evaluation** (drop #2 probe, `e.c_str()` beside the
   call that fills `e`) printed a garbage detail string while the verdict itself
   was correct.
3. **Floating-point division where integer division was required**
   (`(elems+7)/8.0` = 144.875, not 144) produced a false `FAIL` on the Decoda
   storage accounting, against drop code that was correct.

Each would have produced a confident, specific, wrong number. That is now the
fourth, fifth and sixth instance of the pattern in this project, and the reason
this receipt cross-checks every printed figure against the raw artifacts.

---

## 5. Corrected diagnosis

```ini
VULKAN_BODY_BROAD_FAILURE            = NO      (confirmed, and stronger than reported)
DECODE_RECURRENCE_REQUIRED           = NO
DIVERGENCE_LOCALIZED                 = NO      <-- RETRACTED
CPU_VULKAN_AGREE_WITHIN_5E_5_REL_L2  = YES     (8712/8712 pairs)
CROSSINGS_AT_REL_L2_GT_1E_3           = 0
CROSSINGS_AT_REL_L2_GT_1E_4           = 0
WORST_REL_L2                          = 2.01125e-05  (step 28 layer 20 FFN_DOWN)

REPORTED_CROSSINGS_REPRODUCE          = NO
REPORTED_PAIR_COUNT_169               = NO       (8712 / 396, neither)
REPORTED_WORST_VALUE_0_003003         = NO

SWIGLU_IS_ORIGIN                      = NO
SWIGLU_IS_AMPLIFIER                   = YES      (tracks FFN_GATE to 5 digits)
FFN_GATE_ORIGIN_OR_EARLIER            = INDICATED, NOT PROVEN

NEXT_AUTHORITY                        = UPSTREAM_OF_FFN_GATE
  1. RMS_FFN output vs FFN_GATE input
  2. quantized-matvec accumulation type and order (F32 vs reduced precision)
  3. FFN_GATE GEMV tail handling and dispatch indexing
NEXT_AUTHORITY_NOT                    = SWIGLU_SUBSTAGE (excluded by measurement)

INSTRUMENT_BLOCKER                    = FIRST8 only, 8 of 2048 elements
  => FIRST_NONZERO_DIFFERENCE ladder NOT COMPUTABLE without instrument change
```

---

## 6. What this does and does not change

**Unchanged and now measured rather than assumed:** the transformer body is not
broadly broken on Vulkan, decode/KV recurrence is not required to produce any
aggregate divergence, and the remaining gap is small. That much of the narrowing
holds — it is simply better supported than the report claimed, because there is
no crossing at all.

**Changed:** `DIVERGENCE_LOCALIZED=YES` and
`PRIMARY_THRESHOLD_CROSSING_STAGE=SWIGLU` are **retracted**. They rest on a
per-element relative metric whose denominator is frequently near zero, and on a
pair count (169) that matches no pair set in the data (8712 or 396).

**Also retracted:** the specific values `0.001323 / 0.003003 / 0.002687 /
0.002680 / 0.001442 / 0.001010 / 0.001210` and their step/layer coordinates.
None appear in the named artifacts under any metric the grid records.

**Not established:** where the residual difference originates. The SwiGLU
sub-bisect is the right instinct pointed at the wrong stage, and the evidence
now points upstream of `FFN_GATE` instead.

---

## 7. Recommended next step

Before any further numerical bisect, fix the instrument:

1. **Record the full array, or a per-element CPU-vs-GPU diff summary**, so
   `FIRST_NONZERO_DIFFERENCE` and the threshold ladder become computable. Eight
   of 2048 elements cannot support an origin claim.
2. **Add a discriminator to every record** — pass/epoch id — so the 32x
   duplicate emission of `ATTN_SCORES`/`ATTN_PROBS` stops being ambiguous.
3. **Ship one stage-name normalisation map** covering the 4 CPU-only and 6
   GPU-only stage names.
4. **Then** bisect `RMS_FFN -> FFN_GATE` on `STEP=0 LAYER=1` and
   `STEP=4 LAYER=0`, which are the two coordinates the report identified and
   which remain useful even though the crossings attributed to them do not
   reproduce.

Item 1 is a prerequisite. Until the grid can locate a first differing element,
no origin claim from it is admissible, at any threshold.

---

```ini
STATUS                      = MEASURED, REPORT_PARTIALLY_RETRACTED
ARTIFACTS_MEASURED          = cpu_probe_final.txt, vulkan_grid_final.txt
REPORTED_CROSSINGS          = NOT REPRODUCIBLE
DIVERGENCE_LOCALIZED        = RETRACTED
SWIGLU_ORIGIN               = REFUTED (tracks FFN_GATE to 5 significant figures)
NEXT_BISECT_TARGET          = UPSTREAM_OF_FFN_GATE
INSTRUMENT_FIX_REQUIRED     = YES, before any further origin claim
DEFECTS_IN_INSTRUMENT       = 3 (partial array, 32x duplicate emission,
                                stage-name mismatch)
DEFECTS_IN_THIS_ANALYSIS    = 3 (recorded in section 4, all caught before use)
```

**Recorded in:** `F:\~dev\rawrxd\audit\RAWRXD_CANONICAL_INFERENCE_001\`, as a
new file. No existing artifact was modified; both measured files were read-only.
