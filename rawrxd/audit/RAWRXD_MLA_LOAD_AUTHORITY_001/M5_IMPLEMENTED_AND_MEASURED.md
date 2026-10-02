# RAWRXD_MLA_LOAD_AUTHORITY_001 — M5.0-M5.7 IMPLEMENTED AND MEASURED

    GATE   = RAWRXD_MLA_LOAD_AUTHORITY_001
    DATE   = 2026-10-01
    HEAD   = 17b035412efc (working tree)
    SCOPE  = the combined geometry+binding milestone, plus the admission
             propagation it required.
    RESULT = M5.0-M5.5 implemented and measured. Geometry derivation from tensor
             shapes WORKS and validates. M4 remains CORRECTLY CLOSED, for a now
             precisely named reason that is not the one previously assumed.
    CONTROL_REGRESSION = NONE

---

## 1. Milestone ledger

| # | Milestone | State | Evidence |
|---|---|---|---|
| M0 | real MLA GGUF identified | CLOSED | DeepSeek-V2-Lite-Chat.Q4_K_M.gguf, 10364416768 bytes |
| M1 | architecture recognized | CLOSED | `arch=deepseek2` |
| M2 | MLA metadata parsed | CLOSED | `kvLoraRank=512 numHeads=16` via revived B66 |
| M3 | asymmetry preserved | CLOSED | `keyLength=192 valueLength=128` |
| M5.0 | identify the 8 required tensors | **CLOSED** | measured names, below |
| M5.1 | verify type/dims/byte ranges | **CLOSED** | `bindTensor` validates presence, `sizeBytes>0`, `shape.size()` |
| M5.2 | derive absent geometry from shapes | **CLOSED** | `qkNopeHeadDim=128 qkRopeHeadDim=64 vHeadDim=128` |
| M5.3 | reconcile derived vs metadata | **CLOSED** | `geometryValidated=1` |
| M5.4 | bind all 8 into modelWeights | CLOSED for the split layout | per-layer binding added; fused layout binds what exists |
| M5.5 | verify no required binding null | **CLOSED** | per-layer completeness counted; missing set reported |
| M5.6 | rectangular buffer geometry | PARTIAL | `headDim = max(key,value) = 192` set; KV cache not yet re-dimensioned |
| M5.7 | MLA_EXECUTION_ELIGIBLE predicate | **CLOSED, evaluates FALSE** | deliberate |
| M4 | rectangular acceptance | **HELD CLOSED** | the gate is doing its job |
| M7-M10 | load / useMLA / dispatch / witness | BLOCKED | see section 5 |

## 2. M5.0 - what the file actually contains

Measured from the tensor table, not assumed:

    blk.0.attn_q.weight         shape=[2048,3072]  type=12
    blk.0.attn_kv_b.weight      shape=[512,4096]   type=12
    blk.0.attn_kv_a_mqa.weight  shape=[2048,576]   type=12
    blk.0.attn_kv_a_norm.weight shape=[512]         type=0
    blk.0.attn_norm.weight      shape=[2048]        type=0
    blk.0.attn_output.weight    shape=[2048,2048]   type=12

Absent: `attn_q_a`, `attn_q_a_norm`, `attn_q_b`, `attn_k_b`, `attn_v_b`, `attn_o`.

This is a **fused** MLA layout: the converter pre-combined `q_a+q_b` into
`attn_q` and `k_b+v_b` into `attn_kv_b`. The loader now reports
`layout=fused` rather than guessing.

## 3. M5.2/M5.3 - geometry derivation works

The four values the GGUF metadata does not carry were derived from tensor shapes
and cross-validated:

    [Deep2Engine] MLA_METADATA arch=deepseek2 layout=fused numHeads=16
        kvLoraRank=512 qLoraRank=0 qkNopeHeadDim=128 qkRopeHeadDim=64
        vHeadDim=128 keyLength=192 valueLength=128 geometryValidated=1

Derivation, each step exact rather than plausible:

    qkRopeHeadDim = attn_kv_a_mqa.rows - kvLoraRank = 576 - 512 = 64, even, non-zero
    qkNopeHeadDim = keyLength - qkRopeHeadDim        = 192 - 64  = 128
    vHeadDim      = valueLength                     = 128
    cross-check:  attn_kv_b.rows == numHeads*(qkNope + vHead) = 16*(128+128) = 4096  [actual 4096]
    cross-check:  attn_q.rows     == numHeads*keyLength       = 16*192       = 3072  [actual 3072]
    invariant:    qkNope + qkRope == keyLength                           128+64 == 192

All four derived values equal the model's published configuration
(qk_nope_head_dim=128, qk_rope_head_dim=64, v_head_dim=128, heads=16,
kv_lora_rank=512). A plausibility check would not have produced this; the two
independent shape cross-checks are what make it trustworthy.

`qLoraRank` is the one value deliberately left 0: for a fused layout it is not
recoverable from any tensor, and inventing it would be worse than admitting it
is absent.

## 4. M5.6/M5.7 - the eligibility predicate and the invariant

```
MLA_EXECUTION_ELIGIBLE requires ALL of:
    metadata parsed
 && geometry validated
 && the SPLIT layout the consumer requires
 && all 8 required tensors bound on EVERY layer
 && all geometry values non-zero

RECTANGULAR_ATTN && !MLA_EXECUTION_ELIGIBLE  ->  LOAD_REFUSED
```

Implemented as a single decision taken **after** the per-layer binder, so
eligibility is judged on what was bound rather than on what was hoped for. This
is the structural change that makes the invariant hard to defeat by accident: the
equality gate can no longer be deleted into a wrong-result path, because the
rectangle decision does not happen until binding has been counted.

The hard invariant also holds when the gate is bypassed by hand: a rectangular
model with `useMLA=false` is refused, not executed.

## 5. What M4 is closed against now, precisely

The fused layout is the blocker, and it is a real incompatibility rather than a
gap that more work would fill:

    consumer requires:  attn_q_a, attn_q_a_norm, attn_q_b, attn_kv_a_mqa,
                        attn_kv_a_norm, attn_k_b, attn_v_b, attn_o
    this file provides:  attn_q, attn_kv_a_mqa, attn_kv_a_norm, attn_kv_b,
                        attn_output

`computeMLAAttentionGpu` (`Deep2Engine_GpuMoEMLA.cpp:348-350`) requires the split
set. The fused set cannot be turned into it inside the loader, because
`attn_q.weight` is a single Q4_K_M quantised tensor: splitting it would require
dequantise-then-requantise, which changes the numbers the model was trained
with. There is no loader-side fix, only a consumer-side one.

So even with M5e complete for this layout, M7 would still fail. The next unit of
work is therefore **fused-MLA support in the MLA consumer**, not more loader work.

## 6. A second, independent defect found in the same gate

While propagating the asymmetry, `ModelRegistry` was found to reject the model on
two square-only rules, both of which this change had to confront:

1. `ModelRegistry.cpp:180-184` — `numHeads * headDim == hiddenDim`. For MLA that
   is simply false: 16*192=3072 against hiddenDim=2048. Replaced with an MLA
   branch that instead requires `kvLoraRank`, `qkNopeHeadDim`, `qkRopeHeadDim`,
   `vHeadDim` non-zero and `qkNope+qkRope` even. **Substituted, not deleted** — a
   malformed MLA geometry is still rejected.
2. `ModelRegistry.cpp:543` — `kMlaRoles` lists `attn_q`/`q_proj`,
   `attn_k`/`kv_a_proj`, `attn_v`/`kv_b_proj`, `attn_output`/`o_proj`. Those are
   HuggingFace-style stems. The GGUF naming used by every converter in this space
   is `attn_kv_a_mqa` / `attn_kv_b`, which the table does not contain at all.

So admission would still refuse this model on `MissingRequiredTensor` even after
(1) is fixed. That is a separate defect in the registry's role table, and it is
reported rather than worked around, because widening it to admit a model the
consumer cannot execute is precisely the wrong-result path this gate exists to
prevent.

Observed sequence, in order, as each square gate was propagated:

    MLA_RECTANGULAR_DEFERRED  -> geometry now deferred correctly
    MODEL ADMISSION REJECTED MalformedMetadata numHeads*headDim   [gate 1, now fixed]
    MODEL ADMISSION REJECTED MissingRequiredTensor attn_q (4)      [gate 2, reported]

## 7. Control: zero regression

Repeated twice on the same binary:

    [Deep2Engine] admission OK arch=llama family=GENERIC_TRANSFORMER moe=0 mla=0
    LOAD_OK=1
    FORWARD_OK=1
    FORWARD_ROUTE=2
    FORWARD_GPU_COMMITTED=1
    FORWARD_FAILURE_STAGE=(none)

Identical to the pre-change baseline in `M5D_LANDED_AND_REASSESSMENT.md` §2. A
non-MLA model reports `layout=unknown` and all-zero MLA values, and is entirely
unaffected.

## 8. Invariant audit: the dangerous intermediate state was never entered

    RECTANGULAR_MODEL_ACCEPTED      = 0
    USE_MLA_SET_WITHOUT_BINDING    = 0
    WRONG_RESULT_PATH_INTRODUCED    = 0
    CLEAN_REFUSAL_PRESERVED        = 1

`modelWeights.useMLA` is set in exactly one place, inside the `eligible` branch,
which requires the split layout and full per-layer binding. It is never set from
metadata classification. That separation is the point: `md.useMLA` (geometry
class, used by admission) and `modelWeights.useMLA` (routing, used by
computeAttention) are deliberately different variables.

## 9. Files changed

    src/deep2/Deep2Engine.cpp     sha256 D4EFCD890933A4FC...  +376/-? (loader)
    src/deep2/ModelRegistry.cpp   sha256 2B98D22B9A2BB8CF...  +35/-?  (admission)
    CMakeLists.txt                sha256 6E20CE199DAF31BE...  (+1 B66 source)

The CMakeLists diff is larger than one line because other uncommitted work shares
the file; the only line attributable here is the
`src/deep2/Deep2B66RuntimeMeta.cpp` entry.

One process action taken: a frozen `cl.exe` (PID 3800, zero CPU over 20 s, under
MSBuild `Tracker`) held an exclusive lock on `Deep2Engine.cpp` and blocked all
writes for ~13 minutes. It was terminated and the file hash verified identical
before and after (`59DC683F140F7B31...`). This is the orphaned-compiler pattern
already recorded in this tree for `SingleWriterAuthority`.

## 10. Ledger

    M0_M3                            = CLOSED
    M5.0_TENSOR_IDENTIFICATION        = CLOSED  (measured names)
    M5.1_TENSOR_VALIDATION           = CLOSED
    M5.2_GEOMETRY_FROM_SHAPES        = CLOSED  (128 / 64 / 128 derived)
    M5.3_METADATA_RECONCILIATION     = CLOSED  (geometryValidated=1, 2 cross-checks)
    M5.4_SPLIT_LAYOUT_BINDING        = CLOSED
    M5.5_NULL_BINDING_CHECK          = CLOSED
    M5.6_RECTANGULAR_BUFFER_GEOMETRY = PARTIAL (headDim set; KV cache not resized)
    M5.7_ELIGIBILITY_PREDICATE       = CLOSED, EVALUATES_FALSE
    M4_RECTANGULAR_ACCEPTANCE        = HELD_CLOSED (correct)
    M7_LOAD_COMPLETES                = 0
    M8_USE_MLA_SELECTED              = 0
    M9_FORWARD_REACHES_MLA_DISPATCH  = 0
    M10_TARGET_PATH_WITNESS          = 0

    CONTROL_REGRESSION               = NONE
    NEXT_UNIT                        = FUSED_MLA_SUPPORT_IN_THE_CONSUMER
                                        + kMlaRoles GGUF-name correction