# RAWRXD_MLA_LOAD_AUTHORITY_001 — M5d LANDED, REASSESSMENT

    GATE   = RAWRXD_MLA_LOAD_AUTHORITY_001
    SCOPE  = M5d only (revive B66, wire it into the loader), acceptance still
             FALSE by design. Nothing else was attempted.
    DATE   = 2026-10-01
    HEAD   = 17b035412efc (working tree)

    RESULT = M5d landed, M0-M3 still closed, M4 still BLOCKED and now
             BLOCKED FOR A NAMED, MEASURED REASON. Zero regression on the
             control model.

---

## 1. What changed

### CMake

    src/deep2/Deep2B66RuntimeMeta.cpp  ADDED to INFERENCE_ENGINE_LIBRARY_SOURCES

`Deep2B66RuntimeMeta.cpp` was absent from every target, so the only correct
derivation of `useMLA` in the tree was not compiled. It now is.

While measuring this, the surrounding pattern was quantified:

    B-numbered .cpp files in src/deep2 : 56
    of which in CMakeLists            : 1
    NOT in CMakeLists                 : 55   (87.7 KB of uncompiled source)

Sibling `Deep2B70Receipt.cpp`, the only other consumer of the binder, is also
absent. This is the same structural pattern the project has already documented
once for `SingleWriterAuthority`: a stronger implementation that the build graph
does not reach.

### Loader (`Deep2Engine.cpp`)

One new block, immediately before the geometry gate:

- builds a `B66MetadataSource` from the loader's own accessors, resolving each
  key both arch-prefixed (`<arch>.<key>`, which is what `metaSize` uses) and bare
  (which is what the binder expects), across the 20 keys the binder reads;
- calls `B66RuntimeMetaBinder::bind()`;
- on a pass, populates `modelWeights.qLoraRank`, `kvLoraRank`, `qkNopeHeadDim`,
  `qkRopeHeadDim`, `vHeadDim`, `keyLength`, `valueLength` — fields that previously
  had **no assignment anywhere in live source**;
- prints a `MLA_METADATA` line so the values are observable;
- **does not** set `useMLA` for routing, and says why in the comment.

The geometry gate itself is unchanged in outcome, only in diagnostic. It still
returns false for rectangular attention, keeps the existing
`ATTN_HEAD_DIM_MISMATCH` stage name for compatibility, and now names which gate
milestone is unmet.

## 2. Measured: control model must be unchanged

    [Deep2Engine] MLA_METADATA arch=llama qLoraRank=0 kvLoraRank=0
                  qkNopeHeadDim=0 qkRopeHeadDim=0 vHeadDim=0
                  keyLength=0 valueLength=0 tensorsBound=0
    [Deep2Engine] admission OK arch=llama family=GENERIC_TRANSFORMER
                  moe=0 mla=0 recurrent=0 slidingWindow=0 quant=Q4_K(type 12)
    LOAD_OK=1
    HIDDEN_DIM=2048
    FORWARD_OK=1
    FORWARD_ROUTE=2
    FORWARD_GPU_COMMITTED=1
    FORWARD_FAILURE_STAGE=(none)

Identical to the pre-change baseline recorded in ADDENDUM_004 §5. A non-MLA model
binds zero MLA metadata, which is correct, and its behaviour is untouched.
**Zero regression.**

## 3. Measured: the MLA model, before and after

### Before (ADDENDUM_005)

    LOAD_STAGE=ATTN_HEAD_DIM_MISMATCH
    LOAD_MESSAGE=Deep2 currently requires equal attention.key_length and
                 attention.value_length.

### After

    [Deep2Engine] MLA_METADATA arch=deepseek2 qLoraRank=0 kvLoraRank=512
                  qkNopeHeadDim=0 qkRopeHeadDim=0 vHeadDim=0
                  keyLength=192 valueLength=128 tensorsBound=0
    [Deep2Engine] MLA_GEOMETRY_REFUSED arch=deepseek2 key_length=192
                  value_length=128 mlaMetadataParsed=1 tensorsBound=0
    LOAD_OK=0
    LOAD_STAGE=ATTN_HEAD_DIM_MISMATCH
    LOAD_MESSAGE=Rectangular attention: attention.key_length=192 !=
        attention.value_length=128. RAWRXD_MLA_LOAD_AUTHORITY_001: M0-M3 done,
        M5d done (MLA metadata parsed: qLoraRank=0 kvLoraRank=512
        qkNopeHeadDim=0 qkRopeHeadDim=0 vHeadDim=0), M5e outstanding (the 8 MLA
        projection tensors are not bound by this loader), so M4 cannot accept
        rectangular geometry without routing MLA into square code.

Same refusal, same stage name, but now: the architecture is named, the real
geometry is surfaced, one milestone is recorded as done, and the blocking one is
named. An engineer reading this diag now knows exactly what to build next instead
of being told two numbers must be equal.

## 4. Reassessment: the M5d result is smaller than it looks

The binder ran and `kvLoraRank=512` came through, so the revival works. But
**three of the five MLA geometry values are still zero**, and the reason is in
the file, not the code. A string scan of the first 48 MB of the GGUF:

| GGUF key | present |
|---|---|
| `attention.key_length` | yes |
| `attention.value_length` | yes |
| `attention.kv_lora_rank` | yes |
| `attention.head_count` | yes |
| `attention.head_count_kv` | yes |
| `rope.dimension_count` | yes |
| `attention.q_lora_rank` | **no** |
| `qk_nope_head_dim` | **no** |
| `qk_rope_head_dim` | **no** |
| `v_head_dim` | **no** |

So this conversion simply does not carry those four keys. It follows that:

```ini
M5d_STATUS = PARTIAL

    kvLoraRank is now parsed from metadata.
    qLoraRank, qkNopeHeadDim, qkRopeHeadDim and vHeadDim are NOT obtainable
    from this file's metadata under any key name the engine or the binder uses.
```

And `computeMLAAttentionGpu:344-346` requires all of them:

    if(!H||!heads||!qRank||!kvRank||!nope||!rope||!valueLen|| ...) return false;

So even a completed M5d plus a completed M5e would leave this model refused at
`computeMLAAttentionGpu:344` on these four values.

### The consequence for the gate

The missing dimensions have to be **derived from tensor shapes**, not read:

    qkNopeHeadDim = attnK_b.rows / numHeads
    vHeadDim      = attnV_b.rows / numHeads
    qkRopeHeadDim = keyLength - qkNopeHeadDim
    qLoraRank     = attnQ_b.cols   (the down-projection's input width)

That derivation reads the tensor table, so **M5e is a prerequisite of finishing
M5d**, not a parallel track. The two milestones collapse into one piece of work:

    M5d+M5e COMBINED: bind the eight MLA tensors, derive the four absent
                      dimensions from their shapes, populate useMLA, and only
                      then may M4 accept rectangular geometry.

## 5. Why acceptance is still correctly FALSE

Had M4 been switched on after this change, the model would load and then:

- `computeAttention:3689` would test `lw.useMLA || modelWeights.useMLA` — still
  false, because the tensors that would justify it are unbound;
- the MHA/GQA branch would run with a collapsed `headDim` over a model whose
  `attnQ_b`, `attnK_b`, `attnV_b` were never bound.

That is the wrong-result path this gate exists to prevent. The refusal is the
correct state today, and the diagnostic now proves why it is correct rather than
merely asserting it.

## 6. Ledger

    M0 REAL_MLA_GGUF_IDENTIFIED        = 1
    M1 ARCHITECTURE_RECOGNIZED         = 1  (arch=deepseek2, measured)
    M2 MLA_METADATA_PARSED             = 1  (kvLoraRank=512 measured via B66)
    M3 ASYMMETRY_PRESERVED             = 1  (192 vs 128, measured)
    M4 LOADER_EQUALITY_GATE            = 0  (BLOCKED, reason now named)
    M5 BUFFER_GEOMETRY_INDEPENDENT     = 0  (7 square sites still present)
    M5d MLA_METADATA_POPULATED        = PARTIAL  (1 of 5 values from metadata;
                                       4 absent from this GGUF)
    M5e MLA_TENSORS_BOUND              = 0
    M6 KV_LATENT_DIMS_FROM_METADATA    = PARTIAL
    M7 MODEL_LOAD_COMPLETES            = 0
    M8 USE_MLA_SELECTED                = 0
    M9 FORWARD_REACHES_MLA_DISPATCH    = 0
    M10 TARGET_PATH_WITNESS_EMITTED    = 0

    B66_COMPILED_NOW                   = 1
    UNCOMPILED_B_FAMILY_FILES          = 55 of 56  (87.7 KB)
    CONTROL_REGRESSION                 = NONE  (tinyllama byte-identical outcome)
    ACCEPTANCE_ENABLED                 = NO   (by design)
    WRONG_RESULT_PATH_INTRODUCED       = NO
    M5d_AND_M5e_NOW_SINGLE_UNIT        = YES  (shape derivation needs tensors)

## 7. What the next step actually is

Not "fix the loader." One unit of work:

1. bind the eight MLA tensors in the loader's per-layer tensor binder;
2. derive `qkNopeHeadDim`, `qkRopeHeadDim`, `vHeadDim`, `qLoraRank` from those
   tensors' shapes when metadata is absent, and cross-check against
   `keyLength`/`valueLength` — disagreeing values should refuse, not silently
   prefer one;
3. set `useMLA` only when all eight tensors are bound **and** all five geometry
   values are non-zero;
4. only then may M4 accept rectangular geometry, with the existing
   `mla_upload_contract_cert` result (the transfer calls were already repaired)
   becoming the thing it certifies in a production context.

The DeepSeek-V2-Lite file is already on disk at
`G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf`, so that step is
testable immediately when it is taken.