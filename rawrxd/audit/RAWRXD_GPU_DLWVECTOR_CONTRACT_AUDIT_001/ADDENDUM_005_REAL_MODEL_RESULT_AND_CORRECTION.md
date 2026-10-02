# RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT — ADDENDUM 005
# THE REAL MODEL RAN, AND IT CORRECTED MY OWN ANALYSIS

    AUDIT   = RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001
    DATE    = 2026-10-01
    MODEL   = G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf
             10364416768 bytes, magic GGUF, from
             mradermacher/DeepSeek-V2-Lite-Chat-GGUF, download exit 0
    RESULT  = the experiment ran, and it REFUTED ADDENDUM_002's impact claim

    THIS DOCUMENT CORRECTS A CONCLUSION I PUBLISHED EARLIER IN THIS AUDIT.

---

## 1. What was observed

    DEEP2_GPU_SELECT slot=0 ordinal=0 name=AMD Radeon AI PRO R9700
    BATCH9_VULKAN_INIT=DEVICE_BACKED devices=1
    EXPERT_CACHE_INIT slot=0 budgetBytes=8552185856
    MODEL=G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf
    VULKAN_REQUESTED=1
    STRICT_NO_CPU_FALLBACK=1
    INIT_OK=1
    LOAD_OK=0
    LOAD_STAGE=ATTN_HEAD_DIM_MISMATCH
    LOAD_MESSAGE=Deep2 currently requires equal attention.key_length and
                 attention.value_length.
    VERDICT=INCONCLUSIVE stage=load_model

The forward pass was never reached. The **load** was refused.

## 2. The reason, in source

`Deep2Engine.cpp:1376-1387`:

    // Explicit GGUF key/value length is authoritative for rectangular attention.
    const size_t keyLen   = metaSize("attention.key_length", 0);
    const size_t valueLen = metaSize("attention.value_length", 0);
    if (keyLen != 0 && valueLen != 0 && keyLen != valueLen) {
        diag->stageCode = 6;
        diag->stageName = "ATTN_HEAD_DIM_MISMATCH";
        diag->message = "Deep2 currently requires equal attention.key_length "
                        "and attention.value_length.";
        return false;
    }

`key_length != value_length` is the defining asymmetry of Multi-head Latent
Attention. Requiring them equal is a square-attention (MHA/GQA) constraint. So
the loader refuses exactly the geometry that identifies an MLA model, before
admission completes, before `useMLA` can be set, and before any attention code
runs.

## 3. Correction to ADDENDUM_002

ADDENDUM_002 concluded, from the control flow:

```ini
RUNMLATTENTIONHOST_RUNTIME_IMPACT = FATAL_FOR_ANY_MLA_MODEL
```

**That is wrong.** The runtime evidence places the failure strictly earlier:

```ini
CORRECTED
    MLA_MODEL_LOADS_IN_DEEP2          = NO
    REASON                            = key_length != value_length is refused at
                                       Deep2Engine.cpp:1380-1387
    REACHABLE_VIA_REAL_MODEL          = NOTHING
    COMPUTE_MLATTENTION_GPU_REACHABLE = NO
    RUNMLATTENTIONHOST_REACHABLE      = NO
    USE_MLA_SETTABLE                  = NO
    FAILURE_POINT                     = LOAD, not attention
    EARLIER_FAILURE_THAN_PREDICTED    = YES
```

What survives from ADDENDUM_002 is the structure of the chain, which was read
correctly but was attributed the wrong trigger. The chain is:

```text
DeepSeek-V2 GGUF  (key_length=192, value_length=128, per the model's published
                   qk_nope_head_dim=128 + qk_rope_head_dim=64 and v_head_dim=128)
      |
      X  Deep2Engine.cpp:1380   key_length != value_length  ->  return false
      |
   LOAD FAILS: ATTN_HEAD_DIM_MISMATCH
      |
   computeAttention / computeMLAAttentionGpu / RunMLAAttentionHost
      never entered
```

I asserted a fatal forward-pass abort. What actually happens is a refused load.
I inferred forward behaviour from a chain that the product never enters, and the
only reason the inference looked sound is that the static reasoning was
internally correct about a code path that real weights cannot reach.

## 4. Correction to the architectural finding

ADDENDUM_002 also reported:

```ini
HOST_MLA_IMPLEMENTATION = NONE
```

That was too weak. The accurate and considerably more serious statement is:

```ini
MLA_SUPPORT_IN_DEEP2 = NOT_LOADABLE

    The engine cannot load an MLA model at all. The failure is in the loader's
    geometry gate, not in attention. Every MLA-specific code path in the tree --
    computeMLAAttentionGpu, RunMLAAttentionHost, the MLA branch of
    computeAttention, VulkanCompute::RunMLAAttentionHost, the MLA geometry
    checks at Deep2Engine_GpuMoEMLA.cpp:344-359, ModelRegistry's deepseek2/
    deepseek32 admission entries -- is unreachable from real weights.
```

`ModelRegistry.cpp:75-77, 113-115` admits `deepseek2`/`deepseek32`/`deepseek4`
and `:250-258` validates MLA metadata, so the registry believes MLA is
supported. The loader contradicts it 1,100 lines earlier in effect. That
inconsistency is itself a finding: **the registry advertises an architecture the
loader refuses.**

## 5. What this does NOT change

The transfer-contract findings stand, on their own evidence:

```ini
TRANSFER_CONTRACT_IS_ELEMENTS         = RUNTIME_PROVEN  (ADDENDUM_003, real GPU)
3987_ARGUMENT_REJECTED_BY_BOUNDS      = RUNTIME_PROVEN
4024_ARGUMENT_REJECTED_BY_BOUNDS      = RUNTIME_PROVEN
MEMORY_CORRUPTION                     = NOT_OCCURRING
THE_REPAIR                            = CORRECT (ADDENDUM_004)
```

The repair is still correct and still worth having: the contract violation was
real, it was measured on real hardware, and leaving a known 4x-oversized
transfer in the tree would be indefensible the moment MLA becomes loadable.

What changes is its **production impact**, which is now measured as zero:

```ini
REPAIR_PRODUCTION_IMPACT = 0 TODAY
BECAUSE                  = the containing function is unreachable from real
                           weights
BECOMES_EFFECTIVE_WHEN   = the loader accepts key_length != value_length
```

## 6. The lesson, stated plainly

```ini
STATIC_ANALYSIS_CLAIM   = "fatal forward abort for any MLA model"
RUNTIME_OBSERVATION     = "load refused; forward never reached"
STATIC_ANALYSIS_RATING  = WRONG
CAUSE                   = a correct chain through unreachable code
DETECTED_BY             = running the experiment, not by reading harder
```

This is the fourth time in these audits that the reported or inferred state did
not survive contact with reality (`DownloadVector`, `ProjectionBisectResult`,
the stale `HasNonDriveColon` binary, and now this). The correction was only
possible because the experiment was actually run. Reading the chain a sixth time
would not have found it.

## 7. Ledger

    MLA_MODEL_OBTAINED               = 1
    MODEL_BYTES                      = 10364416768
    MODEL_ADMITTED                   = 0
    ADMISSION_REJECTION              = ATTN_HEAD_DIM_MISMATCH (stageCode 6)
    REJECTION_SITE                   = Deep2Engine.cpp:1380-1387
    FORWARD_REACHED                  = 0
    MLA_EXECUTION_PATH_REACHABLE      = 0
    ADDENDUM_002_IMPACT_CLAIM        = RETRACTED
    TRANSFER_CONTRACT_FINDINGS       = UPHELD
    REPAIR                           = CORRECT, production impact 0 today
    REGISTRY_ADVERTISES_MLA_BUT_LOADER_REFUSES = 1
    PRODUCTION_SOURCE_EDITS          = 4 call sites, 1 file (the authorised repair)