# RAWRXD_MLA_LOAD_AUTHORITY_001

    GATE   = RAWRXD_MLA_LOAD_AUTHORITY_001
    DATE   = 2026-10-01
    HEAD   = 17b035412efc
    RULE   = PASS requires M0-M10. No milestone may be inferred from a
             neighbouring one.
    STATUS = M0-M3 CLOSED, M4 BLOCKED, M5-M6 SCOPED, M7-M10 BLOCKED

---

## 1. Why this gate exists

`RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001` established, at runtime, that Deep2
refuses real MLA geometry during load:

    LOAD_STAGE=ATTN_HEAD_DIM_MISMATCH
    LOAD_MESSAGE=Deep2 currently requires equal attention.key_length and
                 attention.value_length.

That barrier is earlier than the transfer defect the audit was opened for, and it
is therefore the real production boundary. Everything downstream of it is
unreachable, which is why a genuine, measured, correctly-repaired defect had zero
production reachability.

## 2. Milestone ledger

| # | Milestone | State | Evidence |
|---|---|---|---|
| M0 | real MLA GGUF identified | **CLOSED** | `DeepSeek-V2-Lite-Chat.Q4_K_M.gguf`, 10364416768 bytes, magic `GGUF`, curl exit 0 |
| M1 | architecture recognized | **CLOSED** | `ModelRegistry.cpp:75-77, 113-115` maps `deepseek-v2`/`deepseek2-lite` -> `deepseek2` |
| M2 | MLA metadata parsed | **CLOSED** | `ModelRegistry.cpp:250-258` validates `kvLoraRank`, `qkNopeHeadDim`, `qkRopeHeadDim`; the diag object reported the parse reached the geometry stage |
| M3 | key/value asymmetry preserved | **CLOSED** | measured as preserved: the asymmetry is *why* the load was refused, not normalised away |
| M4 | loader does not impose equal dimensions | **BLOCKED** | `Deep2Engine.cpp:1380-1387` |
| M5 | dependent buffer geometry derived independently | **SCOPED**, not closed | section 4 |
| M6 | KV/latent dimensions from actual metadata | **SCOPED**, partly already true | section 4 |
| M7 | model load completes | BLOCKED | depends on M4 |
| M8 | `useMLA` selected from validated arch/metadata | BLOCKED | depends on M7 |
| M9 | first forward reaches MLA dispatch | BLOCKED | depends on M8 |
| M10 | target path witness emitted | BLOCKED | depends on M9 |

## 3. The standing constraint on M4

Recorded verbatim as a rule of this gate:

> Do not make M4 pass by deleting the equality check at `:1380-1387`. That check
> may be protecting downstream code whose buffer sizing, strides, KV layout,
> kernels and projection assumptions are all square-attention-specific. The
> inequality has to propagate through the geometry.

The census below was done first, for that reason.

## 4. Census: where the square assumption actually lives

### 4.1 The MLA execution path is already rectangular-aware

This is the most useful result in the census, and it materially de-risks M4.

    vulkan_compute.h:1583-1589
        DeviceBuf mlaKCache_{};
        DeviceBuf mlaVCache_{};
        uint32_t  mlaCacheCapacity_ = 0;

MLA has its own **separate K and V device caches**. On the MLA path the engine's
square `KVCache` is used only for position bookkeeping:

    Deep2Engine_GpuMoEMLA.cpp:77, 150, 175, 227, 329, 361
        const uint64_t epoch = kvCache ? kvCache->currentLength() : 0;
        const size_t  pos   = kvCache->currentLength();

`kvCache` is never written with K or V on that path. And MLA has its own rotary
implementation that already handles the split layout, `applyMlaRope`
(`:398`), rather than the shared stride-`headDim` `applyRoPE`.

So the MLA kernels, caches and rotary are not what the equality check is
protecting.

### 4.2 What the equality check *is* protecting: the non-MLA path

Seven distinct square-attention sites sit on the loader/metadata side, and they
are the real work for M4-M6:

| # | Site | Square assumption |
|---|---|---|
| 1 | `Deep2Engine.cpp:1380-1387` | the gate itself: `keyLen != valueLen` -> reject |
| 2 | `:1388-1392` | collapses the asymmetry: `headDim = keyLen` if nonzero, else `valueLen` |
| 3 | `:1427` | `rope.dimension_count` defaults to `headDim` |
| 4 | `:926-934` | `KVCache` allocated with a single `kc.headDim` |
| 5 | `:2497` | second `kc.headDim = modelWeights.headDim` assignment |
| 6 | `:2172-2192` | **head counts inferred by division**: `numHeads = lw.wq.rows / headDim`, `numKVHeads = lw.wk.rows / headDim` |
| 7 | `:959-962` | `qDim = numHeads*headDim`, `kvDim = numKVHeads*headDim` from one scalar |

`KVCacheConfig` confirms the single-dim shape:

    struct KVCacheConfig {
      size_t numLayers = 0;
      size_t numHeads  = 0;   // KV heads, not query heads
      size_t headDim   = 0;   // one value for both K and V
      size_t maxSeqLen = 0;
    };

Site 6 deserves emphasis. `numHeads` and `numKVHeads` are *derived* by dividing
weight row counts by the single collapsed `headDim`. Under MLA, `attnK_b.rows` is
`heads * qkNopeHeadDim`, not `heads * keyLen`, so that division would produce a
wrong head count and every downstream sizing would follow the error. A change that
merely stopped rejecting the model would therefore produce a *plausible-looking
but wrong* configuration, which is worse than a refusal.

## 5. What M4-M6 therefore require, concretely

Not a one-line deletion. In dependency order:

    1. carry the asymmetry through metadata: a keyHeadDim and a valueHeadDim,
       with headDim retained as a fallback only for genuinely square models
    2. replace site 2 so neither dimension is lost
    3. make site 6 (head-count inference) architecture-aware: it must not divide
       MLA projection row counts by a square headDim
    4. extend KVCacheConfig (sites 4, 5) to separate K and V dimensions, or prove
       the MLA path never stores into it and assert that
    5. make site 3 and site 7 take their dimensions from the asymmetric source
    6. re-verify that the MHA/GQA path, which is the check's real beneficiary,
       still refuses or still behaves identically for square models -- tinyllama
       is the control, and it already produces
       FORWARD_OK=1 / FORWARD_GPU_COMMITTED=1

A regression risk to name explicitly: steps 1-5 weaken a guard whose job is to
keep rectangular models out of square code. The mitigation is that after the
change a rectangular model should be routed to MLA code and a square model to
GQA code, and both paths need a test. Step 6 is not optional.

## 5b. SCOPE CORRECTION: M4-M6 are necessary but NOT sufficient

Discovered while preparing the M4 implementation. Two further blockers stand
between the loader and a working MLA forward, independent of the geometry gate.

### Blocker 2: the engine's own MLA metadata is never populated

`ModelWeights` declares the fields (`Deep2Engine.h:213-223`):

    size_t qLoraRank = 0;  size_t kvLoraRank = 0;
    size_t qkNopeHeadDim = 0;  size_t qkRopeHeadDim = 0;
    size_t vHeadDim = 0;
    size_t keyLength = 0;  size_t valueLength = 0;
    size_t keyLengthMla = 0;  size_t valueLengthMla = 0;
    bool   useMLA = false;

A repository-wide search for assignments to those names in live sources returns
**none**. The loader reads `attention.key_length` / `attention.value_length` into
locals (`:1378-1379`) and immediately collapses them into the single
`modelWeights.headDim` (`:1388-1392`); it never sets `keyLength`, `valueLength`,
`keyLengthMla`, `valueLengthMla`, or `useMLA`.

There is exactly one correct MLA metadata reader in the tree:

    Deep2B66RuntimeMeta.cpp:38-45
        m.qLoraRank  = u32get(s,"attention.q_lora_rank");
        m.kvLoraRank = u32get(s,"attention.kv_lora_rank");
        m.useMLA     = m.kvLoraRank>0 || arch.find("deepseek")!=npos
                                    || arch.find("kimi")!=npos;

and it is **absent from CMakeLists.txt**, so it is not compiled. Its only other
consumer is `Deep2B70Receipt.cpp:83`. So the one place that knows how to derive
`useMLA` is dead code, and the engine's own field stays `false` forever.

### Blocker 3: the MLA tensors are consumed but never bound

`computeMLAAttentionGpu` requires eight tensors to be present
(`Deep2Engine_GpuMoEMLA.cpp:348-350`):

    attnQ_a, attnQ_a_norm, attnQ_b, attnKV_a_mqa, attnKV_a_norm,
    attnK_b, attnV_b, attnO

A search for assignments to any of them returns **none**. They are only ever
read, by consumers that tolerate their absence:

    Deep2Engine.cpp:5667-5683   MARS weight placement (reads whatever is there)
    Deep2Engine.cpp:741-742     history accumulation
    Deep2Engine_GpuForward.cpp:2066-2072   GPU weight upload collection

Nothing binds them from the GGUF.

### Why this changes the sequencing, and why it is not a footnote

With only M4-M6 implemented, the loader would **accept** DeepSeek-V2-Lite:

    M7 model load completes  -> would become TRUE
    M8 useMLA selected       -> would remain FALSE, because useMLA is never set
    computeAttention         -> takes the MHA/GQA branch with a collapsed,
                                wrong headDim, over a model whose MLA tensors
                                were never bound

That converts today's **clean refusal** into a **plausible-looking wrong
result**. For an inference engine that is a strictly worse failure mode than the
one the gate exists to fix, and it would be a regression introduced by this work
rather than a pre-existing one.

So M4 cannot be made to pass in isolation. The acceptance must be *conditional*:

```cpp
accept rectangular key/value lengths ONLY IF
    kvLoraRank > 0                      // genuinely an MLA model, and
    qkNopeHeadDim, qkRopeHeadDim, vHeadDim are all populated, and
    useMLA is set true, and
    all eight MLA tensors are bound
otherwise
    keep refusing, with a diag that names which condition failed
```

Which means the milestone ladder needs two more entries, and they are larger than
the geometry work:

| # | Milestone | Size |
|---|---|---|
| M5d | populate `modelWeights` MLA metadata from GGUF (adopt B66's derivation, or bind B66 into the loader and copy its result) | small-to-moderate |
| M5e | bind the eight MLA tensors in the loader's tensor binder | moderate: new binder entries, per-layer, plus a presence check |

M5e is the reason this is a scope decision and not a continuation.

The transfer repair is not in M0-M10 and is not contingent on this gate:

```ini
TRANSFER_CALL_DEFECT_EXISTED       = YES
TRANSFER_CALL_REPAIR_CORRECT       = YES
DEFECT_REAL_MODEL_REACHABLE_BEFORE = NO
REPAIR_PRODUCTION_IMPACT_TODAY     = 0
REPAIR_BECOMES_EFFECTIVE_WHEN      = M7 passes
```

All three states are recorded separately so no later reader can conclude either
that the repair was unnecessary or that it fixed MLA inference.

## 7. Audit invariant this gate enforces

```ini
STATIC_CALLGRAPH_REACHABILITY != REAL_INPUT_REACHABILITY
```

Runtime impact may only be assigned to a downstream defect after:

```text
real model -> admitted -> loaded -> feature selected -> target path reached
           -> defect observed
```

This audit violated that invariant twice before catching it: once for
`DownloadVector` (a stale binary) and once for the MLA chain (unreachable code).
Both times the violation was invisible to reading and obvious to running.

## 8. Ledger

    M0 REAL_MLA_GGUF_IDENTIFIED            = 1
    M1 ARCHITECTURE_RECOGNIZED             = 1
    M2 MLA_METADATA_PARSED                 = 1
    M3 ASYMMETRY_PRESERVED                 = 1
    M4 LOADER_EQUALITY_GATE                = 0  (Deep2Engine.cpp:1380-1387)
    M5 BUFFER_GEOMETRY_INDEPENDENT         = 0  (7 square sites catalogued)
    M6 KV_LATENT_DIMS_FROM_METADATA        = PARTIAL  (MLA caches already
                                             rectangular; loader is not)
    M7 MODEL_LOAD_COMPLETES                = 0
    M8 USE_MLA_SELECTED                    = 0
    M9 FORWARD_REACHES_MLA_DISPATCH        = 0
    M10 TARGET_PATH_WITNESS_EMITTED        = 0
    MLA_KERNELS_ARE_RECTANGULAR_AWARE      = 1
    SQUARE_ASSUMPTION_SITES                = 7
    DELeting_THE_CHECK_ACCEPTABLE          = NO
    CONTROL_MODEL_FOR_REGRESSION           = tinyllama-1.1b-chat-v1.0.Q4_K_M
    CONTROL_BASELINE_OK                    = 1  (FORWARD_OK=1, GPU_COMMITTED=1)