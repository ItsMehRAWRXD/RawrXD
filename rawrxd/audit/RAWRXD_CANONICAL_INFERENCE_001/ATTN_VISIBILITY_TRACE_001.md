# RAWRXD_ATTN_VISIBILITY_TRACE_001 — state visibility, measured on the production path

```
GATE            = RAWRXD_ATTN_VISIBILITY_TRACE_001
DATE            = 2026-10-02
GIT_HEAD        = b81d3f1312727eb6ab1b7f2dd7ef7798fd5c9223   (worktree modified; see MODIFIED below)
DRIVER          = server_generation_parity.exe   (new CMake target, links the InferenceEngine TARGET)
DRIVER_SHA256   = 91BF8267D359A27271C2CA8EAD0DFB960BB87965D80364754AD5362C5D7F18D8
PRIMITIVE       = Deep2Engine::generateStream()  -- the production primitive the HTTP chat route uses
MODEL           = tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
PROMPT          = "What is the capital of France? Answer in one word."
PROMPT_IDS      = 1,1724,338,278,7483,310,3444,29973,673,297,697,1734,29889   (13 tokens)
SAMPLING        = temperature 0, topK 1, repeatPenalty 1, seed 0
```

This run does two things the previous measurement could not: it instruments the
production primitive rather than a `DecodeCursor`, and it anchors the Vulkan
parity grid's step identity to the authoritative KV position so per-step
comparison became possible at all.

---

## 1. The critical invariant, measured on the CPU production route

One `POS` record per logical position; one `POSLAYER` record per layer, so the
per-position verdict is an aggregate over all 22 layers and cannot be satisfied
by one healthy layer.

```
FRAMES                        = 36      (13 prefill + 23 decode)
POSLAYER_RECORDS              = 792     (36 x 22 layers)
FRAMES_WITHOUT_ATTENTION      = 0       (absence is explicit, never implied)
INV_WRITE_IS_NEWEST_VIOLATIONS     = 0
INV_READ_END_GE_WRITE_VIOLATIONS   = 0
INV_CTX_EQ_WRITE_PLUS1_VIOLATIONS  = 0
INV_MASK_END_GE_WRITE_VIOLATIONS   = 0
ALL_LAYERS_AGREE_VIOLATIONS        = 0
INV_POS_MATCHES_FRAME_VIOLATIONS  = 0
```

The position that produced the **first generated token** (the last prefill
position; in `generate()` the first sampled token's logits come from the final
prefill forward, not from a decode step):

```
STEP                       = 12
KV_POS_BEFORE              = 12
KV_WRITE_INDEX_K           = 12
KV_WRITE_INDEX_V           = 12
KV_HIGHEST_VALID_INDEX     = 12
ATTENTION_READ_BEGIN       = 0
ATTENTION_READ_END         = 12
ATTENTION_CONTEXT_LENGTH   = 13
MASK_VISIBLE_BEGIN         = 0
MASK_VISIBLE_END           = 12
PAST_TOKEN_COUNT           = 12
CURRENT_TOKEN_ID           = 29889
TOP1_TOKEN_ID              = 13
LOGITS_HASH                = 6430abd758177946
NEWEST_SLOT_VISIBLE        = 1
```

`MASK_IMPL=fused_full_causal` on the CPU route: no mask array exists there, the
causal bound is fused into the read loop. The field names the implementation's
mask; it does not report a mask that was never applied.

Prefill KV bookkeeping, same run:

```
PREFILL_FRAMES                  = 13
KV_LEN_AFTER_FINAL_PREFILL      = 13
KV_LEN_EXPECTED_AFTER_PREFILL   = 13
PREFILL_KV_LEN_CORRECT          = 1
```

### Consequence

```ini
NEWEST_SLOT_KV_NOT_VISIBLE = FALSIFIED_ON_THE_CPU_PRODUCTION_ROUTE
PREFILL_OFF_BY_ONE         = ABSENT_ON_THE_CPU_PRODUCTION_ROUTE
```

The second line closes the open question from
`DECODE_STEP_INSTRUMENTATION.md`, which reported
`PREFILL_TOKENS_FED=13 / KV_POS_AFTER_PREFILL=12 / PREFILL_CORRECT=0`. The write
happens at `keyPtr(layer, head, currentLen_)` and `advance()` then increments
past it, so 13 prefill positions end at 13. The `12` belonged to the
`DecodeCursor` harness. The retraction is confirmed by measurement, not by
argument.

This is a falsification, not a pass. It says the remaining CPU behaviour is **not**
a state-visibility defect, and must be explained further upstream or downstream.

---

## 2. The argmax lock did not reproduce, and that is a discrepancy, not a closure

```ini
GENERATED_TOKEN_IDS = 13,1576,7483,310,278,3303,3900,29973,13,29896,29889,
                      13,29906,29889,13,13,29896,29889,13,13,13,29896,29929,29889
TOKEN_COUNT         = 24
DISTINCT_TOKEN_IDS  = 12
DISTINCT_PIECES     = 12
IDS_REPEAT          = 0
VERDICT             = C_IDS_AND_PIECES_VARY
FINAL_TEXT          = "The capital of the United States?" then a numbered list
```

Every decode position carries a distinct `LOGITS_HASH` and a distinct `TOP1`.

The previously reported reproduction was `TOKENS = 11632,11632,17994 x22`,
`DISTINCT_TOKEN_IDS = 2`, `top1_logit = 5.37` at step 0. This run's step-12
`top1_logit` is `11.4626`. Those are not the same computation.

**This is not evidence that the earlier result was wrong.** What is missing is
the earlier run's binary identity and its prompt token ids; neither is recorded
in `DECODE_STEP_INSTRUMENTATION.md`, and the source tree has changed since.
Reconciling the two requires the prior binary hash, not a judgement call.
Until then both observations stand and the discrepancy is open.

Determinism of the current build was checked, because "it did not reproduce"
is only meaningful if the thing that did reproduce is stable:

```ini
RUNS_WITHOUT_TRACE   = 2   DISTINCT_TOKEN_IDS = 12, 12
RUNS_WITH_TRACE      = 1   DISTINCT_TOKEN_IDS = 12
TOKEN_SEQUENCE_IDENTICAL_ACROSS_ALL_THREE = YES
```

---

## 3. Vulkan parity-grid step identity: the defect that hid the defect

```cpp
int step = 0;   // initialised, mutable, NEVER ASSIGNED anywhere in the tree
```

`emit()` keyed on it, so `step` was 0 for the whole process. The
`(step, layer, stageId)` key added by the earlier layer-key fix therefore
degenerated back to `(layer, stageId)`, and 374 numeric records over 22 layers
described **one** token. A single-step agreement was read as an all-layer,
all-step agreement.

The grid is now anchored, not incremented:

```cpp
void anchorStep(int authoritativePos) { step = authoritativePos; }
```

called from the layer body with `kvCache->currentLength()` — the value
`AppendKV` writes to and whose successor `pos + 1` is handed to
`DispatchAttnDecode` as its context length. An unanchored grid refuses to emit
and says so:

```ini
STEP=-1 CP=LAYER_0_INPUT COUNT=2048 UNANCHORED=1
        NOTE=grid_step_never_anchored_to_authoritative_kv_position
```

After the fix, same run:

```ini
SUMMARY VALID_RECORDS=7480 UNSTABLE_RECORDS=0 PREMATURE_RECORDS=0
        READBACK_AUTHORITY=CERTIFIED
        ANCHOR_CALLS=440 MAX_POS=19 STEP_IDENTITY=AUTHORITATIVE_KV_POS
GRID_POSITIONS          = 0,1,2,...,19
GRID_UNANCHORED_RECORDS = 0
```

Two defects in this change were caught by the run rather than by reading:

1. The anchor was first placed next to the KV write, which is *after* the
   `INPUT` and `RMS_ATTN` emits. Two of the seventeen stages lost their identity
   on every position — the same class of failure as the unkeyed mask it
   replaced. The anchor now runs before the first emit in the layer.
2. `writeSummary()` existed with zero callers, so the grid's own
   self-certification line (G14) had never reached a file. `READBACK_AUTHORITY`
   had no measured instance behind it. It is now flushed via `atexit`.

---

## 4. K/V split: the cache is exonerated

Each K/V observation is FNV-1a over the **full** `kvDim` span in the slot's own
`[kvHead][headDim]` layout — the same quantity the CPU probe publishes as
`K_HASH` / `V_HASH`, so the two sides join on `(step, layer)` by exact hash.

```ini
PROJECTED_VS_CACHE_WRITTEN_COMPARED=80  HASH_MISMATCH=0  UNPAIRED=0
CACHE_WRITTEN_VS_READBACK_COMPARED =80  HASH_MISMATCH=0  UNPAIRED=0
SLOT0_SURVIVAL_CHECKS=38               MISMATCH=0
```

```ini
VERDICT = KV_WRITE_STORAGE_AND_READBACK_EXONERATED
```

- `PROJECTED -> CACHE_WRITTEN` is bit-identical: the Vulkan KV write copies
  faithfully.
- `CACHE_WRITTEN -> CACHE_READBACK` is bit-identical, taken *after* the attention
  dispatch: the bytes survive the kernel and the read-back path.
- `K_SLOT0_SURVIVAL` re-reads the slot the first prefill token wrote, at every
  later position, and matches the hash captured at write time 38 times out of 38.
  No later step overwrites an earlier slot.

The Vulkan K/V cache is not the defect. That branch of the discriminator is
closed.

---

## 5. Where the Vulkan divergence actually is

Join of the anchored grid against the CPU probe on `(step, layer, stage)`,
restricted to the prefill window. **The window matters:** from step 13 the two
routes have emitted different token ids and are computing different sequences,
so comparing them yields large, confident, meaningless numbers. 2618 grid
records were excluded for that reason and the count is reported rather than
dropped.

```ini
CPU_LAYER_RECORDS = 62604      GRID_VALUE_RECORDS = 7480
GRID_UNAVAILABLE_GAPS = 1320   (ATTN_SCORES / ATTN_PROBS / ATTN_VALUE have no device arena)
JOINED_RECORDS = 3718          VALID_MAX_POS = 12
STEP_STAGE_PAIRS_TOTAL = 169
STEP_STAGE_PAIRS_ALL_MATCH = 13          <- all 13 are step 0
STEP_STAGE_PAIRS_WITH_DIVERGENCE = 156
EARLIEST_DIVERGENT_STEP = 1
```

Layer 0, every prefill position. `CTX` is the number of visible slots.

| STEP | CTX | Q_ROPE rel | K_ROPE rel | V rel | **ATTN_VALUE rel** |
|---|---|---|---|---|---|
| 0 | 1 | 2.1e-07 | 3.3e-07 | 2.2e-07 | **2.2e-07** |
| 1 | 2 | 3.3e-07 | 3.5e-07 | 3.4e-07 | **1.8e-03** |
| 2 | 3 | 1.0e-07 | 4.1e-09 | 2.7e-08 | **3.9e-02** |
| 3 | 4 | 5.9e-07 | 4.6e-07 | 5.6e-07 | **4.1e-02** |
| 4 | 5 | 3.6e-07 | 2.1e-07 | 3.0e-07 | **3.6e-02** |
| 5 | 6 | 1.4e-06 | 1.3e-06 | 1.2e-06 | **9.2e-02** |
| 6 | 7 | 1.6e-06 | 1.6e-06 | 1.6e-06 | **1.5e-02** |
| 7 | 8 | 2.9e-07 | 2.5e-07 | 2.8e-07 | **9.1e-02** |
| 8 | 9 | 1.5e-07 | 1.6e-07 | 1.3e-07 | **1.4e-01** |
| 9 | 10 | 6.6e-07 | 8.9e-07 | 6.4e-07 | **9.8e-02** |
| 10 | 11 | 8.0e-08 | 2.2e-07 | 5.3e-08 | **5.0e-02** |
| 11 | 12 | 2.0e-07 | 1.7e-07 | 1.7e-07 | **4.0e-02** |
| 12 | 13 | 1.2e-06 | 1.3e-06 | 1.2e-06 | **3.0e-03** |

Every attention **input** is correct to float32 rounding at every position. The
attention **output** is correct at `CTX=1` and wrong from `CTX=2` onward, by
0.2% to 14%.

### The localisation

At layer 0, step 1: `Q_ROPE`, `K_ROPE` and `V` all match to ~3e-7; the cache is
proven to hold exactly those bytes (§4); the context length handed to the kernel
is `pos + 1` and the visibility invariants hold on the GPU too. The output of
`DispatchAttnDecode` is nevertheless 0.18% wrong, and `O_PROJ` faithfully
consumes that wrong value.

```ini
VULKAN_ATTENTION_SINGLE_SLOT_CONTEXT  = CORRECT
VULKAN_ATTENTION_MULTI_SLOT_CONTEXT   = WRONG_FROM_CTX_2
VULKAN_KV_PROJECTION                  = CORRECT
VULKAN_KV_ROPE                        = CORRECT
VULKAN_KV_CACHE_WRITE                 = CORRECT  (bit-identical)
VULKAN_KV_CACHE_READBACK              = CORRECT  (bit-identical)
VULKAN_KV_SLOT_SURVIVAL               = CORRECT  (38/38)
VULKAN_ATTENTION_CONTEXT_LENGTH_ARG   = CORRECT  (pos + 1)
VULKAN_FUSED_ATTENTION_KERNEL         = DEFECTIVE_FROM_TWO_SLOTS
```

`DispatchAttnDecode` is correct when it reads one slot and wrong as soon as it
must read more than one. That is a defect inside the kernel, not in its inputs,
its storage, or its arguments.

This also settles the framing. "Stateful decode is broken" was too broad on both
routes, in opposite directions:

- On the **CPU** route the state is fully visible and the previously reported
  lock does not reproduce on this build. There is no measured state-visibility
  defect to fix.
- On the **Vulkan** route the failure begins inside prefill, at the second
  visible slot, and needs no decode recurrence to reach it.

## 6. Next measurable step

`ATTN_SCORES` and `ATTN_PROBS` have no device-side arena (1320 explicit
`UNAVAILABLE` gaps), so the kernel's internal read set is the one thing still
unobserved. The next gate is to make it visible — a device arena for the scores,
or a host replay of the kernel's own indexing against the cache bytes that
§4 already proves are correct — and to discriminate:

```text
scores disagree with a host replay that indexes the cache the way AppendKV
    and ProbeKvSlotFloats do   -> the kernel's slot/head/stride mapping is wrong
scores agree, value mix wrong   -> the value accumulation or GQA head mapping
                                  is wrong
scores and mix both agree       -> the defect is downstream and this premise
                                  is wrong
```

A scale or softmax convention difference would also present here: with two
slots the output is a two-way mixture, so a small error in the mixing weight
produces exactly the 0.2% seen at `CTX=2`.

---

## 7. Instrument defects found and fixed while producing this

Recorded because each produced a confident, wrong result before being caught.

| # | Defect | How it surfaced | Effect if shipped |
|---|---|---|---|
| 1 | Analyzer regex `[A-Z0-9_]+` matched only upper-case field names, while the emitter mixes cases (`kv_write_k` lower, `INV_*` upper) | 36 frames read as `producers=0`, page of empty rows, `VERDICT=INVARIANT_VIOLATION` on a run where all four invariants held | the exact opposite conclusion |
| 2 | PowerShell parameter `-Gpu` and local `$gpu` are the SAME variable (names are case-insensitive) | `GPU_SPLIT_RECORDS=1` for a 278-record file, empty table, confident `VERDICT=KV_WRITE_OR_STORAGE_DEFECT` with `0 of 0` evidence | a fabricated defect with no evidence behind it |
| 3 | `Has-Field` used `PSObject.Properties` on a `Hashtable`, which exposes the CLR surface, not the keys | `CPU_PROBE_EMPTY=1` for a 64081-line probe | the GPU half of the grid join would have been skipped as "no data" |
| 4 | `kvDim` is `uint32_t`; the new records printed it with `%zu` | `COUNT=2366526980352` for a 256-float tensor | a garbage field inside otherwise valid evidence |
| 5 | Two block-local `static FILE*` in sibling blocks are two distinct objects; the second reopened the same path with `"wb"` | found while writing, not at runtime | would have truncated every K/V record the first had written |
| 6 | Grid anchor placed after the first two `emit()` calls | 2 `UNANCHORED` records per run, in the file | two of seventeen stages silently without identity |
| 7 | `writeSummary()` had zero callers | absence of the `SUMMARY` line in the grid file | `READBACK_AUTHORITY=CERTIFIED` with no measured instance |

Common thread, and the reason each was caught: the parser and the emitter were
checked against each other, and every one of these produced a *plausible
numeric* result rather than an error.

---

## 8. Ledger

```ini
RAWRXD_ATTN_VISIBILITY_TRACE_001            = INSTRUMENTED_AND_MEASURED
PRODUCTION_CELL_ATTENTION_VISIBILITY        = PASS
PRODUCTION_PREFILL                          = PASS
PRODUCTION_KV_POSITION_ADVANCE              = PASS
PRODUCTION_PREFILL_KV_LEN_AFTER             = PASS   (13 of 13)
NEWEST_SLOT_KV_NOT_VISIBLE                  = FALSIFIED
PRODUCTION_ARGMAX_LOCK                      = NOT_REPRODUCED_ON_THIS_BUILD
PRODUCTION_ARGMAX_LOCK_PRIOR_OBSERVATION    = UNRECONCILED (prior binary identity missing)

VULKAN_GRID_STEP_IDENTITY                   = FIXED_AND_VERIFIED  (MAX_POS=19, was 0)
VULKAN_GRID_SELF_SUMMARY                    = WIRED  (was an orphan with 0 callers)
VULKAN_KV_WRITE                             = PASS   (bit-identical, 80/80)
VULKAN_KV_STORAGE                          = PASS   (bit-identical, 80/80)
VULKAN_KV_SLOT_SURVIVAL                     = PASS   (38/38)
VULKAN_KV_CACHE_READ_DEFECT                 = RULED_OUT
VULKAN_LAYER_BODY_STEP0                     = PASS   (all 13 joined stages, 22 layers)
VULKAN_LAYER_BODY_STEP1_PLUS                = FAIL   (156 of 169 step/stage pairs)
VULKAN_FIRST_DIVERGENT_STEP                 = 1
VULKAN_FIRST_DIVERGENT_POINT                = LAYER_0 ATTENTION_OUTPUT (inputs correct)
VULKAN_FUSED_ATTENTION_KERNEL               = DEFECTIVE_FROM_TWO_VISIBLE_SLOTS
GPU_KV_ATTENTION_SEMANTICS_OPEN             = OPEN   (1320 UNAVAILABLE gaps)

GPU_QUANT_EXECUTION_CERT                    = INVALID/OPEN  (unchanged)
CPU_EXTERNAL_REFERENCE_PARITY               = OPEN          (unchanged)
SAFE_TO_SHIP                                = 0
```

## 9. Artifacts

```
attn_visibility_cpu.txt      258431 B  SHA256 6BAA549659E1B8D7...
attn_visibility_vulkan.txt   142128 B  SHA256 41BCC732D49827BA...
cpu_kv_probe.txt            14622381 B  SHA256 DCB238B83297285A...
vulkan_kv_split.txt           48729 B  SHA256 2890D292A99A5475...
vulkan_parity_grid.txt      3207077 B  SHA256 D27A4FD33364A51D...
cpu_run_stdout.log             2026 B  SHA256 367823CF388C14D0...
vulkan_run_stdout.log           945 B  SHA256 527A92E6212ECACD...
```

## 10. Files changed

```text
src/deep2/AttnVisibilityTrace.h                    NEW
src/deep2/Deep2Engine.cpp                          computeAttention record; generate() frame
src/deep2/Deep2Engine_GpuForward.cpp               grid anchor; K/V split; GPU visibility record
tools/server_generation_parity.cpp                 route switch; CPU-side parity probe
tools/attn_visibility_analyze.ps1                  NEW
tools/vulkan_kv_split_analyze.ps1                  NEW
tools/vulkan_grid_layer_bisect.ps1                 NEW
CMakeLists.txt                                     server_generation_parity target
```

No behaviour outside the three opt-in gates
(`RAWRXD_ATTN_VISIBILITY_TRACE`, `RAWRXD_VULKAN_KV_SPLIT`,
`RAWRXD_VULKAN_PARITY_GRID`) is changed. All default to off.
