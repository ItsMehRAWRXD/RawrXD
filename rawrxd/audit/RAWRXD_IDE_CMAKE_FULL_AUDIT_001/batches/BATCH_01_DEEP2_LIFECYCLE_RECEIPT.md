# BATCH 01 — Deep2 lifecycle closure (D2)

Authority: RAWRXD_DEEP2_GENERATION_LIFECYCLE_001
Receipt class: measured. Every numeric value below is copied from
`BATCH_01_d2_run_tinyllama.log`, produced by a binary built in this session.
Verdict: **D2_CLOSED_ON_MEASUREMENT**, with one literal sub-item recorded as FAIL
and one carried defect recorded as NOT-FIXED.

```ini
D2_KV_RESET=PASS
ENGINE_INSTANCE_COUNT=1
GEN1=PASS
GEN2=PASS
GEN3=PASS
GEN4=PASS
STALE_KV_EXCEPTIONS=0
SAME_ENGINE_ALL_GENERATIONS_PASS=1
VERDICT=PASS
EXITCODE=0

# recorded, not upgraded
ITEM_03_RESET_CLEARS_KV_ENTRIES=FAIL_LITERAL        (see DEFECT-D2-1)
RESULT_CONTRACT_CLEAN=1_BUT_NOT_YET_PROVEN         (see SCOPE)
D3_EOS_TERMINATION=NOT_FIXED                        (see CARRY-1)
TOKEN_DECODE_RETURNS_CR=NOT_FIXED                   (see CARRY-2)
```

## Items

| # | Item | Result | Evidence |
|---|------|--------|----------|
| 1 | Audit what `reset()` clears | MEASURED | `Deep2Engine.cpp:659-690` |
| 2 | Reset clears KV position | PASS | `KVCache.h:66` `currentLen_ = 0` |
| 3 | Reset clears KV entries | **FAIL (literal)** | `Deep2Engine.cpp:661` `clear(false)`; `KVCache.h:67-70` |
| 4 | Reset clears generation-local state | PASS | lines 663-689 |
| 5 | Reset does not destroy model weights | PASS | only `modelWeights.numLayers` reads |
| 6 | Canonical independent-request boundary | MEASURED | `Deep2Engine.cpp:3671` |
| 7 | D2 reset bound at that boundary | PASS (pre-existing) | line 3671 |
| 8 | Same-engine generation #1 | PASS | `B[0] status=Completed generatedTokens=8` |
| 9 | Same-engine generation #2 | PASS | `B[1] status=Completed generatedTokens=8` |
| 10 | Same-engine generation #3 | PASS | `B[2] status=Completed generatedTokens=8` |
| 11 | Same-engine generation #4 | PASS | `B[3] status=Completed generatedTokens=8` |
| 12 | No `cpu_forward_exception` | PASS | 0 occurrences in 74315 log lines |
| 13 | No engine reconstruction | PASS | `ENGINE_INSTANCES=1`, load once, `loadMs=82` |
| 14 | Fresh prompt/state per generation | PASS (corrected predicate) | `GENERATION_INHERITED_KV_FROM_PRIOR_GENERATIONS=0` |
| 15 | D2 measured receipt | PASS | this file |

## Item 1 — exactly what `reset()` clears

`rawrxd/src/deep2/Deep2Engine.cpp:659-690`, verbatim structure:

```cpp
void Deep2Engine::reset() {
    clearCancel();                                            // 660  cancel flag
    if (kvCache) (void)kvCache->clear(false);                 // 661  KV length only
    if (hiddenStates  && config.hiddenDim) memset(..., 0);   // 663-664
    if (attentionOutput && config.hiddenDim) memset(..., 0);  // 665-666
    if (ffnOutput && config.hiddenDim) memset(..., 0);       // 667-668
    if (ssmState)      memset(..., 0);                        // 671-674  recurrent state
    if (ssmConvState)  memset(..., 0);                        // 675-680  conv history
    for (auto& gpu : vulkanDevices_) if (gpu) gpu->ResetMLACache();  // 683-685
    specKvMirrorReset();                                      // 686
    gpuFwdCommitted_ = false;  gpuFwd_ = {};                  // 688-689
}
```

## Item 5 — weights survive reset

`modelWeights` appears twice inside `reset()`, at lines 672 and 678. Both are
*reads* of `modelWeights.numLayers`, used to size a memset. No weight pointer is
written, freed, or reallocated. Confirmed by reading the whole function body.

## Items 6-7 — the boundary and the binding

The canonical independent-generation boundary is the top of
`Deep2Engine::generate()`, immediately after the cancel transaction and before
`modelState_` becomes `Generating`:

```
Deep2Engine.cpp:3662   clearCancel();
Deep2Engine.cpp:3663-3670  D2 comment, tagged RAWRXD_DEEP2_GENERATION_LIFECYCLE_001
Deep2Engine.cpp:3671   reset();
Deep2Engine.cpp:3672   modelState_ = ModelState::Generating;
```

`generateStream()` (`Deep2Engine.cpp:4072`) is a thin wrapper that tokenizes,
computes a token limit, and calls `generate()` at line 4105. So the reset is
reached on every streaming generation, exactly once, before prefill.

**This binding was already in the source before this batch.** `Deep2Engine.cpp`
was last modified 9/29/2026 3:41:51 PM, before the lease was taken at
2:44:44 PM on 9/30. Item 7 required no new mutation. What was missing was the
measurement, which is what items 8-15 produced.

## Items 8-13 — the run

Driver: `rawrxd/tools/deep2_generation_lifecycle_test.cpp`
Model: `G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`
Build: fresh configure + `InferenceEngine` target in `F:\~dev\build_d2_lifecycle_001`,
then the driver compiled and linked against `InferenceEngine.lib` directly
(`/O2 /EHsc /std:c++20 /MT`). No `CMakeLists.txt` was modified.

```
ENGINE_INIT=PASS
MODEL_LOAD=PASS loadMs=82 kvAtLoad=0
ENGINE_INSTANCES=1
ENGINE_RECONSTRUCTED_BETWEEN_GENERATIONS=0

B[0] promptTokens=12 kvBefore=0  kvAfter=19 status=Completed completed=1 cancelled=0 generatedTokens=8 callbackInvocations=8 wallMs=17492
B[1] promptTokens=12 kvBefore=19 kvAfter=19 status=Completed completed=1 cancelled=0 generatedTokens=8 callbackInvocations=8 wallMs=17857
B[2] promptTokens=9  kvBefore=19 kvAfter=16 status=Completed completed=1 cancelled=0 generatedTokens=8 callbackInvocations=8 wallMs=15184
B[3] promptTokens=9  kvBefore=16 kvAfter=16 status=Completed completed=1 cancelled=0 generatedTokens=8 callbackInvocations=8 wallMs=15077
```

One model load. One engine object. Four independent generations, four distinct
prompts (`promptFor(i)` cycles four different instructions), each completing with
8 sampled tokens and 8 callback invocations.

```
cpu_forward_exception occurrences = 0
Exception|EXCEPTION|abort|assert occurrences = 0
```

## Item 14 — fresh state, and a driver predicate that was wrong

The first run reported `GENERATION_STARTED_WITH_NONZERO_KV=3` and
`VERDICT=FAIL`. That counter was measuring the wrong thing:

```cpp
if (i > 0 && o.kvBefore != 0) ++kvNotResetAtGenerationStart;
```

`o.kvBefore` is sampled in `runOne()` **before** `generateStream()` is entered.
The reset happens *inside* `generate()`. So `kvBefore` is by construction the
residue of the previous generation, and requiring it to be 0 tests nothing about
the reset. It is a false positive.

Replaced with a predicate that states what D2 actually forbids — a new
generation inheriting KV written by earlier generations on the same engine:

```cpp
if (i > 0 && o.kvAfter >= priorTokensWritten)
    ++kvInheritedFromPriorGenerations;
priorTokensWritten += o.promptTokens + o.generatedTokens;
```

Re-run result:

```
GENERATION_INHERITED_KV_FROM_PRIOR_GENERATIONS=0
TOKENS_WRITTEN_BY_PRIOR_GENERATIONS=74
KV_LENGTH_AFTER_LAST_GENERATION=16
```

Generations 1-3 wrote 74 tokens between them. The KV length after generation 4
is 16. Without a reset the length would have exceeded 74. It does not.

The same conclusion falls out of the arithmetic independently of the driver.
Across all five generations, `kvAfter == promptTokens + generatedTokens - 1`:

```
B[0]  12 +  8 - 1 = 19   measured 19
B[1]  12 +  8 - 1 = 19   measured 19
B[2]   9 +  8 - 1 = 16   measured 16
B[3]   9 +  8 - 1 = 16   measured 16
D[0]  12 + 48 - 1 = 59   measured 59
```

The KV length is fully determined by the current generation alone, five for
five. That is a stronger statement than the boolean: no generation carried any
KV written by an earlier one.

## DEFECT-D2-1 — item 3 fails as literally written

The batch asks to "confirm reset clears KV entries." It does not.

`Deep2Engine.cpp:661` calls `kvCache->clear(false)`. The parameter is
`zeroMemory`:

```cpp
// KVCache.h:61-72
bool clear(bool zeroMemory = false) {
    if (!allocated_) { currentLen_ = 0; return true; }
    currentLen_ = 0;
    if (zeroMemory) {
        std::fill(keys_.begin(),   keys_.end(),   0.0f);
        std::fill(values_.begin(), values_.end(), 0.0f);
    }
    return true;
}
```

`currentLen_` is reset; `keys_` and `values_` keep their previous bytes. So the
KV *position* is fresh and the KV *entries* are stale.

This is recorded as FAIL rather than waved through, because the item asked a
specific question and the honest answer is no. It is also not currently a
correctness hazard: every KV read in the engine is bounded by `currentLength()`
or `+1` (lines 2155, 2833, 3060, 3789), and the five-for-five arithmetic above
confirms no byte beyond the live length influences any result. The residual risk
is latent: a future read path that trusts `keys_` length rather than
`currentLen_` would silently consume generation N-1 bytes. Worth a guard; not
worth changing D2's measured state.

## SCOPE — `RESULT_CONTRACT_CLEAN=1` is not a D1 proof

```
FORWARD_FAILURE_REPORTED_AS_COMPLETED=0
CANCELLED_REPORTED_AS_COMPLETED=0
COMPLETED_WITH_ZERO_GENERATED_TOKENS=0
FAILURE_STATUS_WITHOUT_DETAIL=0
GENERATED_TOKENS_DISAGREE_WITH_CALLBACK=0
RESULT_CONTRACT_CLEAN=1
```

All five are zero **because no failure occurred in this run**, not because the
forbidden states are unreachable. A predicate that counts violations over a
run in which nothing fails is measuring the run, not the contract.

Source reading shows one D1 hazard is still open. At `Deep2Engine.cpp:4117-4139`:

```cpp
res.cancelled  = cancelRequested_.load(std::memory_order_acquire);
res.completed  = !res.cancelled;          // line 4118
...
if (res.cancelled)              res.status = Cancelled;
else if (n > 0)                 res.status = Completed;
else if (!lastFailureDetail_.empty()) { res.status = lastFailureStatus_;   // ForwardFailure
                                       res.failureDetail = lastFailureDetail_; }
else                            res.status = EndOfSequence;
```

`res.completed` is computed **before** the status is decided, from the cancel
flag alone. When `generate()` returns 0 tokens because of a forward failure and
no cancel was requested, `res.completed == true` while `res.status ==
ForwardFailure`. That is exactly `FORWARD_FAILURE_COMPLETED_TRUE=1`, the state
Batch 2 must make structurally impossible. It did not trigger here because this
run had no forward failure.

The two early-return paths at lines 4085 and 4098 return a zero-initialized
`GenerationResult` whose status defaults to `InternalError` with an empty
`failureDetail` — a failure status carrying no reason.

D1 is therefore **open**, and Batch 2 items 2-8 are the work that closes it.

## CARRY-1 — D3 EOS termination confirmed not fixed

```
D[0] generatedTokens=48  (EOS_PROBE_MAX_TOKENS=48)
D_TERMINATED_AT_CEILING=1
D_TERMINATED_EARLY=0
```

The engine ran to the token ceiling and stopped because it ran out of budget,
not because it reached end-of-sequence. This matches the engine's own comment at
`Deep2Engine.cpp:4088-4089`:

```cpp
// maxTokens==0 means "until a real stop condition". This engine does not
// yet own EOS metadata, so the hard context boundary is the safe stop.
```

A repo-wide search for EOS/control handling in the engine finds only this
comment, one diagnostic string at line 4125, and an unrelated
`DecodeOneResult::Kind::Eos` at `Deep2Engine.h:615`. Batch 2 items 10-15 own
this.

## CARRY-2 — decode returns CR for most tokens

The four generations each produced 8 tokens and 8 non-empty callback pieces, but
the concatenated text was a single carriage return in three of four cases:

```
B[0] text bytes = 0D
B[1] text bytes = 0D
B[2] text bytes = 20 74 6F 20 67 6F 2E 0D      (" to go.")
B[3] text bytes = 0D
```

`callbackEmptyPieces=0` in every case, so the pieces are not empty — they
decode to `\r`. This is a tokenizer/decode defect, independent of D2, and it is
why no Batch 3 semantic judgment can be made yet. `Tokenizer.hpp` is inside the
lease scope, so Batch 2 can investigate it without a new lease.

## Build evidence

```
Configure:  4.2s, 0 errors
InferenceEngine: 155/155 objects, 0 errors, 0 warnings escalated
  [67/155]  CMakeFiles\InferenceEngine.dir\src\deep2\Deep2Engine.cpp.obj
  [152/155] CMakeFiles\InferenceEngine.dir\src\deep2\Tokenizer.cpp.obj
Driver compile: 0 errors, 0 warnings (/W3)
Driver link:    LINK_OK
Run:            EXITCODE=0
Log:            BATCH_01_d2_run_tinyllama.log, 74315 lines
```

The fresh configure also independently re-confirmed a Batch 8 finding, from
CMake's own output:

```
-- [RAWRXD_BUILD_SOURCE_INTEGRITY_001] Skipping agentic rawr CLI:
   missing src/cli/rawr_main.cpp and other agentic sources
```

## Mutation performed by Batch 01

One file, inside the lease:

- `rawrxd/tools/deep2_generation_lifecycle_test.cpp` — replaced the mis-sited
  `kvBefore == 0` predicate with the inheritance predicate, and added two
  reporting fields (`TOKENS_WRITTEN_BY_PRIOR_GENERATIONS`,
  `KV_LENGTH_AFTER_LAST_GENERATION`).

No change to `Deep2Engine.h`, `Deep2Engine.cpp`, or `Tokenizer.hpp`. No
`CMakeLists.txt` change. No HEAD movement.

An intermediate build of this batch caught its own bug: the first version of the
new predicate omitted the `priorTokensWritten` accumulation line, which printed
`TOKENS_WRITTEN_BY_PRIOR_GENERATIONS=0` and produced a meaningless verdict. The
run was discarded and repeated after the fix. The receipt field exists because
it is what made the omission visible.

## Next batch

Batch 02 — result contract + EOS, 15 items. It owns:

- D1: the `res.completed` computation at `Deep2Engine.cpp:4118` must be derived
  from the decided status, not from the cancel flag alone, so
  `ForwardFailure + completed=true` is unreachable.
- D1: the two early returns at 4085 and 4098 must carry a failure reason.
- D3: model EOS metadata resolution and real EOS termination.
- CARRY-2: the `\r` decode.

All four files required are already in the lease. No new authority needed.

---

## CONCURRENT-MUTATION-001 — the tree moved under this receipt

Recorded 16:11, after the measured run completed.

```
git diff --stat -- rawrxd/src/deep2/Deep2Engine.cpp
 1 file changed, 10 insertions(+)

Deep2Engine.cpp.obj      15:57:42.710   <- what the binary was compiled from
deep2_generation_lifecycle_test.exe  16:06:33.566
rawrxd/src/deep2/Deep2Engine.cpp     16:09:29.174   <- changed AFTER both
```

At 16:09:29 — after the object file was built at 15:57:42 and after the driver
was linked at 16:06:33 — `Deep2Engine.cpp` gained ten lines that I did not
write and did not authorize:

```diff
@@ -4129,6 +4129,16 @@ GenerationResult Deep2Engine::generateStream(
         res.status = GenerationStatus::EndOfSequence;
     }
+    // D2 — generation lifecycle: at the end of every independent generation,
+    // clear the KV cache and per-generation state so the NEXT independent
+    // request on this engine instance observes kvCacheLength() == 0.
+    // ...
+    // RAWRXD_DEEP2_GENERATION_LIFECYCLE_001.
+    reset();
     return res;
 }
```

### What this does and does not change

**The evidence in this receipt is valid.** The measured binary was compiled at
15:57:42, before the edit existed. Everything above describes the code as it was
at that timestamp, including the start-of-`generate()` reset at line 3671.

**The tree no longer matches the evidence.** The current working tree has a
*second* D2 binding — an end-of-`generateStream()` reset — which this receipt
does not describe and has not measured.

The two bindings are not redundant. They place the reset on opposite sides of
the same request:

- start-of-`generate()` (measured, line 3671): `kvCacheLength()` is 0 at the
  start of a generation, but non-zero after one returns.
- end-of-`generateStream()` (unmeasured, added): `kvCacheLength()` is 0 after a
  generation returns.

The second one invalidates the field this receipt's corrected predicate is
built on. `GENERATION_INHERITED_KV_FROM_PRIOR_GENERATIONS` compares `kvAfter`
against `TOKENS_WRITTEN_BY_PRIOR_GENERATIONS`. If `kvAfter` becomes 0, the
driver stops measuring KV hygiene and starts passing vacuously. **The driver as
committed will report a clean D2 against a broken KV cache.** That needs a
re-run and a predicate that samples inside the boundary, not after it.

### Single-writer state

```
.rawrxd\leases\writer.lease
  pid          30252   (unchanged)
  nonce        5712953110738933491  (unchanged)
  expected_head a078e3b87...        (unchanged, HEAD did not move)
```

The writer took no new lease and moved no HEAD. The lease names
`Deep2Engine.cpp` as an authorized path, but the nonce is the prior session's,
and the prior session's holder process (PID 30252) has consumed 0.42 s of CPU
across four hours and is not an editing process.

```ini
CONCURRENT_MUTATION_OF_LEASE_PROTECTED_FILE=1
AUTHORITY_ACQUIRED_FOR_IT=0
HEAD_MOVED=0
THIS_RECEIPT_MEASURED_PRE_EDIT_CODE=1
CURRENT_TREE_MATCHES_THIS_RECEIPT=0
DRIVER_PREDICATE_INVALIDATED_BY_THIS_EDIT=1
```

### Not done, deliberately

The added code was **not reverted**. Reverting it would be the uncontrolled
second writer this audit exists to prevent, and it would destroy another
session's work on the basis of my own timing. The file is left exactly as
found, and the conflict is escalated instead.

Batch 02 must not start by building on this receipt until the D2 binding is
settled: one binding or two, and re-measured either way.