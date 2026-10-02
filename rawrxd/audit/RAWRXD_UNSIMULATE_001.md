# RAWRXD_UNSIMULATE_001 — fabricated model-facing results removed

```
GATE            = RAWRXD_UNSIMULATE_001
DATE            = 2026-10-02
GIT_HEAD        = b81d3f1312727eb6ab1b7f2dd7ef7798fd5c9223  (worktree modified)
SCOPE           = anything that makes a model, a model's output, or a model's
                  integrity appear to work without computing it
```

Eleven sites removed or made fail-closed. Six are compile-verified, five are
blocked from parsing by a pre-existing missing include and are therefore
reported as **not** compile-verified rather than assumed good.

---

## 1. What was found

### 1.1 Model-truth surface — the model catalog was entirely invented

`src/cli/RawrDumpRebuild.cpp`, compiled into the shipping `rawr` target:

```cpp
g_rebuildState.rootsScanned           = 6;    // Example: 6 roots scanned
g_rebuildState.filesScanned           = 150;  // Example: 150 files scanned
g_rebuildState.ollamaManifestsScanned = 161;  // Example: 161 manifests scanned
g_rebuildState.aliasesScanned         = 10;   // Example: 10 aliases scanned
g_rebuildState.catalogRebuilt         = true;
g_rebuildState.verdict = (catalogRebuilt && filesScanned > 0) ? "PASS" : "FAIL";
```

Every field a constant, so the verdict was decided before the first filesystem
call and nothing could change it. This is the command surface that answers
"what models do I have", and it answered with numbers invented at authoring time.
The ledger records that `RawrDumpAuthority.cpp` was already rewritten for
exactly this defect; the sibling file was missed.

**Fixed by delegating to the implementation that already exists and is already
real**: `rawrxd::models::buildCatalogFromScratch()`, used by `rawr dump` and
`rawr dump --rebuild`, which scans the filesystem, probes GGUF headers,
classifies, and computes `verdict = (modelsDiscovered > 0 && modelsWithPath > 0)`.
`writeRebuildReceipt` now reports `INVALID` if the rebuild was not entered,
instead of printing zeros that look like a measurement.

### 1.2 A class named `Deep2Engine` that returned "Hello world"

`src/generation/module7_glue.h` defined a **concrete** class named
`Deep2Engine` whose `generate()` emitted two hardcoded tokens and returned
`true`:

```cpp
tokenCb("Hello", 0);
tokenCb(" world", 1);
return true;  // placeholder
```

Its own comment said "This stub simulates a few tokens then stops". It was not
inert: the header is part of the `RawrXDGeneration` interface target
(`add_subdirectory(src/generation)`) and was included by
`integration/RawrXDEngineAdapter.h` and `integration/Deep2GenerationAdapter.h`,
so a translation unit could have satisfied the generation interface with a
class bearing the production engine's name and returning fabricated text with a
success status.

**The class is deleted, not stubbed.** A class that is present, correctly named,
correctly signed and returns success without computing anything is worse than
one that fails to link, because the link error is visible and the success is
not.

Deleting it exposed a real structural problem: `module6_generate.h` *calls*
engine methods and so needs a complete type, which meant the generation module
was **structurally dependent on the fake implementation in order to compile**.
The abstract interface now lives in `module6_generate.h`, the header that
consumes it, and the duplicate declaration in `RawrXDEngineAdapter.h` is gone.
There is exactly one `Deep2Engine` declaration in the tree and it is abstract
with no definition.

### 1.3 Speculative decoding driven by random numbers

`src/ai/SpeculativeTreeAttentionBridge.cpp`:

```cpp
// SingleDraftPredictions
std::uniform_int_distribution<int32_t> token_dist(0, 32000);
std::uniform_real_distribution<float> prob_dist(0.0f, 1.0f);
...
    predictions.emplace_back(token_dist(rng_), prob_dist(rng_));

// GetTargetLogits
std::uniform_real_distribution<float> dist(-2.0f, 2.0f);
std::vector<float> logits(32000);
for (auto& l : logits) l = dist(rng_);
```

Neither `context` nor `draft_idx` was consulted. The second one is worse: those
are the **target model's logits**, the vector a rejection sampler uses to accept
or reject every speculative token. A random target is not a degraded model, it
is the absence of one, and it makes `AcceptToken` a coin flip.

Both now return empty, which means "no speculation available" / "no verification
available" — a real answer that routes the caller to ordinary single-token
decoding.

### 1.4 A GEMM that reported success without multiplying

`src/backend/VulkanGemmDispatcher.cpp`, compiled into the build:

```cpp
if (vk_device_ == VK_NULL_HANDLE) { /* Mock mode: simulate success */ return true; }
```

`DispatchGemm` returned true leaving the output buffer untouched, so any caller
using the result — and a GEMM result is a model activation — consumed
uninitialised memory and had no way to know. `CreatePipeline` returned true with
no `VkPipeline` behind it, handing callers an empty `PipelineState` to bind.
`Initialize` returned true having created nothing, because the device handles
are literals set to `VK_NULL_HANDLE` with the real extraction left as a comment,
making the path both reachable and terminal.

All three now fail closed with a stated reason.

### 1.5 Training metrics produced by a formula

`src/cli/deep_iteration_engine.cpp`:

```cpp
metrics.loss       = best_loss_ * 0.99f + 0.01f;   // "synthetic decay"
metrics.perplexity = std::exp(metrics.loss);
metrics.accuracy   = min(1.0f, step / max_steps);  // a progress-bar ratio
metrics.grad_norm  = max_grad_norm * 0.5f;         // half a constant
metrics.forward_time = 10ms; metrics.backward_time = 20ms;  // literals
```

No forward, no backward, no gradient — and the one number a training loop exists
to produce decayed by construction, so improvement was guaranteed. The
implementation is **deleted**; `RunSingleStep` refuses and says why. Keeping it
under a different name would only invite it to be re-wired. `StepMetrics` gained
`bool measured = false`, because a zero in a metrics struct is indistinguishable
from a measurement of zero, and no code path sets it true.

### 1.6 Model integrity checks that always passed

| Site | Was | Now |
|---|---|---|
| `canonical/UnifiedModelLoader.cpp` `VerifySHA256` | `return true; // placeholder`, "SHA256 computation omitted" | refuses; every hash-bound receipt in this tree is pinned to a model by hash, so a verifier that never reads the file makes them unfalsifiable |
| `core/sovereign_model_loader.cpp` `ValidateGGUF` | `return true; // Placeholder` for any path | **implements the real check** — reads the 4-byte `GGUF` magic and the little-endian uint32 format version, rejects versions outside 1..3 |
| `core/RawrXD_FeatureRegistry.cpp` `CanEnableAgentBridge` | `return true; // For now, assume yes` after three TODOs | fails closed with the reason, matching the sibling `CanEnableOmegaOrchestrator` in the same file |
| `install/InstallRebootRawrE2EAuthority.cpp` | `freshShellRawRunCompleted = true`, `generatedTokenCount = 42; // Example token count`, `VERDICT=PASS` | `INVALID`, with `GENERATED_TOKEN_COUNT=NOT_MEASURED` |
| `diagnostics/IdeResponseHangAuthority.cpp` | `waitImportHits=3`, `networkImportHits=2`, `responseSymbolHits=5`, `subsystemLine="CONSOLE"`, all "Example", then a risk verdict computed from them | `INVALID`, `NOT_MEASURED` for each |

`GENERATED_TOKEN_COUNT = 42` is a claim about model output, reported from a model
that was never launched, alongside a PATH resolution that was never performed
and a shell that never started. The hang authority reported `LOW_RISK` about a
binary it never opened, and the invented numbers (3 and 2) happened to fall
below the thresholds that would have flagged `HANG_RISK`.

---

## 2. The scanner that missed them

`RawrAuditAuthority` has a `SIMULATED_COUNTER` rule, and it is a **fixed list of
eleven names**. It caught `generatedTokenCount` and `rootsScanned`, so it
reported coverage — while `filesScanned`, `waitImportHits`,
`networkImportHits`, `responseSymbolHits`, `pathResolvesRawr` and
`freshShellRawRunCompleted`, every one of which was assigned a literal in this
tree, passed as clean.

A census whose coverage is a list somebody chose is worse than one that fails
loudly, because it reports a count that looks like a measurement of the whole.

Two rules added:

1. **Generic suffix rule.** Any identifier whose name ends in a measurement
   suffix (`count`, `hits`, `scanned`, `discovered`, `exists`, `resolves`,
   `completed`, `started`, `verified`, `valid`, `parsed`, `loaded`, `issued`,
   `found`, `matched`, `skipped`, …) assigned a bare non-zero integer literal is
   a simulated observation. `= 0` is exempt: initialising a counter to zero is
   correct. New counters are covered by construction rather than by remembering
   to add them.
2. **`ASSUMED_SUCCESS`.** `return true;` / `return false;` on a line carrying a
   concession marker (`placeholder`, `for now`, `assume`, `simplified`,
   `omitted`, `not implemented`, `stub`, `mock`, `would need`, `todo`,
   `would extract`, `would call`, `would actually`) is a blocking finding. This
   class is invisible to any rule that inspects assignments.

---

## 3. Verification status, stated honestly

| File | Status |
|---|---|
| `src/cli/RawrDumpRebuild.cpp` | **compiles** (cl /Zs clean) |
| `src/install/InstallRebootRawrE2EAuthority.cpp` | **compiles** |
| `src/diagnostics/IdeResponseHangAuthority.cpp` | **compiles** |
| `src/backend/VulkanGemmDispatcher.cpp` | **compiles** |
| `src/cli/deep_iteration_engine.cpp` | **compiles** |
| `src/agentmodes/RawrAuditAuthority.cpp` | **compiles** (new rules) |
| `src/ai/SpeculativeTreeAttentionBridge.cpp` | parses past all edits; fails later on a pre-existing `std::construct_at` error unrelated to them |
| `src/canonical/UnifiedModelLoader.cpp` | **not verified** — `#include "sha256.h"`, which does not exist in the tree |
| `src/core/sovereign_model_loader.cpp` | **not verified** — `RawrXD_120B_Loader_C.h` missing |
| `src/core/RawrXD_FeatureRegistry.cpp` | **not verified** — `RawrXD_FeatureRegistry.hpp` missing |
| `src/generation/integration/RawrXDEngineAdapter.{h,cpp}` | **not verified** — `rawrxd_sampler.h` missing |
| `src/generation/test_generation.cpp` | **not verified** — same missing header, via the adapter |

None of those five headers exists anywhere in the tree, so those five
translation units have never compiled and their behaviour has never been
observed. Removing a fabrication from a file that cannot run is still correct
and costs nothing, but it is not the same as a verified fix and is not claimed
as one.

### 3.1 A regression I introduced and repaired

Two PowerShell `Set-Content -Encoding UTF8` edits to
`src/deep2/Deep2Engine_GpuForward.cpp` and
`src/deep2/vulkan_compute_patched.h` round-tripped the files through the ANSI
codepage, **double-encoding 9 and 1 pre-existing non-ASCII characters** and
adding a BOM. Detected by decoding the bytes as UTF-8 explicitly and comparing
against HEAD, then reversed by re-encoding the mojibake back to CP1252 to
recover the original bytes.

`vulkan_compute_patched.h` was then restored from HEAD and re-patched byte-wise
to preserve CRLF, because the line-ending round-trip had made `git diff` report
801 added / 400 deleted for a two-line change. Its diff is now **3 added /
1 deleted**, which is the actual edit.

Two pre-existing compile errors in files I was already editing were also fixed,
since leaving a knowingly broken file while claiming to have cleaned it would
be the same defect at a different level:

- `src/cli/deep_iteration_engine.cpp:58-60` — three
  `reinterpret_cast<const char>(&x)` missing the `*`, so `SaveCheckpoint` did
  not compile.
- `src/ai/SpeculativeTreeAttentionBridge.cpp` — `#include "math"` and
  `static constexpr float ATTENTION_SCALE = 1.0f / std::sqrt(64.0f)`, which is
  not a constant expression before C++26.

### 3.2 The real generation path is unchanged

Production `Deep2Engine::generateStream()`, tinyllama-1.1b-chat-v1.0.Q4_K_M,
greedy, 24 tokens, rebuilt binary, after every removal above:

```ini
cpu     DISTINCT_TOKEN_IDS=12  VERDICT=C_IDS_AND_PIECES_VARY
vulkan  DISTINCT_TOKEN_IDS=12  VERDICT=C_IDS_AND_PIECES_VARY
GENERATED_TOKEN_IDS=13,1576,7483,310,278,3303,3900,29973,13,29896,29889,13,
                     29906,29889,13,13,29896,29889,13,13,13,29896,29929,29889
```

Identical to the pre-change measurement, and the two routes still agree
token-for-token. Nothing on the real path was touched; every change above is in
a fabricated, orphaned, or fail-closed surface.

---

## 4. Ledger

```ini
RAWRXD_UNSIMULATE_001                   = APPLIED
SITES_FOUND                            = 11
SITES_REMOVED_OR_FAIL_CLOSED            = 11
SITES_COMPILE_VERIFIED                 = 6
SITES_BLOCKED_BY_PREEXISTING_MISSING_INCLUDE = 5
MODEL_CATALOG_REBUILD_FABRICATION      = REMOVED  (delegates to the real scan)
FAKE_ENGINE_CLASS_IN_GENERATION_PATH    = REMOVED  (was returning "Hello world")
FAKE_ENGINE_INTERFACE_DEPENDENCY        = REMOVED  (module6 was dependent on it to compile)
SPECULATIVE_RANDOM_LOGITS               = REMOVED
GEMM_MOCK_SUCCESS                       = REMOVED
SYNTHETIC_TRAINING_METRICS              = REMOVED  (implementation deleted, not renamed)
MODEL_SHA256_VERIFIER_ALWAYS_TRUE       = REMOVED
GGUF_VALIDATOR_ALWAYS_TRUE              = IMPLEMENTED_FOR_REAL
LITERAL_TOKEN_COUNT_CLAIM              = REMOVED
INVENTED_RISK_COUNTS                    = REMOVED
FEATURE_GATE_ALWAYS_OPEN                = FAIL_CLOSED
AUDIT_COUNTER_RULE_LIST_TO_SUFFIX_RULE  = DONE
AUDIT_ASSUMED_SUCCESS_RULE              = NEW
ENCODING_REGRESSION_INTRODUCED_AND_FIXED = YES  (2 files)

REAL_GENERATION_PATH_AFFECTED           = 0
CPU_VULKAN_24_TOKEN_AGREEMENT           = UNCHANGED
SAFE_TO_SHIP                            = 0
```

`SAFE_TO_SHIP` is unchanged and still 0, for the reason in
`VULKAN_ROPE_CONVENTION_001.md`: two routes agreeing is not correctness against
a reference, and the CPU route still answers the France question wrongly.

## 5. Files changed

```text
src/cli/RawrDumpRebuild.cpp                    fabricated catalog -> real scan
src/generation/module7_glue.h                  fake engine class deleted
src/generation/module6_generate.h              abstract interface declared where used
src/generation/integration/RawrXDEngineAdapter.h duplicate declaration removed
src/ai/SpeculativeTreeAttentionBridge.cpp      random logits -> empty
src/backend/VulkanGemmDispatcher.cpp           mock success -> fail closed (3 sites)
src/cli/deep_iteration_engine.{hpp,cpp}        synthetic metrics -> refusal
src/canonical/UnifiedModelLoader.cpp           SHA256 always-true -> refusal
src/core/sovereign_model_loader.cpp            GGUF always-true -> real header check
src/core/RawrXD_FeatureRegistry.cpp            always-open gate -> fail closed
src/install/InstallRebootRawrE2EAuthority.cpp  literal token count -> NOT_MEASURED
src/diagnostics/IdeResponseHangAuthority.{h,cpp}  invented counts -> NOT_MEASURED
src/agentmodes/RawrAuditAuthority.cpp          two new detection rules
```
