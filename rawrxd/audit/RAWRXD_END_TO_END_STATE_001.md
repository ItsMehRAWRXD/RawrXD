# RAWRXD_END_TO_END_STATE_001 — six claims, measured right now

```
GATE            = RAWRXD_END_TO_END_STATE_001
DATE            = 2026-10-02
GIT_HEAD        = b81d3f1312727eb6ab1b7f2dd7ef7798fd5c9223  (worktree modified)
TREE            = F:\~dev\rawrxd\certbuild  (RAWR_ENABLE_VULKAN=ON, RAWRXD_BUILD_CLI=ON)
```

Every field below is a measurement from this session. Four of the six claims are
false; one is false for a reason narrower than "not yet proven"; one was already
correct. No claim is promoted.

---

```ini
ALL_SIMULATION_ELIMINATED         = 0    NOT PROVEN
ALL_CHANGED_FILES_BUILD           = 0    CONFIRMED FALSE
SPECULATIVE_DECODE_FUNCTIONAL     = 0    CONFIRMED FALSE
ALL_MODEL_DISCOVERY_PATHS_PROVEN  = 0    MEASURED FALSE
IDE_END_TO_END_CERTIFIED          = 0    MEASURED FALSE
SAFE_TO_SHIP                      = 0    DERIVED
```

---

## 1. `ALL_SIMULATION_ELIMINATED = 0`

The eleven sites removed in `RAWRXD_UNSIMULATE_001` are gone. The claim is still
false, and the counts are large enough that the framing is wrong rather than
merely premature.

```ini
BARE_STUB_FILES_IN_SRC            = 337    files whose entire body is "// STUB: <path>"
STUB_FILES_REFERENCED_BY_TOP_CMAKE = 163
OF_125_COMPILED_TUS_IN_INFERENCEENGINE = 0 bare stubs
```

The engine itself compiles none of them. My first count said **2**, and that was
wrong: it compared basenames, so `src/inference/Deep2Engine.cpp` (a stub) was
conflated with `src/deep2/Deep2Engine.cpp` (the real engine, 6 500 lines) and
`src/deep2/Sampler.cpp` with another `Sampler.cpp`. Re-run on full paths: **0**.
A census keyed on file names is the same defect as a census keyed on a list of
names — it cannot tell two different things apart.

### Live always-true sites that remain

```text
src/ceo/ceo_link_stubs.cpp:36          return true; // Allow all in stub
src/install/InstallAuthority.cpp:7     return true; // stub — real impl in a .ps1
src/install/InstallAuthority.cpp:10    (void)root; return true;
src/core/feature_registry.cpp:85       return 0;    // Cannot query memory — assume not a stub
src/core/feature_registry.cpp:149      return 0;    // Not a stub
src/core/tensor_residency_pipeline.cpp:157  return true; // Simplified
src/core/vscode_marketplace.cpp:1255   return true; // No policy engine = allow all
```

`vscode_marketplace.cpp:1255` and `ceo_link_stubs.cpp:36` are the notable ones:
both are **allow-all** policies, not merely optimistic defaults. A security or
permission gate that opens when the thing it should consult is missing is
fail-open by construction.

Also unresolved: `UnifiedModelLoader.cpp:229,238` still `return false; // TODO`
for safetensors and ONNX. Those fail closed, which is honest, but they mean those
formats are unsupported rather than supported-and-broken.

### Model-facing discovery paths that are literal stubs

```text
src/inference/polymorphic_loader.cpp      // STUB: src/inference/polymorphic_loader.cpp
src/inference/ollama_blob_parser.cpp      // STUB: src/inference/ollama_blob_parser.cpp
src/engine/sovereign_engines.cpp          // STUB: src/engine/sovereign_engines.cpp
```

Three discovery paths are files that contain a comment naming themselves.

---

## 2. `ALL_CHANGED_FILES_BUILD = 0`

```ini
CHANGED_FILES                        = 12
COMPILE_VERIFIED_CLEAN               = 6
PARSES_PAST_EDITS_THEN_PREEXISTING_ERROR = 1
BLOCKED_BY_MISSING_INCLUDE           = 5
```

| File | Status |
|---|---|
| `src/cli/RawrDumpRebuild.cpp` | compiles clean |
| `src/install/InstallRebootRawrE2EAuthority.cpp` | compiles clean |
| `src/diagnostics/IdeResponseHangAuthority.cpp` | compiles clean |
| `src/backend/VulkanGemmDispatcher.cpp` | compiles clean |
| `src/cli/deep_iteration_engine.cpp` | compiles clean (after fixing 3 pre-existing `reinterpret_cast` errors) |
| `src/agentmodes/RawrAuditAuthority.cpp` | compiles clean (2 new rules) |
| `src/ai/SpeculativeTreeAttentionBridge.cpp` | parses past all edits; fails later on a pre-existing `std::construct_at` error |
| `src/canonical/UnifiedModelLoader.cpp` | **blocked** — `#include "sha256.h"` does not exist |
| `src/core/sovereign_model_loader.cpp` | **blocked** — `RawrXD_120B_Loader_C.h` does not exist |
| `src/core/RawrXD_FeatureRegistry.cpp` | **blocked** — `RawrXD_FeatureRegistry.hpp` does not exist |
| `src/generation/integration/RawrXDEngineAdapter.{h,cpp}` | **blocked** — `rawrxd_sampler.h` does not exist |
| `src/generation/test_generation.cpp` | **blocked** — same, via the adapter |

None of those four headers exists anywhere in the tree, so those translation
units have never compiled. **Five of the files I changed have never been built**,
which is the direct reason this claim is false rather than unproven.

---

## 3. `SPECULATIVE_DECODE_FUNCTIONAL = 0`

The cause is narrower than "broken", and it is two independent facts.

**Fact 1 — the path can never activate.**

```cpp
// src/deep2/Deep2Engine.h:1273
bool medusaEnabled_ = false;

// src/deep2/Deep2Engine.cpp:5423
const bool specActive =
    medusaEnabled_ && deterministicGreedy_ && medusaDecoder_ &&
    parityProbe_ == nullptr && !modelWeights.isMoE && !modelWeights.useMLA;
```

`medusaEnabled_` is only ever written at `Deep2Engine.cpp:3400`, inside
`enableMedusa()`. Repo-wide, `enableMedusa` has exactly **one** caller outside
`.bak` copies:

```cpp
// src/deep2/deep2_engine_ssvk_decode_bind_cert.cpp
engine.enableMedusa(false);
```

So `medusaEnabled_` is permanently false, `medusaDecoder_` is never constructed,
`specActive` is permanently false, and the `if (specActive)` block plus the
speculative `continue` in the production generate loop are **dead code**. They
are not broken; they are unreachable.

**Fact 2 — the KV-mirror reset it depends on crashes.**

```cpp
// Deep2Engine.cpp:1098 — RAWRXD_D2_LIFECYCLE_001_HOTFIX
// specKvMirrorReset() crashes inside the pre-built InferenceEngine_patched.lib
// when called from reset() at a generation boundary.
static const char* enableSpecKvResetEnv = std::getenv("RAWRXD_ENABLE_SPEC_KV_RESET");
if (enableSpecKvReset) { specKvMirrorReset(); }
```

Gated off by default because the underlying call raises `0xC0000409` in the
prebuilt library, reproducibly and independent of input.

**Not a stub, for the record.** `MedusaDecoder` is fully implemented in
`MedusaDecoder.hpp:26-161` as a **prompt-lookup / n-gram drafter** (longest
suffix match, then a `nextByToken` map), with a `SpeculativeCounters` structure
and an acceptance EWMA. `MedusaDecoder.cpp` is a 38-byte `// STUB` marker, but
the class is header-only, so the empty `.cpp` costs nothing. The drafter is
real; nothing turns it on, and its verification step does not exist as wired.

---

## 4. `ALL_MODEL_DISCOVERY_PATHS_PROVEN = 0`

`rawr` now builds in this tree (`RAWRXD_BUILD_CLI=ON`, `RECONF_EXIT=0`,
`BUILD_EXIT=0`), so the model-truth path was executed rather than reasoned about.

```ini
RAWRXD_RAWR_DUMP_AUTHORITY_001=ENTERED
GENERATED_FROM_SCRATCH=1
CONFIG_USED=filesystem_scan
ROOTS_SCANNED=2
ROOTS_SKIPPED_MISSING=0
ALIASES_SCANNED=0
OLLAMA_MANIFESTS_SCANNED=168
GGUF_FILES_SCANNED=75
MODELS_DISCOVERED=206
MODELS_CLASSIFIED=206
MODELS_WITH_PATH=78
VERDICT=PASS
```

The scan is real: 206 records, 168 Ollama manifests, 75 GGUF files, 78 with
resolved paths. The fix to `RawrDumpRebuild.cpp` compiles and no longer
fabricates; `--rebuild` now reports the scan's own numbers
(`ROOTS_SCANNED=2 MODELS_DISCOVERED=206 VERDICT=PASS`).

### The finding that fails the claim

```text
Scanned roots:
  C:\Users\Garrett\.ollama\models
  F:\OllamaModels
```

**Neither root is the project's own model directory.** `G:\~dev\rawrxd\models`
holds 7 GGUFs, including the two this entire certification sequence is run
against:

```text
DeepSeek-V2-Lite-Chat.Q4_K_M.gguf   10364416768
gemma3-1b-Q2_K.gguf                    699066720
llama3.2-3b-Q2_K.gguf                 1363935456
model.gguf                                4120
phi3-mini-Q2_K.gguf                    1509949440
tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf   668788096
tinyllama.gguf                          668788096
```

Consequence, measured rather than inferred:

```text
occurrences of "tinyllama" in `rawr dump --all` output   = 0
occurrences of "gemma3"   in the same output              = 1
occurrences of "DeepSeek" in the same output              = 83

rawr dump --format json tinyllama   -> "models": []      (0 records)
rawr dump --format json gemma3      -> 1 record
rawr dump --format json llama3.2    -> 1 record
```

So the catalog reports `VERDICT=PASS` over 206 models while **every model this
project actually loads is absent from it**, and a named lookup for one returns an
empty array. `VERDICT=PASS` is computed from the roots it was given; it says
nothing about whether the configured roots are the right ones. That is the same
shape as every other finding in this project: a passing measurement scoped to a
set the operator chose.

### Discovery paths that are stubs or cannot compile

| Path | State |
|---|---|
| `ModelCatalogAuthority` / `OllamaCatalogReader` / `GgufMetadataProbe` / `RawrDumpAuthority` | **WORKS** — measured above |
| `Deep2Engine::loadModel` | **WORKS** — real weights, both routes, token-for-token CPU/GPU agreement |
| `src/inference/polymorphic_loader.cpp` | bare `// STUB` file |
| `src/inference/ollama_blob_parser.cpp` | bare `// STUB` file |
| `src/engine/sovereign_engines.cpp` | bare `// STUB` file |
| `canonical/UnifiedModelLoader.cpp` | cannot compile — `sha256.h` missing |
| `core/sovereign_model_loader.cpp` | cannot compile — `RawrXD_120B_Loader_C.h` missing |
| `core/RawrXD_FeatureRegistry.cpp` | cannot compile — `RawrXD_FeatureRegistry.hpp` missing |

Eight of eleven enumerated paths are proven. Three are literally a comment, and
three more have never compiled.

---

## 5. `IDE_END_TO_END_CERTIFIED = 0`

The IDE target does not build from this source. 9 distinct errors, **one root
cause**:

```text
src/core/workspace_model.h(69,36): error C2526:
  'RawrXD_IDE_GetWorkspaceFolders': C linkage function cannot return C++ class
  'std::vector<RawrXDWorkspaceFolder, std::allocator<RawrXDWorkspaceFolder>>'
```

```cpp
extern "C" {
std::vector<RawrXDWorkspaceFolder> RawrXD_IDE_GetWorkspaceFolders();   // illegal
}
```

That one declaration cascades into every error at its call site:

```text
Win32IDE_Sidebar.cpp(264,22): error C2530: 'f': references must be initialized
Win32IDE_Sidebar.cpp(264,24): error C2143: syntax error: missing ';' before ':'
Win32IDE_Sidebar.cpp(264,56): error C2451: a conditional expression of type 'void' is not valid
Win32IDE_Sidebar.cpp(264,56): error C3312: no callable 'begin' function found for type 'void'
Win32IDE_Sidebar.cpp(264,58): error C2143: syntax error: missing ';' before ')'
Win32IDE_Sidebar.cpp(372,5):  error C2679: binary '=': no operator for std::wstring
```

### The executable in the tree is stale

```text
certbuild\bin\Release\RawrXD-Win32IDE.exe
  size     20901376
  modified 2026-10-01 17:29:55
```

That predates every change in this session. It is a leftover from a build of
source that no longer exists, and any claim resting on running it would be
describing a binary that the current tree cannot produce. This is the
stale-artifact hazard the ledger records for the binary seal — and the seal only
covers the driver, not this target.

### Correction to the recorded blocker

The ledger names `k_quant_gemv_avx512.h:264` (`__m512` assigned to `__m512i`) as
the IDE build break. **This build does not reach that error.** It fails earlier,
on `workspace_model.h:69`. The ledger's blocker is either fixed or no longer the
first failure; either way it is not what is stopping the link now.

---

## 6. `SAFE_TO_SHIP = 0`

Derived, not asserted. Four independent blockers, any one of which is
disqualifying:

```ini
1  IDE does not build                        -> no product binary
2  5 of 12 changed files have never compiled -> change is unverified
3  simulation not eliminated, 2 allow-all gates open
4  model catalog does not include the models this product loads
5  CPU and Vulkan agree with each other and are both wrong about France
```

Point 5 is unchanged from `VULKAN_ROPE_CONVENTION_001.md`: two routes agreeing
is not correctness against a reference. The CPU route still answers "The capital
of the United States" to "What is the capital of France?" — deterministic,
reproducible, and wrong.

---

## 7. Measured, and still true

For balance, these were re-verified after every change in this session and were
not affected:

```ini
PRODUCTION_GENERATE_STREAM_CPU        = WORKS   24 tokens, greedy, real weights
PRODUCTION_GENERATE_STREAM_VULKAN     = WORKS   token-for-token identical to CPU
CPU_VULKAN_24_TOKEN_AGREEMENT         = YES
MODEL_CATALOG_FILESYSTEM_SCAN         = WORKS   206 records, real paths
RAWRXD_UNSIMULATE_001_SITES_REMOVED   = 11 of 11
REAL_GENERATION_PATH_AFFECTED_BY_CLEANUP = 0
```

## 8. What would move each claim

Ordered by how much they unblock, not by effort.

| Claim | What is required | Blocker |
|---|---|---|
| `IDE_END_TO_END_CERTIFIED` | fix `workspace_model.h:69` — return a C-compatible struct or drop `extern "C"`; then rebuild and re-run ctest | one declaration |
| `ALL_CHANGED_FILES_BUILD` | supply or remove `sha256.h`, `RawrXD_120B_Loader_C.h`, `RawrXD_FeatureRegistry.hpp`, `rawrxd_sampler.h` | 4 missing headers |
| `ALL_MODEL_DISCOVERY_PATHS_PROVEN` | add `G:\~dev\rawrxd\models` as a scan root, then re-run and require `rawr dump tinyllama` to return a record | configuration, not code |
| `ALL_SIMULATION_ELIMINATED` | convert the 2 allow-all gates to fail-closed; decide whether 337 stub files are in scope | policy decision |
| `SPECULATIVE_DECODE_FUNCTIONAL` | rebuild `InferenceEngine_patched.lib` with the `specKvMirrorReset` fix, then call `enableMedusa(true)` and certify acceptance | prebuilt library |
| `SAFE_TO_SHIP` | all of the above, plus a numerical reference for the CPU route | — |
