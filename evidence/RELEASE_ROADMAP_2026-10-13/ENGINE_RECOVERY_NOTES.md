# Deep2 Engine Link Recovery — Working Notes

Status: in progress. Baseline at session start: **269 unresolved externals**
(`evidence/RELEASE_ROADMAP_2026-10-13/RECOVERY_SCOPE.md`).

## Current state

| Metric | Value |
|---|---|
| Compile errors (`error C*`) | 0 |
| Unique unresolved externals | 90 (see `evidence/RELEASE_ROADMAP_2026-10-13/unresolved_current.txt`) |
| Link log | `evidence/RELEASE_ROADMAP_2026-10-13/engine_link_build.log` |

Build command used:

```
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cmake.exe --build build_gate_recovery_20261013 --config Release --target rawrxd_deep2_engine --verbose
```

## Root causes fixed

1. **`GGUFLoadResult` namespace conflict (C2874).** `src/deep2/GGUFLoader.hpp:1030`
   deliberately defines `GGUFLoadResult` at *global* scope and aliases it into
   `namespace Deep2` (`using ::GGUFLoadResult;`, line 59).
   `src/deep2/DynamicPersistentModelManifest.hpp:29` and
   `src/deep2/ReverseHotpatchEngine.hpp:36` each forward-declared a *separate*
   `Deep2::GGUFLoadResult`, which collided with the alias. Both forward
   declarations were moved to global scope so they name the same type.

2. **Missing `ggml-common.h` include.** `QK4_0`, `QK_K`, `block_q4_0`,
   `block_iq2_xxs` etc. live in `3rdparty/ggml/src/ggml-common.h`, which is not
   on any include path. `MoEWeightsLoader.cpp` and `ReverseHotpatchEngine.cpp`
   now include it with `GGML_COMMON_DECL_CPP` defined, and
   `3rdparty/ggml/src` is on the engine target's include path.

3. **The `vulkan_compute.h` shadow (C2027).** An unqualified
   `#include "vulkan_compute.h"` binds to `src/deep2/vulkan_compute.h`
   (`Deep2::VulkanCompute`) because `src/deep2` precedes `include`. Code typed on
   `CPUInference::VulkanCompute` therefore saw an incomplete type.
   `include/vulkan_compute_cpu_ns.hpp` is the authoritative declaration and
   includes both headers path-qualified. `K2GpuStreamCopy.cpp`, `K2MLA_GpuGemv.cpp`
   and `MoEWeightProxy.cpp` now include it instead.

4. **`ollama_blob_parser.h` had no implementation.** Declared a pimpl with no
   definition anywhere. `src/deep2/ollama_blob_parser.cpp` now implements
   `OllamaBlobParser` (ctor/dtor/`parseBlobToGGUF`/`extractGGUFToFile`) by reading
   real bytes: it locates the GGUF magic inside an Ollama blob, validates the
   GGUF version, and materialises an embedded payload to a temp file.

5. **`Deep2Engine` members declared but never defined.** `resetGpuForwardCounters`,
   `gpuResidentDecodeEnabled`, `forwardTokenAllLayers`, `emitHotpathWitnesses` and
   `emitLiveDecodeWitnesses` are declared in `src/Deep2Engine.h:471-483` and called
   from `Deep2Engine.cpp` but had no body.
   `src/deep2/Deep2Engine_missing_members.cpp` defines them from real state
   (`gpuFwd_`, `gpuFwdCommitted_`, the same layer loop the B3_StageDigest path
   runs inline, and the real `Deep2GpuForward_Emit` witness emitter).

6. **`ElasticResidencyManager` path was wrong.** An earlier CMake edit referenced
   a non-existent `src/deep2/src/deep2/ElasticResidencyManager.cpp`. The real file
   is `src/deep2/ElasticResidencyManager.cpp`.

## Implementations written

| File | Covers |
|---|---|
| `src/deep2/ollama_blob_parser.cpp` | `rawrxd::ollama::OllamaBlobParser` |
| `src/deep2/Deep2Engine_missing_members.cpp` | 5 `Deep2Engine` members |
| `src/deep2/TrailBrake.cpp` | `Deep2::TrailBrake`, `GetTrailBrake`, drift/anchors |
| `src/deep2/K2MLA_telemetry.cpp` | **superseded — see collision note** |
| `src/deep2/lavapath/FreeTokenMicroZone.cpp` | `Deep2::freetoken::*` |
| `src/deep2/lavapath/FutureConsumerSpace.cpp` | `Deep2::future::*` |

## COLLISION WARNING — duplicate symbol definitions

`src/deep2/K2MLA_telemetry.cpp` (written in this recovery pass) defines the same
symbols as files authored concurrently for the same link:

| `K2MLA_telemetry.cpp` defines | Concurrent file also defines |
|---|---|
| `MLA_FusedQ4KT_Wanted`, `MLA_FusedQ4KT_NowUs`, `MLA_FusedQ4KT`, `MLA_FusedQ4KT_Reset`, `MLA_FusedQ4KT_Emit`, `MLA_Note*` | `src/deep2/K2MLA_FusedQ4KT.cpp` |
| `MLA_QaPathForce`, `MLA_QaAllowFused`, `MLA_QaWantFused`, `MLA_QaCrit_*` | `src/deep2/K2MLA_QaCritical.cpp` |
| `MLA_QPathDevice_NoteOk/NoteFail/Emit` | `src/deep2/K2MLA_QPathDevice.cpp` |
| `LogitsLineage_*` | `src/deep2/K2LogitsLineage.cpp` |

`K2MLA_telemetry.cpp` has therefore been **removed from the engine's source
list in `CMakeLists.txt`**; it must not be re-added while those four files exist,
or the link fails with LNK2005 (redefinition). Recommend deleting it once the
concurrent files are confirmed good, to remove the trap.

## Remaining unresolved groups (90 unique)

- `CPUInference::VulkanCompute::*` — 23 symbols (the console adapter defines
  `InitializeSolo` but none of the dispatch/arena/host-io members).
- `Deep2::LivePath_*` — 13.
- `Deep2::DualStick*`, `Streamer*` — ~14.
- `Deep2::PatchOperationGuard`, `ScopedWatchdog`, `SHA256Checksum`, `PatchSafety`,
  `CrashRecovery` — 9.
- `Deep2::MARS::TensorGraph::*`, `MARSController::PlaceTensor` — 4.
- `Deep2::Exec::*` — 4.
- `Deep2::K2LivePolicy_*` — 3.
- Also `K2NativeStreamGate::Run`, `K2GpuStreamCopy_UploadOverlap`,
  `K2ValidateLineage`, `Deep2GenerateStream`, `Deep2MultiGpu_ApplyCostWeightedCut`,
  `Fused_LawResetDepth`, `rawrxd::AmdGpuPowerTelemetryAvailable`,
  `rawrxd::GpuPowerValidForPolicy`.

## Notes for the next pass

- `Deep2Engine::loadWeights(const void*, size_t)` intentionally returns `false`
  and directs callers to `loadModel(ggufPath)`. Do **not** replace it with a
  `return true`; the in-memory ownership rules have not been established.
- `engine_subsystems.cpp` already owns `ProductionProfiler` and
  `ToroidalKVCache`. Do not duplicate them.
- `src/deep2/NVMeStream.h` is 11588 bytes (~200 lines); a reported error at line
  230 cannot refer to it — check `NVMeStream.cpp` or an included header.
- Prefer one TU per subsystem. `K2MLA_telemetry.cpp` is the cautionary example of
  two TUs defining the same contract.
- Build with `build_gate_recovery_20261013` (Ninja Multi-Config, MSVC 19.44,
  cmake 4.4). `--clean-first` perturbs other worktrees; build incrementally.
