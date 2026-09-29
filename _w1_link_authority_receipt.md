# W1 Link Authority Audit — RAWRXD_WIN32IDE_REAL_LINK_001 (2026-09-28)

Fresh strict-lane tree: `F:\~dev\rawrxd\build_w1` (configure 0 errors, all 373
IDE TUs + deps compiled clean, single link attempt).

```
CONFIGURE=PASS (0 CMake errors)
COMPILE=PASS (0 C-errors across the full target graph)
LINK=FAIL with LNK1120: 91 unresolved externals
LNK_LINES=91 (each unique; first-reference recorded per symbol)
BASELINE_DELTA vs N2 (v24): 88 -> 91 (LiveBinaryPatcher gained 6 new methods:
verify_integrity, revert_last_swap, revert_trampoline, swap_implementation,
unload_module + LocalReasoningEngine path; IDELogger/statusbar families
shifted reference sites)
```

## Classified inventory (Symbol · Object File · Subsystem · Category)

### C side (19) — REAL_IMPLEMENTATION_MISSING
| Symbol | Object File | Subsystem | Category |
|---|---|---|---|
| Dbg_WalkStack, Dbg_InjectINT3, Dbg_RestoreINT3, Dbg_SetHardwareBreakpoint, Dbg_ClearHardwareBreakpoint, Dbg_MemoryScan | (via native_debugger_engine decls; referenced from IDE UI) | Utilities/Diagnostics | Missing implementation |
| HexMag_BotCount, HexMag_GetParallelAgents, HexMag_IsInitialized, HexMag_Tuner_GenerationId | hexmag_ide_link_probe.obj | Agent | Missing implementation (hexmag_control_plane intentionally excluded) |
| IsStubFunction | feature_registry.obj | Utilities | Missing implementation (gated `#ifndef RAWR_HAS_MASM`) |
| QB_Init, QB_LoadModel, QB_StreamTensor, QB_ReleaseTensor, QB_ForceEviction, QB_SetVRAMLimit, QB_GetStats, QB_Shutdown | (QuadBuffer streamer decls) | Deep2 | Missing implementation (26-byte asm scaffold, 0-length obj) |

### C++ side (72) — classified per subsystem

**LiveBinaryPatcher (12)** — unified_hotpatch_manager.obj — Agent —
`instance, initialize, install_trampoline, register_function, apply_batch,
load_module, unload_module, revert_last_swap, revert_trampoline,
swap_implementation, verify_integrity, shutdown, get_stats`
Category: implementation TU exists but fails to compile
(`hotpatch_telemetry_safety.h` never committed).

**AutonomousWorkflowEngine (3)** — unified_hotpatch_manager.obj — Agent —
instance/isRunning + internal; impl TU excluded
(`autonomous_subagent.hpp` never committed).

**AgentOllamaClient (6)** — model_bruteforce_engine.obj — Agent —
ctor/dtor/TestConnection/ListModels/ChatSync; impl TU never existed
(24B stub in all git history). Category: Missing implementation.

**LocalReasoningEngine (3)** — LocalReasoningIntegration::instance,
LocalReasoningEngine::IsRunning, ReasoningResult method — Agent — Missing
implementation TU.

**ToolGateway::invoke (1)** — Agent — Missing implementation TU.

**AgenticTaskGraph (1), runAgenticGate (1), runAgenticE2EGate (1)** —
Agentic — Missing implementation TU (AgenticE2EReceipt producer absent).

**EmbeddingEngine (5)** — instance/loadModel/indexDirectory/embed/shutdown —
Agent/Utilities — Missing implementation TU.

**VisionEncoder (4)** — instance/loadModel/shutdown + VisionResult method —
Agent/Utilities — Missing implementation TU.

**PDBManager/NativePDBParser (8)** — pdb_reference_provider.obj — Utilities
— impl TU excluded (needs `nlohmann/json.hpp`, not vendored).

**LSP Hotpatch (6)** — HotpatchSymbolProvider (instance/getAllSymbols/
rebuildIndex), LSPHotpatchBridge (instance/rebuildSymbolIndex/
refreshDiagnostics/detach) — Utilities — Missing implementation TU.

**ReverseEngineering (15)** — BinaryAnalyzer (AnalyzePE/ExtractSection/
GenerateReport), NativeDisassembler (DisassembleX64/AnalyzeFunctions/
AnalyzeExports/AnalyzeImports/ExtractStrings), RECodex (AnalyzeWithAI/
GetCompilerPatterns/GetMalwarePatterns/ScanForPatterns), NativeCompiler
(CompileToNative) — Utilities — RE-Library builds and links as a static lib
(see build log: RawrXD-RE-Library.lib) but the IDE target links the WRONG
lib (rawrxd-re-library built, but IDE references unresolved) → Category:
Library-not-linked or namespace mismatch (verify exact import list vs lib).

**IDELogger (3)** — info/warn/error — Utilities — Missing implementation TU.

**TransferScheduler::schedule (1)** — Memory — Utilities — Missing impl.

**IDE UI (6)** — StatusBar_Create/Register/Resize, EditorEngine_Set/
ClearGhostText, License::g_FeatureManifest — Win32 IDE — Missing
implementation TU.

## Batch resolution plan (W3)

- Batch A (C-side, 19): write real bodies for QB_*, Dbg_*, HexMag_*, IsStubFunction
- Batch B (Patcher/Agent, 23): create the two missing headers
  (autonomous_subagent.hpp, hotpatch_telemetry_safety.h) + AgentOllamaClient impl
- Batch C (RE + PDB + LSP + IDELogger + IDE UI, ~24): vendor nlohmann, verify
  RE lib link wiring, write IDELogger/StatusBar/GhostText impls
- Batch D (Embeddings/Vision/Transfer/Agentic, ~12): real impls

## Provenance

- Build: strict lane (STUB_FALLBACK=OFF, MISSING_HANDLER_STUBS=OFF,
  STRICT_AGENTIC_REALITY=ON, LEGACY_CERTS=OFF)
- Tree: audit-session-2-cleanup @ a288f70c5 + P0.3 (c57dc18af)
- Full error log: `_w1_link_errors.txt`; symbol list: `_w1_unres.txt`
## W2 Dependency Graph (added to receipt)

Verified by dumpbin + source inspection (not guessed):

1. RE-Library static lib builds (RawrXD-RE-Library.lib) but contains ZERO
   re_api.hpp symbols (dumpbin /LINKERMEMBER: AnalyzePE=0, DisassembleX64=0).
   Root cause: re_api.hpp declarations have NO implementing TU anywhere;
   disassembler.cpp implements a DIFFERENT decoder (Disassembler::DecodeInstruction,
   unqualified). Category: MISSING IMPLEMENTATION TU (re_api_bridge.cpp).
   win32ide_link_stubs.cpp (synthetic stub defs) correctly commented out at
   CMake L5712.

2. LiveBinaryPatcher (12): impl TU exists (live_binary_patcher.cpp, 33KB real
   code) but excluded for missing hotpatch_telemetry_safety.h (never committed).

3. AgentOllamaClient (6): no impl TU in any commit (24B stub always).

4. C-side 19 (QB_*/Dbg_*/HexMag_*/IsStubFunction): providers are empty asm
   scaffolds; real bodies needed.

5. PDB/LSP/IDELogger/StatusBar/GhostText/Embeddings/Vision/Transfer/Agentic:
   excluded or missing TUs; each has an existing real caller with real
   semantics - all are genuinely MISSING IMPLEMENTATIONS, not link wiring.

## W3 Closure (2026-09-28 19:42) — RAWRXD_WIN32IDE_REAL_LINK_001 = PASS

```
GATE=RAWRXD_WIN32IDE_REAL_LINK_001
CONFIGURE=PASS
COMPILE=PASS  (0 C-errors, all 373+ TUs)
LINK=PASS      (0 unresolved externals, LNK2019=0, LNK2001=0)
LAUNCH=PASS    (pid spawned, alive 6s, clean Stop-Process; HexMag MASM backend linked)

UNRESOLVED_EXTERNALS=0
EXE=F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.exe
EXE_BYTES=20346880
EXE_MTIME=19:42:08
BUILD_LOG=_w1_build22.txt (BUILD_EXIT=0)

STRICT_LANE=HELD
  RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=OFF
  RAWRXD_BUILD_LEGACY_CERTS=OFF

VERDICT=PASS
```

Delta path: 91 → 88 (BATCH B/C: AgentOllamaClient + IDE UI TUs) →
75 → 61 (BATCH B/C wiring of on-disk-but-unwired real TUs) →
68 (BATCH E/F: sovereign_gguf_mapper Deep2::GGMLType + lsp PatchResult +
local_reasoning planFor arity + agentic run_shell_command +
agentic_failure_detector.hpp) →
6 (BATCH G2/I: embedding/vision rewritten onto Deep2::GGUFLoader;
vision_encoder re-wired; WorkspaceGuard wired; re_api_bridge real
PE export/import walkers) →
0 (build22, clean slate after killing wedged concurrent MSBuild nodes).

### Standing debt (NOT link blockers, NOT unresolveds)
- 141 LNK4006 duplicate-definition warnings (asm_*_shutdown / asm_omega_*
  / asm_watchdog_* etc): `unlinked_symbols_batch_001.obj` and
  `win32ide_watchdog_init.obj` define symbols already in
  `gold_command_providers.obj`. `/FORCE:MULTIPLE` (ForceFileOutput=
  MultiplyDefinedSymbolOnly) picks the first definition and emits
  LNK4006. This is a dedupe cleanup, not a fail-closed violation:
  no unresolved externals are masked, no stub fallback is introduced.
- LNK4204 pdb-missing-debug-info warnings on DiskRecoveryAgent /
  vulkan_compute: those TUs have no debug info (stripped); cosmetic.

### Real implementations landed this wave (no synthetic stubs)
- src/reverse_engineering/re_api_bridge.cpp — AnalyzeExports/AnalyzeImports
  walk the real PE export/import directories via mmap'd image +
  RvaToFileOffset/PePtr (no stub returns).
- src/core/embedding_engine.cpp + vision_encoder.cpp — rebound to the
  real Deep2::GGUFLoader (memory-mapped shards, listTensors/getTensor);
  the phantom StreamingGGUFLoader zone contract is gone.
- src/core/win32ide_debugger_bridge.cpp + win32ide_quadbuffer_bridge.cpp —
  real Win32 DebugActiveProcess/ReadProcessMemory bodies + real VRAM
  residency registry.
- src/agent/local_reasoning_engine_real.cpp — deterministic multi-phase
  LocalReasoningEngine (pImpl, no LLM-stub fallback).
- src/runtime/memory/TransferScheduler.cpp — real priority drain +
  bandwidth throttle worker.
- src/agent/autonomous_subagent.{hpp,cpp} — real SubagentTask dispatcher.
- src/core/agentic_task_graph.cpp — real run_shell_command subprocess.
- src/agent/agentic_failure_detector.hpp — real failure classifier.

Commit: 07a2d7a8b (HEAD == origin/model-correctness).

## W3 Dedupe (2026-09-28 19:57) — Stub-wins violation FIXED

```
GATE=RAWRXD_STUB_FREE_BUILD_001 (partial)
LNK4006_DELTA=141 -> 67
EMPTY_STUB_WINS=0  (was 74: 59 gold + 12 camellia + 3 subsystem)
REAL_VS_REAL_ODR=67  (remaining: batch-vs-omega_asm_native_kernel, batch-vs-win32ide_asm_kernel_bridge)
UNRESOLVED_EXTERNALS=0
COMPILE_ERRORS=0
EXE_BYTES=20353024
LAUNCH=PASS (pid alive 6s, HexMag MASM backend)
BUILD_LOG=_w1_build23.txt (BUILD_EXIT=0)
COMMIT=e62b3876d
```

### Fail-closed violation discovered + fixed
/FORCE:MULTIPLE (ForceFileOutput=MultiplyDefinedSymbolOnly) picks the FIRST
definition on the link line. Empty no-op stubs `{}` in three TUs were
winning over REAL bodies in unlinked_symbols_batch_*.cpp:

1. gold_command_providers.cpp — 59 empty asm_neural/omega/mesh/speciator/
   hwsynth stubs (real bodies in batch_001/005/006/007/008/009).
2. inference_link_production.cpp — 12 empty asm_camellia256_* stubs (real
   key-derivation + set_key body in runtime_symbol_bridge.cpp).
3. rawrxd_subsystem_api.cpp — AgenticMode/AgentTraceMode/AD_ProcessGGUF
   empty stubs (real bodies in batch_009/010/011).

Effect: the shipped exe was silently running no-ops for asm_hwsynth_init,
asm_camellia256_init, AgenticMode, AD_ProcessGGUF, etc. despite real
implementations existing in the build. /FORCE:MULTIPLE hid this behind
LNK4006 "second definition ignored" warnings.

Fix: removed the 74 empty stubs; retained 8 unique symbols not provided
by any batch (BeaconSend, RunInference, asm_*_get_stats, asm_speciator_evaluate).
Forward-declared AD_ProcessGGUF for the internal call in rawrxd_subsystem_api.

### Remaining 67 LNK4006 (real-vs-real ODR, NOT stub-wins)
- asm_omega_* (15): batch_005/006 vs omega_asm_native_kernel.cpp — both
  have real bodies with state + mutex; canonical owner is a design decision.
- asm_perf_* (5): batch_001 vs win32ide_asm_kernel_bridge — both real.
- asm_camellia256_auth_* (2): batch_005 (4-arg bool) vs win32ide_asm_kernel_bridge
  (2-arg int) — extern C signature collapse; gold_link_closure.cpp calls the
  4-arg version but gets the 2-arg body.
- asm_lsp_bridge_shutdown, asm_gguf_loader_close (2): batch_001 vs
  win32ide_asm_kernel_bridge — both real mutex+state cleanup.
- asm_*_get_stats (5): gold_command_providers (retained) vs batch_007/008/009.

These require an architectural ownership decision (which TU is canonical for
each family) — not a stub-removal fix.

---

## W5 Runtime Launch Receipt — 19:59 (post-build23)

```
GATE=RAWRXD_WIN32IDE_RUNTIME_LAUNCH_001
EXE=F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.exe
EXE_BYTES=20353536 (post-W2-dedupe build23, BUILD_EXIT=0)
PROCESS_CREATED=1 (pid 19264)
ALIVE_6S=1
ENTRYPOINT_ERROR=0
EARLY_CRASH=0
HEXMAG_BACKEND=MASM
HEXMAG_LINKED=1
HEXMAG_INIT=0  (probe state at boot: counters real, uninitialized by design — control-plane Init wires them on first use)
STOPPED_CLEAN=1 (Stop-Process graceful)
VERDICT=PASS
```

Dedupe state after worker W2 sweep: LNK4006 141 → 67
(remaining 67 = real-vs-real ODR: batch_* vs omega_asm_native_kernel /
win32ide_asm_kernel_bridge, camellia_auth signature collapse —
explicit architectural ownership debt tracked under RAWRXD_STUB_FREE_BUILD_001).
Unresolved externals remain 0 (no LNK2001/LNK1120 in build23).

---

## W6 Clean-Link Certification Receipt — 20:24 (build30)

```
GATE=RAWRXD_WIN32IDE_CLEAN_LINK_001
LINK_OPTIONS=/FORCE:MULTIPLE REMOVED (CMakeLists L6979 deleted)
LNK2001=0
LNK2019=0
LNK1120=0
LNK4006=0   (dedupe debt: 141 -> 67 -> 0)
LNK4088=0   (no force-generated image warning)
EXE=F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.exe
EXE_BYTES=20359168
EXE_MTIME=20:23:48
BUILD_LOG=_w1_build30.txt (BUILD_EXIT=0)

RELINK=PASS (no-FORCE certification: duplicate-symbol dedupe complete)
LAUNCH=PASS (pid 26940, alive 6s, HexMag MASM backend proof, clean Stop-Process)
VERDICT=PASS
```

Dedupe final leg this wave:
- rawrxd_subsystem_api.cpp now defines the CANONICAL SO_* family with REAL
  bodies (path validation, real VRAM arena via operator new, real streaming
  state machine) and its call sites adapted (no return-0 stubs).
- unlinked_symbols_batch_{010,011}.cpp hold the batch-variant bodies with
  compatibility notes (signatures intentionally diverge; canonical contract
  documented in rawrxd_subsystem_api.cpp).
- Remaining LNK4204 warnings are PDB-debug-info cosmetics on stripped TUs.
