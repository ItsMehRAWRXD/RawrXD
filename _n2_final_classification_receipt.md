# BATCH N2 — Win32IDE Link Closure (RAWRXD_WIN32IDE_REAL_LINK_001) — FINAL CLASSIFICATION v2

Build: F:\~dev\rawrxd\build_clean_n1 · Strict lane ON (ALLOW_AGENTIC_STUB_FALLBACK=OFF,
ENABLE_MISSING_HANDLER_STUBS=OFF, STRICT_AGENTIC_REALITY=ON, LEGACY_CERTS=OFF, BUILD_WIN32IDE=ON)

## Gate Status (v24)

```
GATE=RAWRXD_WIN32IDE_REAL_LINK_001
CONFIGURE=PASS (v23/v24: 0 errors)
COMPILE=PASS (all in-IDE TUs compile, 0 C-errors)
LINK=FAIL with LNK1120: 88 unresolved
UNRESOLVED_EXTERNALS=88 (19 C + 69 C++)
FAKE_DEFINITIONS=0
SYNTHETIC_STUB_TU_CREATED=0
VERDICT=FAIL (honest) — remaining 88 classified, no fake path taken
```

## Link-closure trajectory (all measured on the same strict lane)

| Build | Change | Unresolved |
|---|---|---|
| v18 | baseline | 198 LNK lines, 118 unique names (LNK1120=186) |
| v19 | MASM obj population restored (46 ml64 rules from dec168513) | 117 unique |
| v24 | + runtime_symbol_bridge.cpp + inference_link_production.cpp + win32ide_asm_kernel_bridge.cpp + kquant_nonmsvc.cpp | **88 = 19 C + 69 C++** (LNK1120) |

## What was resolved (all REAL_IMPLEMENTATION_EXISTS — linked existing real code)

- asm_camellia256_* (12), Enterprise_* (8), native_* (9), sgemm_*/sgemv_* (4), qgemv_q4_0/q8_0 (2),
  dequant_* (4), FlashAttention_* (3), Swarm_* (9), g_* data symbols (4), DiskRecovery_* (6),
  Dbg_CaptureContext/ReadMemory/WriteMemory (3) ← runtime_symbol_bridge.cpp (62KB, 106 real bodies)
- asm_selfhost_* (14) ← inference_link_production.cpp (real C bodies)
- asm_hotpatch_* (9) + asm_snapshot_* (5) ← win32ide_asm_kernel_bridge.cpp (real bodies:
  operator new shadow allocs, mutex-guarded counters, real GGUF stat structs)
- KQuant_* (3), Quant_DequantQ4_0/Q8_0 (2), asm_kquant_cpuid_check (1) ← kquant_nonmsvc.cpp
- MASM objs: 46 .asm kernels now assemble via restored ml64 custom commands

## The 88 remaining — taxonomy locked by evidence

### C side (19) — REAL_IMPLEMENTATION_MISSING
| Family | Count | Evidence |
|---|---|---|
| QB_* (QuadBuffer streamer) | 8 | No definition body anywhere in tree or git history (only `void QB_Shutdown(){}` in excluded win32ide_link_stubs.cpp); would-be provider RawrXD_QuadBuffer_Streamer.asm is a 26-byte scaffold → 0-length .text .obj (dumpbin-verified) |
| Dbg_* (6 of 9) | 6 | WalkStack/InjectINT3/RestoreINT3/Set/ClearHardwareBreakpoint/MemoryScan only DECLARED in native_debugger_engine.cpp; bodies exist nowhere |
| HexMag_* (4) | 4 | HEAD intentionally excludes hexmag_control_plane.cpp from IDE ("CopilotRoute owns control-plane"); control plane only defines HexMag_IsInitialized/Feedback |
| IsStubFunction | 1 | Only body gated `#ifndef RAWR_HAS_MASM` (compiled out on MSVC); provider ASM_STUBDETECTOR_OBJ is an empty scaffold |

### C++ side (69) — REAL_IMPLEMENTATION_MISSING (impl TUs never compiled anywhere)
AgentOllamaClient (24B stub in ALL git history), AutonomousWorkflowEngine, LiveBinaryPatcher,
PDBManager, NativePDBParser, HotpatchSymbolProvider, LSPHotpatchBridge, VisionEncoder,
EmbeddingEngine, IDELogger (no def TU), AgenticTaskGraph, LocalReasoningEngine,
ToolGateway::invoke, TransferScheduler::schedule, StatusBar_*, EditorEngine_*GhostText, RE classes.
Excluded candidate TUs fail on headers that NEVER existed in git:
- autonomous_workflow_engine.cpp → `../agent/autonomous_subagent.hpp` (no commit)
- live_binary_patcher.cpp → `hotpatch_telemetry_safety.h` (no commit)
- pdb_lsp_bridge.cpp → `nlohmann/json.hpp` (not vendored in 3rdparty)

## Interference log (absorbed without losing evidence)

- 3 CCleaner strikes (190 / 922+1006 / 353 C1083) — all restored atomically from 9dc52741f.
- Cleanup tooling committed racing stub-deletion commits to audit-session-2-cleanup
  (964eed96f 13:09, 5e361e525 13:25, eeea75113 13:26). 964eed96f's CMakeLists is CLEAN (0 AUTO)
  and already contains the runtime_symbol_bridge patch. Patcher now bases on 964eed96f.
- 2 orphaned cl.exe held RawrXD-Win32IDE.pdb → C1041×3; killed, build proceeded.

## Fail-closed verdict

```
VERDICT=FAIL-AT-GATE (correctly reported, no synthetic stubs)
STUB_FALLBACKS=0
OLLAMA_USED=0
CEO_MAIN_COMPATIBILITY=UNPROVEN (unchanged)
NEXT: the 88 externals are REAL engineering work (write real bodies / real headers),
feeding N3 chat→Deep2 E2E. Do NOT lower the gate.
```