// unlinked_symbols_batch_010.cpp
// Batch 10: REFERENCE ONLY — all symbols owned elsewhere (LNK2005 if linked).
//
// OWNER map (see LAW_BATCH_009_010_OWNER.txt):
//   Mode* (StubGenMode..AVScanMode) → rawrxd_subsystem_api.cpp
//   SO_* streaming → rawrxd_subsystem_api.cpp (product) /
//                     streaming_orchestrator.cpp (selected GOLD paths)
//
// CMake: EXCLUDED from RawrEngine and Win32IDE. Do not re-add without
// removing matching stubs from subsystem_api (would force LNK2005).
// Digestion_scanner.asm is CMake-excluded — do not rely on linking it.
//
// This TU retained for ABI documentation of the offline-bool theater that
// previously lived here; product path must not treat it as link owner.

#if 0  // intentionally not compiled when accidentally added to a target
#include <cstdint>
extern "C" {
void StubGenMode() {}
void TraceEngineMode() {}
void CompileMode() {}
void GapFuzzMode() {}
void EncryptMode() {}
void EntropyMode() {}
void AgenticMode() {}
void UACBypassMode() {}
void AVScanMode() {}
bool SO_InitializeVulkan() { return false; }
bool SO_InitializeStreaming() { return false; }
bool SO_CreateMemoryArena(size_t, void**) { return false; }
bool SO_CreateThreadPool(int) { return false; }
bool SO_CreateComputePipelines() { return false; }
bool SO_InitializePrefetchQueue(int) { return false; }
}
#endif
