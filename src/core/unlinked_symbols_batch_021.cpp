// unlinked_symbols_batch_021.cpp
// Quintile D+E: keep ONLY symbols with no other Win32IDE owner.
// ODR-omitted (real owners linked separately — do not redefine here):
//   AnnotationOverlay → src/win32app/AnnotationOverlay.cpp
//   AppendANSIToRichEdit → src/ANSIParser.cpp
//   SettingsManager → product SettingsManager TU (not this stub)
//   Deep2_SwiGLU / Deep2_RMSNorm → src/deep2/Deep2Engine.cpp
//   Deep2Discovery::GetPreferredBackend → src/deep2/Deep2Discovery.cpp
//   CRDTBuffer → src/collab/crdt_buffer.* / Win32IDE_Collab
//   ModelConversionDialog / handleAIStopGeneration → product GUI / command_handlers
//   BraidedLoader_Init(BraidedLoader*, WCHAR*) → src/inference/BraidedModelLoader.c
// AgentCoordinator C ABI: Ship/RawrXD_AgentCoordinator.h (Ship/*.cpp stripped empty).
// PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
// UNLINKED_STUB_GATE_CONTINUOUS_001 — fail-close fake success (no return-0 theater).

#include "../../Ship/RawrXD_AgentCoordinator.h"

#include <cstdint>
#include <windows.h>

// ---- Completion backend registration (VAL-063 surface) ----
// Stores native engine ptr only. Does NOT authorize GhostText product absorb.
// GhostText ABSORB=NOT_AUTHORIZED (B421 witness-only). SOURCE_WIRED storage ≠ absorb.
static void* g_nativeCompletionBackend = nullptr;

extern "C" void* GetCompletionBackendNative(void) {
    return g_nativeCompletionBackend;
}

extern "C" bool SetCompletionBackendNative(void* engine_ptr) {
    g_nativeCompletionBackend = engine_ptr;
    if (engine_ptr == nullptr) {
        OutputDebugStringA(
            "[AICompletion] SetCompletionBackendNative: cleared (FAIL_CLOSED)\n");
        return false;
    }
    OutputDebugStringA(
        "[AICompletion] SetCompletionBackendNative: ptr stored SOURCE_WIRED "
        "(GhostText ABSORB=NOT_AUTHORIZED)\n");
    return true;
}

// ---- AgentCoordinator C API — ABI matches Ship/RawrXD_AgentCoordinator.h ----
// Ship/RawrXD_AgentCoordinator.cpp is intentionally empty; Full Source not linked.
// Create returns nullptr → Initialize never succeeds → no fake pipeline wire.
extern "C" {

AgentCoordinatorHandle CreateAgentCoordinator(void) {
    OutputDebugStringA(
        "[AgentCoordinator] Create FAIL_CLOSED — Ship TU empty; no real coordinator\n");
    return nullptr;
}

void DestroyAgentCoordinator(AgentCoordinatorHandle coord) {
    (void)coord;
}

BOOL AgentCoordinator_Initialize(AgentCoordinatorHandle coord) {
    (void)coord;
    // BOOL 0 = FALSE. Never return non-zero without a live coordinator object.
    OutputDebugStringA("[AgentCoordinator] Initialize FAIL_CLOSED\n");
    return FALSE;
}

void AgentCoordinator_Shutdown(AgentCoordinatorHandle coord) {
    (void)coord;
}

int AgentCoordinator_SubmitTask(AgentCoordinatorHandle coord,
                                const wchar_t* description, int priority) {
    (void)coord;
    (void)description;
    (void)priority;
    return -1;
}

int AgentCoordinator_GetPendingTaskCount(AgentCoordinatorHandle coord) {
    (void)coord;
    return 0;
}

BOOL AgentCoordinator_TryDequeueTask(AgentCoordinatorHandle coord,
                                     wchar_t* descBuffer, int descBufferLen,
                                     int* outPriority) {
    (void)coord;
    (void)descBuffer;
    (void)descBufferLen;
    (void)outPriority;
    return FALSE;
}

// Orphan 1-arg BraidedLoader_Init — real owner is BraidedLoader_Init(BraidedLoader*, WCHAR*).
// Return 0 so bool-style `if (!BraidedLoader_Init(...))` treats as fail (never success theater).
int BraidedLoader_Init(const char* /*path*/) {
    OutputDebugStringA(
        "[BraidedLoader] orphan BraidedLoader_Init(const char*) FAIL_CLOSED; "
        "use BraidedModelLoader.c\n");
    return 0;
}

void BraidedLoader_Shutdown(void) {}

}  // extern "C"
