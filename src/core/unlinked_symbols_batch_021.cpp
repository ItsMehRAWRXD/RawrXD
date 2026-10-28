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
// PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0

#include <windows.h>
#include <cstdint>

struct CommandContext;
struct CommandResult;
class Win32IDE;

// ---- C-linkage: no other Win32IDE definition (Ship coordinator API + bridges) ----
extern "C" {
void SetCompletionBackendNative(void*) {}

struct AgentCoordinator;
AgentCoordinator* CreateAgentCoordinator() { return nullptr; }
void DestroyAgentCoordinator(AgentCoordinator*) {}
int AgentCoordinator_Initialize(AgentCoordinator*, const char*) { return 0; }
int AgentCoordinator_TryDequeueTask(AgentCoordinator*, char*, int) { return 0; }

int BraidedLoader_Init(const char*) { return 0; }
void BraidedLoader_Shutdown() {}
}
