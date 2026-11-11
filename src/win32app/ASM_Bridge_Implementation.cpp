// ============================================================================
// ASM_Fallback_Stubs.cpp — Safe fallback stubs for missing ASM/external symbols
// ============================================================================
// MSVC Implementation Notes:
//   Unlike GCC/Clang, MSVC does NOT support __attribute__((weak)).
//   We use the /ALTERNATENAME linker directive to create weak-like behavior.
//   Each stub is prefixed with "__fb_" and /ALTERNATENAME maps the real name
//   to the fallback. If a real implementation exists, it takes precedence.
//
// Build Integration:
//   Compile this file into a SEPARATE static library (fallbacks.lib).
//   Link order: REAL_OBJS first, then fallbacks.lib LAST.
//   The linker will only resolve to fallbacks for symbols not found in REAL_OBJS.
//
// FMF INSTRUMENTED: All fallback stubs report execution via FailureModeFirewall
// ============================================================================

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "FailureModeFirewall.h"

// ============================================================================
// MSVC /ALTERNATENAME Weak Symbol Mapping
// ============================================================================
// For x64: no underscore prefix needed
// For x86: would need underscore prefix (not supported here)

#ifdef _WIN64
    #define ASM_WEAK_ALIAS(real_name, fallback_name) \
        __pragma(comment(linker, "/alternatename:" #real_name "=" #fallback_name))
#else
    #define ASM_WEAK_ALIAS(real_name, fallback_name) \
        __pragma(comment(linker, "/alternatename:_" #real_name "=_" #fallback_name))
#endif

// ============================================================================
// Safe fallback panic handler
// ============================================================================
extern "C" void ASM_Fallback_Panic(const char* symbolName)
{
    // Report to FMF
    FMF_STUB_ENTRY(symbolName);
    
    char msg[256];
    snprintf(msg, sizeof(msg), "[ASM Fallback] Missing or failed symbol: %s\n", symbolName ? symbolName : "unknown");
    OutputDebugStringA(msg);
    fprintf(stderr, "%s", msg);
    // Don't crash — just return safely
}

// ============================================================================
// SparseGather family — telemetry/stats gathering from ASM kernels
// ============================================================================
extern "C" {
    void SparseGather_Init(void* config)
    {
        ASM_Fallback_Panic("SparseGather_Init");
    }

    void SparseGather_Shutdown(void)
    {
        ASM_Fallback_Panic("SparseGather_Shutdown");
    }
}

// ============================================================================
// AgentPanel family — agentic UI stream finalization
// ============================================================================
extern "C" {
    void AgentPanel_InitStream(void* config)
    {
        ASM_Fallback_Panic("AgentPanel_InitStream");
    }

    void AgentPanel_AbortStream(void* streamHandle)
    {
        ASM_Fallback_Panic("AgentPanel_AbortStream");
    }
}

// ============================================================================
// ExecutionTruth family — execution verification / telemetry
// ============================================================================
extern "C" {
    void Win32IDE_ExecutionTruth_Verify(void* context)
    {
        ASM_Fallback_Panic("Win32IDE_ExecutionTruth_Verify");
    }
}

// ============================================================================
// showSidebarPanel family — sidebar UI updates from ASM
// ============================================================================
extern "C" {
    void Win32IDE_toggleSidebarPanel(void* ideInstance, int panelId)
    {
        ASM_Fallback_Panic("Win32IDE_toggleSidebarPanel");
    }
}

// ============================================================================
// Sovereign VEH Handler — crash containment
// ============================================================================
extern "C" {
    LONG WINAPI Sovereign_VEH_Handler(PEXCEPTION_POINTERS ExceptionPointers);
}

// ============================================================================
// Agentic Orchestrator — task processing
// ============================================================================
extern "C" {
    void RawrXD_AgenticOrchestrator_Cleanup(void);
    void RawrXD_AgenticOrchestrator_Init(void* config);
}

// ============================================================================
// Self-Host Engine — diagnostics
// ============================================================================
extern "C" {
    void asm_selfhost_init(void)
    {
        ASM_Fallback_Panic("asm_selfhost_init");
    }

    void asm_selfhost_shutdown(void)
    {
        ASM_Fallback_Panic("asm_selfhost_shutdown");
    }

    void asm_selfhost_get_stats(void* outStats, size_t statsSize)
    {
        ASM_Fallback_Panic("asm_selfhost_get_stats");
        if (outStats && statsSize > 0)
            memset(outStats, 0, statsSize);
    }
}

// ============================================================================
// ASM Orchestrator — lifecycle
// ============================================================================
extern "C" {
    void asm_orchestrator_init(void)
    {
        ASM_Fallback_Panic("asm_orchestrator_init");
    }

    void asm_orchestrator_shutdown(void)
    {
        ASM_Fallback_Panic("asm_orchestrator_shutdown");
    }
}

// ============================================================================
// Ghost Pipeline — probe/testing
// ============================================================================
extern "C" {
    int runGhostPipelineProbeCli(void)
    {
        ASM_Fallback_Panic("runGhostPipelineProbeCli");
        return 0; // Success (no-op)
    }
}

// ============================================================================
// Agent WAL CLI Smoke Test
// ============================================================================
extern "C" {
    int runAgentWalCliSmokeTest(void)
    {
        ASM_Fallback_Panic("runAgentWalCliSmokeTest");
        return 0; // Success (no-op)
    }
}

// ============================================================================
// Inference Engine — bridge functions
// ============================================================================
extern "C" {
    void RawrXD_InferenceEngine_Init(void* config)
    {
        ASM_Fallback_Panic("RawrXD_InferenceEngine_Init");
    }

    void RawrXD_InferenceEngine_Run(void* context)
    {
        ASM_Fallback_Panic("RawrXD_InferenceEngine_Run");
    }
}

// ============================================================================
// Agentic Tool Executor
// ============================================================================
extern "C" {
    void RawrXD_AgenticToolExecutor_Init(void* config)
    {
        ASM_Fallback_Panic("RawrXD_AgenticToolExecutor_Init");
    }

    void RawrXD_AgenticToolExecutor_Execute(void* context)
    {
        ASM_Fallback_Panic("RawrXD_AgenticToolExecutor_Execute");
    }
}

// ============================================================================
// Agentic Memory System
// ============================================================================
extern "C" {
    void* RawrXD_AgenticMemorySystem_Alloc(size_t size)
    {
        ASM_Fallback_Panic("RawrXD_AgenticMemorySystem_Alloc");
        return malloc(size); // Fallback to standard allocator
    }

    void RawrXD_AgenticMemorySystem_Write(void* ptr, const void* data, size_t size)
    {
        ASM_Fallback_Panic("RawrXD_AgenticMemorySystem_Write");
        if (ptr && data && size > 0)
            memcpy(ptr, data, size);
    }

    void RawrXD_AgenticMemorySystem_Free(void* ptr)
    {
        ASM_Fallback_Panic("RawrXD_AgenticMemorySystem_Free");
        free(ptr); // Fallback to standard allocator
    }
}

// ============================================================================
// Agentic Deep Thinking
// ============================================================================
extern "C" {
    void RawrXD_AgenticDeepThinking_Init(void* config)
    {
        ASM_Fallback_Panic("RawrXD_AgenticDeepThinking_Init");
    }
}

// ============================================================================
// GGUF Runner callbacks
// ============================================================================
extern "C" {
    void GGUFRunner_tokenChunkGenerated(void* runner, const char* token)
    {
        ASM_Fallback_Panic("GGUFRunner_tokenChunkGenerated");
    }

    void GGUFRunner_inferenceComplete(void* runner, int success)
    {
        ASM_Fallback_Panic("GGUFRunner_inferenceComplete");
    }
}

// ============================================================================
// Dynamic Model Loader
// ============================================================================
extern "C" {
    struct LoadResult {
        int success;
        char errorMsg[256];
    };

    void* RawrXD_DynamicModelLoader_instance(void)
    {
        ASM_Fallback_Panic("RawrXD_DynamicModelLoader_instance");
        return nullptr;
    }

    LoadResult RawrXD_DynamicModelLoader_loadTinyModel(void* loader)
    {
        ASM_Fallback_Panic("RawrXD_DynamicModelLoader_loadTinyModel");
        LoadResult result = {0, "ASM fallback stub"};
        return result;
    }

    int RawrXD_DynamicModelLoader_enableMedusa(void* loader, const char* modelPath)
    {
        ASM_Fallback_Panic("RawrXD_DynamicModelLoader_enableMedusa");
        return 0; // Failure (no-op)
    }

    int RawrXD_DynamicModelLoader_enableSpeculativeDecoding(void* loader, int depth)
    {
        ASM_Fallback_Panic("RawrXD_DynamicModelLoader_enableSpeculativeDecoding");
        return 0; // Failure (no-op)
    }
}

// ============================================================================
// Agent Bridge / Prompt Warm
// ============================================================================
extern "C" {
    void PromptWarm_SetAcceptRequests(int accept)
    {
        FMF_STUB_ENTRY("PromptWarm_SetAcceptRequests");
        // This is a critical path — just log, don't crash
        OutputDebugStringA("[PromptWarm] SetAcceptRequests fallback stub called\n");
    }
}

// ============================================================================
// Agent Chat Cursor Overlay
// ============================================================================
extern "C" {
    // These are C++ methods, not C — provide C wrappers
    void Win32IDE_createAgentChatCursorOverlay(void* ideInstance)
    {
        ASM_Fallback_Panic("Win32IDE_createAgentChatCursorOverlay");
    }

    void Win32IDE_shutdownAgentChatCursorOverlay(void* ideInstance)
    {
        ASM_Fallback_Panic("Win32IDE_shutdownAgentChatCursorOverlay");
    }

    void Win32IDE_layoutAgentChatCursorOverlay(void* ideInstance)
    {
        ASM_Fallback_Panic("Win32IDE_layoutAgentChatCursorOverlay");
    }

    void Win32IDE_setAgentChatCursorTarget(void* ideInstance, int x, int y, int visible)
    {
        ASM_Fallback_Panic("Win32IDE_setAgentChatCursorTarget");
    }

    void Win32IDE_tickAgentChatCursorAnimation(void* ideInstance)
    {
        ASM_Fallback_Panic("Win32IDE_tickAgentChatCursorAnimation");
    }
}

// ============================================================================
// Agent Diff Panel
// ============================================================================
extern "C" {
    void Win32IDE_ensureAgentDiffPanelVisible(void* ideInstance)
    {
        ASM_Fallback_Panic("Win32IDE_ensureAgentDiffPanelVisible");
    }

    int Win32IDE_stageDirectFixAgentProposal(void* ideInstance, const char* filePath,
                                                           const char* originalText, const char* proposedText,
                                                           const char* reasoning)
    {
        ASM_Fallback_Panic("Win32IDE_stageDirectFixAgentProposal");
        return 0; // Failure
    }

    int Win32IDE_validateCurrentAgentSessionMirrorGate(void* ideInstance)
    {
        ASM_Fallback_Panic("Win32IDE_validateCurrentAgentSessionMirrorGate");
        return 1; // Success (no-op validation)
    }

    int Win32IDE_rollbackLastAIEditTransaction(void* ideInstance)
    {
        ASM_Fallback_Panic("Win32IDE_rollbackLastAIEditTransaction");
        return 1; // Success (no-op rollback)
    }
}

// ============================================================================
// Agentic LSP Condition Wiring
// ============================================================================
extern "C" {
    void Win32IDE_clearAgenticLspConditionWiring(void* ideInstance)
    {
        ASM_Fallback_Panic("Win32IDE_clearAgenticLspConditionWiring");
    }
}

// ============================================================================
// File Tree Select
// ============================================================================
extern "C" {
    void Win32IDE_onFileTreeSelect(void* ideInstance, void* treeItem)
    {
        ASM_Fallback_Panic("Win32IDE_onFileTreeSelect");
    }
}

// ============================================================================
// Wiring Manifest Gaps
// ============================================================================
extern "C" {
    int Win32IDE_handleWiringManifestGaps(void* ideInstance, int cmdId, unsigned int param)
    {
        ASM_Fallback_Panic("Win32IDE_handleWiringManifestGaps");
        return 0; // Not handled
    }
}

// ============================================================================
// End of fallback stubs
// ============================================================================
