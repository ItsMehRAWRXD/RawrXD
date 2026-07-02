// ==============================================================================
// GhostBuffer_Wrappers.cpp — C-linkage wrappers + global instance
// ==============================================================================
// Compiled with: cl /c /O2 /GS- /GR- /EHsc /Fo GhostBuffer_Wrappers.obj
// ==============================================================================

#include "GhostBuffer.hpp"

// Global instance (lives in .data section of DLL/EXE)
__declspec(dllexport) GhostBuffer g_GhostBuffer;

// C wrapper: Write event (called from MASM via GhostBuffer_WriteEvent)
extern "C" __declspec(dllexport) void GhostBuffer_WriteEvent(uint8_t type, uint64_t payload) {
    g_GhostBuffer.Write(static_cast<GhostEvent>(type), payload);
}

// Safe write path for MASM loader thread call sites that must never fault the process.
extern "C" __declspec(dllexport) int GhostBuffer_WriteEvent_Safe(uint8_t type, uint64_t payload) {
    __try {
        g_GhostBuffer.Write(static_cast<GhostEvent>(type), payload);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// C wrapper: Read single event
extern "C" __declspec(dllexport) int GhostBuffer_ReadEvent(GhostRecord* out) {
    return g_GhostBuffer.Read(out);
}

// C wrapper: Batch drain
extern "C" __declspec(dllexport) uint32_t GhostBuffer_DrainEvents(GhostRecord* out, uint32_t max_count) {
    return g_GhostBuffer.Drain(out, max_count);
}
