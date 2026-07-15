//==============================================================================
// MoEBackend_Sovereign.h - Sovereign MoE Backend Glue Layer Header
// Minimal, dependency-free C++ interface
//==============================================================================

#ifndef MOE_BACKEND_SOVEREIGN_H
#define MOEBACKEND_SOVEREIGN_H

#include "MoEBackend_ABI.h"

namespace Sovereign {
namespace Inference {

//==============================================================================
// Backend Loader
//==============================================================================

// Load the MoE DLL from the specified path (or search common paths if nullptr)
bool MoEBackend_Load(const char* path);

// Unload the MoE DLL
void MoEBackend_Unload();

// Check if the MoE DLL is loaded
bool MoEBackend_IsLoaded();

//==============================================================================
// Backend Interface
//==============================================================================

// Initialize the MoE backend (call after Load)
void MoEBackend_Initialize();

// Generate output using the MoE router
void MoEBackend_Generate(const MoEGenerateInput* in, MoEGenerateOutput* out);

// Get information about a specific expert
void MoEBackend_GetExpertInfo(unsigned int id, MoEExpertInfo* info);

// Get the trace buffer
void MoEBackend_GetTrace(MoETraceBuffer* buf);

// Get backend capabilities
void MoEBackend_GetCaps(MoEBackendCaps* caps);

//==============================================================================
// Expert Enumeration
//==============================================================================

// Get the total number of experts supported
unsigned int MoEBackend_GetExpertCount();

// Get the semantic name of an expert (e.g., "ghost_1", "core_0")
// buf must be at least 64 bytes
const char* MoEBackend_GetExpertName(unsigned int id, char* buf, size_t bufSize);

//==============================================================================
// Trace Access
//==============================================================================

// Get the number of trace entries
unsigned int MoEBackend_GetTraceCount();

// Get a specific trace entry by index
bool MoEBackend_GetTraceEntry(unsigned int index, MoETraceEntry* entry);

} // namespace Inference
} // namespace Sovereign

#endif // MOE_BACKEND_SOVEREIGN_H
