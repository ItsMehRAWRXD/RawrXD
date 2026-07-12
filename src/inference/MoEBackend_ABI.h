//==============================================================================
// MoEBackend_ABI.h - C++ Header matching MASM MoE DLL ABI
//
// This header provides the C++ interface to the pure x64 MASM MoE DLL.
// No external dependencies - just raw ABI matching.
//==============================================================================

#ifndef MOE_BACKEND_ABI_H
#define MOE_BACKEND_ABI_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Capability Flags (must match ExpertCaps bitmask in MASM)
//==============================================================================

#define MOE_CAP_GHOST   0x01    // Ghost text / speculative
#define MOE_CAP_LATENT  0x02    // Latent / conditional activation
#define MOE_CAP_SHADOW  0x04    // Shadow / fallback routing
#define MOE_CAP_SWARM   0x08    // Swarm / parallel activation
#define MOE_CAP_PREFETCH 0x10   // Prefetch / lookahead
#define MOE_CAP_ECHO    0x20    // Echo / refinement
#define MOE_CAP_MERGE   0x40    // Merge / aggregation
#define MOE_CAP_SPECULATIVE 0x80 // Speculative branching

//==============================================================================
// Structs (must match MASM layout exactly)
//==============================================================================

#pragma pack(push, 8)

struct MoEExpertInfo {
    uint32_t id;           // Expert ID (0-63)
    uint32_t caps;         // Capability bitmask
};

struct MoETraceEntry {
    uint32_t expertId;     // Which expert fired
    uint32_t confidence;   // Router confidence (0-1000)
    uint32_t caps;           // Expert capabilities
};

#define MOE_TRACE_MAX_ENTRIES 256

struct MoETraceBuffer {
    uint32_t count;                            // Number of entries
    MoETraceEntry entries[MOE_TRACE_MAX_ENTRIES]; // Trace entries
};

struct MoEGenerateInput {
    void* logits;          // Pointer to logits array
    void* kv;              // Pointer to KV cache
    uint32_t token;        // Current token ID
    uint32_t _pad;         // Padding for 8-byte alignment
};

struct MoEGenerateOutput {
    uint32_t expertId;     // Selected expert
    uint32_t confidence;   // Confidence score
    uint32_t caps;           // Expert capabilities
};

struct MoEBackendCaps {
    uint32_t version;           // Backend version
    uint32_t maxExperts;        // Maximum experts supported
    uint32_t maxTraceEntries;   // Maximum trace entries
};

#pragma pack(pop)

//==============================================================================
// DLL Function Types
//==============================================================================

typedef void (*MoE_InitializeFn)(void);
typedef void (*MoE_GenerateFn)(const MoEGenerateInput* in, MoEGenerateOutput* out);
typedef void (*MoE_GetExpertInfoFn)(uint32_t id, MoEExpertInfo* info);
typedef void (*MoE_GetTraceFn)(MoETraceBuffer* buf);
typedef void (*MoE_GetBackendCapsFn)(MoEBackendCaps* caps);

//==============================================================================
// Function Declarations (for static linking)
// For dynamic loading, use GetProcAddress with the types above
//==============================================================================

// These are exported from MoE.dll
void MoE_Initialize(void);
void MoE_Generate(const MoEGenerateInput* in, MoEGenerateOutput* out);
void MoE_GetExpertInfo(uint32_t id, MoEExpertInfo* info);
void MoE_GetTrace(MoETraceBuffer* buf);
void MoE_GetBackendCaps(MoEBackendCaps* caps);

#ifdef __cplusplus
}
#endif

#endif // MOE_BACKEND_ABI_H
