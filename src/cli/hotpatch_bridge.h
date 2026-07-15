// ============================================================================
// Hotpatch Bridge - C++ Interface to rawrxd_hotpatch_router.asm
// ============================================================================
// Provides type-safe access to the MASM hotpatch router with proper
// memory alignment and calling convention compliance.
// ============================================================================

#ifndef HOTPATCH_BRIDGE_H
#define HOTPATCH_BRIDGE_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Return codes from hotpatch operations
#define HP_SUCCESS              0
#define HP_ALREADY_PENDING      1
#define HP_INFERENCE_ACTIVE     2
#define HP_DEFERRED             2
#define HP_NO_SWAP              0
#define HP_SWAP_COMPLETED       1

// Model descriptor structure (must match ASM layout)
#pragma pack(push, 8)
typedef struct _ModelDescriptor {
    uint64_t magic;              // 0x52415752 'RAWR'
    uint64_t version;
    uint64_t modelId;
    uint64_t weightsPtr;
    uint64_t weightsSize;
    uint64_t metadataPtr;
    uint32_t metadataSize;
    uint32_t flags;
    uint64_t reserved[4];
} ModelDescriptor;
#pragma pack(pop)

#define RAWR_MODEL_MAGIC 0x524157524D444C00ULL  // "RAWRMDL\0"

// ASM exports - x64 calling convention (rcx, rdx, r8, r9)
extern uint64_t RawrXD_RequestHotpatch(ModelDescriptor* descriptor, uint64_t gpuFence);
extern uint64_t RawrXD_CheckEpochSwap(void);
extern uint64_t RawrXD_ExecuteInferenceStep(void);
extern uint64_t RawrXD_WaitForHotpatchComplete(uint64_t timeoutMs);
extern uint64_t RawrXD_ForceSyncHotpatch(ModelDescriptor* descriptor);
extern uint64_t RawrXD_InitHotpatchSystem(void);

// C++ wrapper functions with proper error handling
static inline int RequestHotpatch(ModelDescriptor* desc, uint64_t gpuFence) {
    if (!desc || desc->magic != RAWR_MODEL_MAGIC) return -1;
    return (int)RawrXD_RequestHotpatch(desc, gpuFence);
}

static inline int CheckEpochSwap(void) {
    return (int)RawrXD_CheckEpochSwap();
}

static inline int InitHotpatchSystem(void) {
    return (int)RawrXD_InitHotpatchSystem();
}

#ifdef __cplusplus
}
#endif

#endif // HOTPATCH_BRIDGE_H
