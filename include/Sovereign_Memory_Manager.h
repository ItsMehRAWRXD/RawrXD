// ============================================================================
// Sovereign Memory Manager — Header Interface
// Hardware-Direct Arena Allocator for RDNA3 GPU Inference
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Arena Lifecycle
// ============================================================================

/// Initialize the sovereign memory arena
/// @param size Size in bytes (0 = default 4GB)
/// @return true on success, false on failure
bool SovereignArena_Initialize(size_t size);

/// Shutdown and release the arena
void SovereignArena_Shutdown(void);

/// Reset arena (zero memory, reset offset) for model hot-swap
void SovereignArena_Reset(void);

// ============================================================================
// Allocation
// ============================================================================

/// Allocate from arena with custom alignment
/// @param size Size in bytes
/// @param alignment Alignment boundary (power of 2, 0 = default 256)
/// @return Pointer to aligned memory, or nullptr on OOM
void* SovereignArena_Allocate(size_t size, size_t alignment);

/// Allocate weight tensor (256-byte aligned for RDNA3)
/// @param tensor_size Size of weight tensor in bytes
/// @return Aligned pointer, or nullptr on OOM
void* SovereignArena_AllocateWeights(size_t tensor_size);

// ============================================================================
// State Queries
// ============================================================================

/// Get arena base address
void* SovereignArena_GetBase(void);

/// Get total arena size
size_t SovereignArena_GetSize(void);

/// Get currently used bytes
size_t SovereignArena_GetUsed(void);

/// Check if arena is initialized
bool SovereignArena_IsInitialized(void);

// ============================================================================
// Diagnostics (SOVEREIGN_VERIFY_RESIDENCY must be defined)
// ============================================================================

#ifdef SOVEREIGN_VERIFY_RESIDENCY
/// Verify physical residency of a memory range
bool SovereignArena_VerifyResidency(void* ptr, size_t size);

/// Print arena statistics to stdout
void SovereignArena_DumpStats(void);
#endif

#ifdef __cplusplus
}
#endif
