// =============================================================================
// sovereign_loader_mmap.h
// Zero-Copy MMAP-Based Model Loader Header
// =============================================================================

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Types
// =============================================================================

typedef void* SovereignMMAPHandle;

typedef struct {
    size_t total_mapped_mb;      // Total virtual memory mapped
    size_t resident_mb;          // Actually resident in RAM
    uint32_t num_mappings;       // Number of active mappings
    float compression_ratio;     // If using compressed MMAP
} SovereignMMAPStats;

// =============================================================================
// Core API
// =============================================================================

// Open a file via memory mapping
// filepath: Path to the model file
// prefetchCritical: If true, prefetch embeddings and early layers
// Returns: Handle to the mapped file, or NULL on error
__declspec(dllexport) SovereignMMAPHandle Sovereign_MMAP_Open(const char* filepath, bool prefetchCritical);

// Close a memory-mapped file
__declspec(dllexport) void Sovereign_MMAP_Close(SovereignMMAPHandle handle);

// Get pointer to data at offset
__declspec(dllexport) void* Sovereign_MMAP_GetPointer(SovereignMMAPHandle handle, size_t offset);

// Get total size of mapped file
__declspec(dllexport) size_t Sovereign_MMAP_GetSize(SovereignMMAPHandle handle);

// Prefetch a range of pages into RAM
__declspec(dllexport) void Sovereign_MMAP_Prefetch(SovereignMMAPHandle handle, size_t offset, size_t size);

// Prefetch a specific layer (requires layer metadata)
__declspec(dllexport) void Sovereign_MMAP_PrefetchLayer(SovereignMMAPHandle handle, uint32_t layerIdx);

// =============================================================================
// Statistics
// =============================================================================

// Get total mapped memory across all handles
__declspec(dllexport) size_t Sovereign_MMAP_GetTotalMappedMemory(void);

// Get estimated resident memory
__declspec(dllexport) size_t Sovereign_MMAP_GetResidentMemory(void);

// Get detailed statistics
__declspec(dllexport) void Sovereign_MMAP_GetStats(SovereignMMAPStats* stats);

// Check if a specific page is resident in RAM
__declspec(dllexport) bool Sovereign_MMAP_IsPageResident(SovereignMMAPHandle handle, size_t offset);

// =============================================================================
// Constants
// =============================================================================

#define SOVEREIGN_MMAP_PAGE_SIZE       4096
#define SOVEREIGN_MMAP_PREFETCH_SIZE   (512 * 1024 * 1024)  // 512MB default
#define SOVEREIGN_MMAP_CRITICAL_LAYERS 4

#ifdef __cplusplus
}
#endif
