// rawr_linear_allocator.h
// C/C++ interface to the sovereign VirtualAlloc-based linear allocator
//
// Usage:
//   RawrLinearAlloc_Init(0);
//   void* arena = RawrLinearAlloc_InitArena(6ULL * 1024 * 1024 * 1024); // 6GB reserve
//   RawrLinearAlloc_CommitArena(arena, 0, 512*1024*1024, PAGE_READWRITE); // commit 512MB
//   ... use arena ...
//   RawrLinearAlloc_ReleaseArena(arena);
//

#ifndef RAWR_LINEAR_ALLOCATOR_H
#define RAWR_LINEAR_ALLOCATOR_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Core allocator API (VirtualAlloc backend)
// ---------------------------------------------------------------------------

// Initialize allocator. Enables SeLockMemoryPrivilege for large pages.
// Returns 1 on success, 0 on failure.
int RawrLinearAlloc_Init(uint32_t flags);

// Allocate a standalone block. Attempts MEM_LARGE_PAGES, falls back to 4KB pages.
// Returns aligned pointer or NULL.
void* RawrLinearAlloc_Alloc(size_t size);

// Free a standalone block allocated with RawrLinearAlloc_Alloc.
// Returns 1 on success.
int RawrLinearAlloc_Free(void* ptr);

// Realloc for standalone blocks (alloc + copy + free).
// Returns new pointer or NULL.
void* RawrLinearAlloc_Realloc(void* ptr, size_t new_size);

// Get stats: uint64_t[3] = {allocCount, freeCount, largePageCount}
void RawrLinearAlloc_GetStats(uint64_t* out_stats);

// ---------------------------------------------------------------------------
// Arena API (reserve/commit/release for model mapping)
// ---------------------------------------------------------------------------

// Reserve a contiguous virtual address range (no physical backing yet).
// Size is rounded up to 2MB. Returns base pointer or NULL.
void* RawrLinearAlloc_InitArena(size_t reserve_size);

// Commit a sub-range of a reserved arena with specified protection.
// offset and size are rounded to 4KB boundaries.
// protect: 0x02 = PAGE_READONLY, 0x04 = PAGE_READWRITE
// Returns 1 on success.
int RawrLinearAlloc_CommitArena(void* arena_base, size_t offset, size_t size, uint32_t protect);

// Release entire arena reservation.
// Returns 1 on success.
int RawrLinearAlloc_ReleaseArena(void* arena_base);

// ---------------------------------------------------------------------------
// Constants (mirror Windows API values for convenience)
// ---------------------------------------------------------------------------
#define RAWR_PAGE_READONLY     0x02
#define RAWR_PAGE_READWRITE    0x04

#ifdef __cplusplus
}
#endif

#endif // RAWR_LINEAR_ALLOCATOR_H
