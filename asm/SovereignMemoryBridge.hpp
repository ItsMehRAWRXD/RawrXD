// ============================================================================
// SovereignMemoryBridge.hpp - Unified Memory Fabric for DDR5 + VRAM
// ============================================================================
// Treats 64GB DDR5 + 16GB VRAM as ~80GB unified working set
//
// Date: July 10, 2026
// Status: PRODUCTION
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Memory Domain Enumeration
// ============================================================================

typedef enum {
    MEMORY_DOMAIN_HOST = 0,      // Normal DDR5 RAM
    MEMORY_DOMAIN_DEVICE = 1,   // VRAM (7800XT)
    MEMORY_DOMAIN_PINNED = 2,   // Pinned host memory for fast DMA
    MEMORY_DOMAIN_UNIFIED = 3   // Hardware unified (if supported)
} MemoryDomain;

// ============================================================================
// Sovereign Buffer Handle
// ============================================================================

typedef struct {
    void*        ptr;            // Host pointer (may be mapped device memory)
    size_t       sizeBytes;      // Allocation size
    MemoryDomain domain;         // Current domain
    uint64_t     deviceHandle;   // GPU buffer handle (0 if host-only)
    uint64_t     hostHandle;     // For tracking pinned allocations
    uint32_t     flags;          // Allocation flags
    uint64_t     lastAccessTime; // For LRU eviction
    uint32_t     refCount;       // Reference counting
} SovereignBuffer;

// Buffer flags
#define BUFFER_FLAG_READ_ONLY   0x01
#define BUFFER_FLAG_WRITE_ONLY  0x02
#define BUFFER_FLAG_PERSISTENT  0x04  // Don't evict
#define BUFFER_FLAG_MAPPED      0x08  // Host-visible device memory

// ============================================================================
// Memory Bridge API
// ============================================================================

// Initialize memory bridge
int MemoryBridge_Initialize(void);

// Shutdown memory bridge
void MemoryBridge_Shutdown(void);

// Allocate buffer in specific domain
SovereignBuffer* MemoryBridge_Allocate(size_t sizeBytes, MemoryDomain domain);

// Free buffer
void MemoryBridge_Free(SovereignBuffer* buffer);

// Copy between buffers (domain-aware)
int MemoryBridge_Copy(SovereignBuffer* dst, const SovereignBuffer* src);

// Ensure buffer is in device domain (VRAM)
int MemoryBridge_EnsureOnDevice(SovereignBuffer* buffer);

// Ensure buffer is in host domain (DDR5)
int MemoryBridge_EnsureOnHost(SovereignBuffer* buffer);

// Ensure buffer is pinned (for DMA)
int MemoryBridge_EnsurePinned(SovereignBuffer* buffer);

// Get current domain
MemoryDomain MemoryBridge_GetDomain(const SovereignBuffer* buffer);

// Check if buffer is resident in domain
bool MemoryBridge_IsResident(const SovereignBuffer* buffer, MemoryDomain domain);

// Prefetch to domain (async)
int MemoryBridge_Prefetch(SovereignBuffer* buffer, MemoryDomain domain);

// Memory statistics
void MemoryBridge_GetStats(uint64_t* hostUsed, uint64_t* deviceUsed, 
                           uint64_t* pinnedUsed, uint64_t* totalAllocated);

// Evict least-recently-used device buffers to host
size_t MemoryBridge_EvictDevice(size_t targetBytes);

// ============================================================================
// C++ Wrapper
// ============================================================================

#ifdef __cplusplus

namespace Sovereign {

class MemoryBridge {
public:
    // Singleton access
    static MemoryBridge& Instance();
    
    // Initialize bridge
    bool Initialize();
    
    // Shutdown
    void Shutdown();
    
    // Allocation
    SovereignBuffer* Allocate(size_t sizeBytes, MemoryDomain domain = MEMORY_DOMAIN_HOST);
    void Free(SovereignBuffer* buffer);
    
    // Domain migration
    bool Copy(SovereignBuffer* dst, const SovereignBuffer* src);
    bool EnsureOnDevice(SovereignBuffer* buffer);
    bool EnsureOnHost(SovereignBuffer* buffer);
    bool EnsurePinned(SovereignBuffer* buffer);
    
    // Queries
    MemoryDomain GetDomain(const SovereignBuffer* buffer) const;
    bool IsResident(const SovereignBuffer* buffer, MemoryDomain domain) const;
    
    // Async operations
    bool Prefetch(SovereignBuffer* buffer, MemoryDomain domain);
    
    // Memory management
    size_t EvictDevice(size_t targetBytes);
    void GetStats(uint64_t& hostUsed, uint64_t& deviceUsed, 
                  uint64_t& pinnedUsed, uint64_t& totalAllocated) const;
    
    // Domain hints for kernels
    MemoryDomain SuggestDomain(size_t dataSize, bool frequentAccess, bool computeHeavy);

private:
    MemoryBridge() = default;
    ~MemoryBridge() = default;
    
    bool initialized_ = false;
    uint64_t hostUsed_ = 0;
    uint64_t deviceUsed_ = 0;
    uint64_t pinnedUsed_ = 0;
    uint64_t totalAllocated_ = 0;
};

} // namespace Sovereign

#endif // __cplusplus

#ifdef __cplusplus
}
#endif
