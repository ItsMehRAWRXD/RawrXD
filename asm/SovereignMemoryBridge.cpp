// ============================================================================
// SovereignMemoryBridge.cpp - Unified Memory Fabric Implementation
// ============================================================================
// Bridges DDR5 RAM and VRAM through Titan DMA
//
// Date: July 10, 2026
// ============================================================================

#include "SovereignMemoryBridge.hpp"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <windows.h>

// Titan DMA entry points (from MASM)
extern "C" {
    typedef struct {
        uint32_t operationType;
        uint64_t sourceBuffer;
        uint64_t destBuffer;
        uint64_t transferSize;
        uint64_t startTimeUs;
        uint64_t endTimeUs;
        uint32_t throughputMBps;
        uint32_t status;
        uint32_t errorCode;
        uint64_t callbackFunc;
        uint64_t callbackData;
        uint64_t pinnedMemoryId;
        uint64_t stagingBufferId;
    } GPU_COPY_OPERATION;
    
    int Titan_PerformCopy(GPU_COPY_OPERATION* op, uint32_t flags);
    int Titan_PerformDMA(void* dmaDesc, uint32_t maxRetries);
}

namespace Sovereign {

// ============================================================================
// Internal State
// ============================================================================

struct BridgeState {
    bool initialized = false;
    uint64_t hostUsed = 0;
    uint64_t deviceUsed = 0;
    uint64_t pinnedUsed = 0;
    uint64_t totalAllocated = 0;
    
    // Tracking allocations for eviction
    std::vector<SovereignBuffer*> deviceBuffers;
    std::vector<SovereignBuffer*> pinnedBuffers;
    
    // Configuration
    size_t deviceCapacity = 16ULL * 1024 * 1024 * 1024;  // 16GB VRAM
    size_t hostCapacity = 64ULL * 1024 * 1024 * 1024;     // 64GB DDR5
    size_t pinnedCapacity = 4ULL * 1024 * 1024 * 1024;   // 4GB pinned
};

static BridgeState g_state;

// ============================================================================
// Helper Functions
// ============================================================================

static uint64_t GetTimestamp() {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (count.QuadPart * 1000000ULL) / freq.QuadPart;
}

static void* AllocateHostMemory(size_t size) {
    // Use aligned allocation for SIMD
    return _aligned_malloc(size, 64);
}

static void FreeHostMemory(void* ptr) {
    _aligned_free(ptr);
}

static void* AllocatePinnedMemory(size_t size) {
    // VirtualAlloc with MEM_LARGE_PAGES for pinned/pinned behavior
    return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static void FreePinnedMemory(void* ptr, size_t size) {
    VirtualFree(ptr, 0, MEM_RELEASE);
}

// Stub for device allocation - would integrate with Vulkan/DirectX
static uint64_t AllocateDeviceMemory(size_t size) {
    // TODO: Integrate with Vulkan/DirectX allocator
    // For now, return a dummy handle
    static uint64_t nextHandle = 1;
    return nextHandle++;
}

static void FreeDeviceMemory(uint64_t handle) {
    // TODO: Free device memory
}

static void* MapDeviceMemory(uint64_t handle) {
    // TODO: Map device memory to host address space
    // For now, allocate host memory as placeholder
    return AllocateHostMemory(4096); // Placeholder
}

static void UnmapDeviceMemory(void* ptr) {
    FreeHostMemory(ptr);
}

// ============================================================================
// Memory Bridge Implementation
// ============================================================================

MemoryBridge& MemoryBridge::Instance() {
    static MemoryBridge instance;
    return instance;
}

bool MemoryBridge::Initialize() {
    if (g_state.initialized) {
        return true;
    }
    
    printf("[MemoryBridge] Initializing unified memory fabric...\n");
    printf("[MemoryBridge] DDR5: %zu GB\n", g_state.hostCapacity / (1024*1024*1024));
    printf("[MemoryBridge] VRAM: %zu GB\n", g_state.deviceCapacity / (1024*1024*1024));
    printf("[MemoryBridge] Total: %zu GB unified working set\n", 
           (g_state.hostCapacity + g_state.deviceCapacity) / (1024*1024*1024));
    
    g_state.initialized = true;
    initialized_ = true;
    
    return true;
}

void MemoryBridge::Shutdown() {
    if (!g_state.initialized) {
        return;
    }
    
    printf("[MemoryBridge] Shutting down...\n");
    
    // Free all tracked buffers
    for (auto* buf : g_state.deviceBuffers) {
        if (buf->deviceHandle) {
            FreeDeviceMemory(buf->deviceHandle);
        }
        if (buf->ptr) {
            UnmapDeviceMemory(buf->ptr);
        }
    }
    
    for (auto* buf : g_state.pinnedBuffers) {
        if (buf->ptr) {
            FreePinnedMemory(buf->ptr, buf->sizeBytes);
        }
    }
    
    g_state.deviceBuffers.clear();
    g_state.pinnedBuffers.clear();
    g_state.initialized = false;
    initialized_ = false;
}

SovereignBuffer* MemoryBridge::Allocate(size_t sizeBytes, MemoryDomain domain) {
    if (!g_state.initialized) {
        printf("[MemoryBridge] ERROR: Not initialized\n");
        return nullptr;
    }
    
    SovereignBuffer* buffer = new SovereignBuffer();
    buffer->sizeBytes = sizeBytes;
    buffer->domain = domain;
    buffer->deviceHandle = 0;
    buffer->hostHandle = 0;
    buffer->flags = 0;
    buffer->lastAccessTime = GetTimestamp();
    buffer->refCount = 1;
    
    switch (domain) {
        case MEMORY_DOMAIN_HOST:
            buffer->ptr = AllocateHostMemory(sizeBytes);
            if (buffer->ptr) {
                g_state.hostUsed += sizeBytes;
            }
            break;
            
        case MEMORY_DOMAIN_PINNED:
            buffer->ptr = AllocatePinnedMemory(sizeBytes);
            if (buffer->ptr) {
                g_state.pinnedUsed += sizeBytes;
                g_state.pinnedBuffers.push_back(buffer);
            }
            break;
            
        case MEMORY_DOMAIN_DEVICE:
            buffer->deviceHandle = AllocateDeviceMemory(sizeBytes);
            if (buffer->deviceHandle) {
                buffer->ptr = MapDeviceMemory(buffer->deviceHandle);
                g_state.deviceUsed += sizeBytes;
                g_state.deviceBuffers.push_back(buffer);
            }
            break;
            
        default:
            printf("[MemoryBridge] ERROR: Unknown domain %d\n", domain);
            delete buffer;
            return nullptr;
    }
    
    if (!buffer->ptr && domain != MEMORY_DOMAIN_DEVICE) {
        printf("[MemoryBridge] ERROR: Allocation failed for domain %d, size %zu\n", 
               domain, sizeBytes);
        delete buffer;
        return nullptr;
    }
    
    g_state.totalAllocated += sizeBytes;
    
    printf("[MemoryBridge] Allocated %zu bytes in domain %d\n", sizeBytes, domain);
    
    return buffer;
}

void MemoryBridge::Free(SovereignBuffer* buffer) {
    if (!buffer) return;
    
    buffer->refCount--;
    if (buffer->refCount > 0) {
        return; // Still referenced
    }
    
    switch (buffer->domain) {
        case MEMORY_DOMAIN_HOST:
            if (buffer->ptr) {
                FreeHostMemory(buffer->ptr);
                g_state.hostUsed -= buffer->sizeBytes;
            }
            break;
            
        case MEMORY_DOMAIN_PINNED:
            if (buffer->ptr) {
                FreePinnedMemory(buffer->ptr, buffer->sizeBytes);
                g_state.pinnedUsed -= buffer->sizeBytes;
                // Remove from tracking
                auto it = std::find(g_state.pinnedBuffers.begin(), 
                                   g_state.pinnedBuffers.end(), buffer);
                if (it != g_state.pinnedBuffers.end()) {
                    g_state.pinnedBuffers.erase(it);
                }
            }
            break;
            
        case MEMORY_DOMAIN_DEVICE:
            if (buffer->deviceHandle) {
                FreeDeviceMemory(buffer->deviceHandle);
                g_state.deviceUsed -= buffer->sizeBytes;
                // Remove from tracking
                auto it = std::find(g_state.deviceBuffers.begin(),
                                   g_state.deviceBuffers.end(), buffer);
                if (it != g_state.deviceBuffers.end()) {
                    g_state.deviceBuffers.erase(it);
                }
            }
            if (buffer->ptr) {
                UnmapDeviceMemory(buffer->ptr);
            }
            break;
            
        default:
            break;
    }
    
    g_state.totalAllocated -= buffer->sizeBytes;
    delete buffer;
}

bool MemoryBridge::Copy(SovereignBuffer* dst, const SovereignBuffer* src) {
    if (!dst || !src) {
        printf("[MemoryBridge] ERROR: Null buffer in Copy\n");
        return false;
    }
    
    if (dst->sizeBytes < src->sizeBytes) {
        printf("[MemoryBridge] ERROR: Destination too small\n");
        return false;
    }
    
    // Same domain - direct memcpy
    if (dst->domain == src->domain) {
        memcpy(dst->ptr, src->ptr, src->sizeBytes);
        dst->lastAccessTime = GetTimestamp();
        return true;
    }
    
    // Host to Device or Device to Host - use Titan DMA
    if ((src->domain == MEMORY_DOMAIN_HOST && dst->domain == MEMORY_DOMAIN_DEVICE) ||
        (src->domain == MEMORY_DOMAIN_DEVICE && dst->domain == MEMORY_DOMAIN_HOST) ||
        (src->domain == MEMORY_DOMAIN_PINNED && dst->domain == MEMORY_DOMAIN_DEVICE) ||
        (src->domain == MEMORY_DOMAIN_DEVICE && dst->domain == MEMORY_DOMAIN_PINNED)) {
        
        GPU_COPY_OPERATION op = {};
        op.operationType = 0; // Standard copy
        op.sourceBuffer = (uint64_t)src->ptr;
        op.destBuffer = (uint64_t)dst->ptr;
        op.transferSize = src->sizeBytes;
        op.startTimeUs = GetTimestamp();
        
        int result = Titan_PerformCopy(&op, 0);
        
        if (result != 0) {
            printf("[MemoryBridge] ERROR: Titan_PerformCopy failed: %d\n", result);
            // Fallback to memcpy
            memcpy(dst->ptr, src->ptr, src->sizeBytes);
        }
        
        dst->lastAccessTime = GetTimestamp();
        return true;
    }
    
    // Other combinations - use memcpy as fallback
    memcpy(dst->ptr, src->ptr, src->sizeBytes);
    dst->lastAccessTime = GetTimestamp();
    return true;
}

bool MemoryBridge::EnsureOnDevice(SovereignBuffer* buffer) {
    if (!buffer) return false;
    
    if (buffer->domain == MEMORY_DOMAIN_DEVICE) {
        buffer->lastAccessTime = GetTimestamp();
        return true; // Already there
    }
    
    // Need to migrate
    printf("[MemoryBridge] Migrating buffer to DEVICE domain...\n");
    
    // Check if we need to evict
    if (g_state.deviceUsed + buffer->sizeBytes > g_state.deviceCapacity) {
        size_t toEvict = (g_state.deviceUsed + buffer->sizeBytes) - g_state.deviceCapacity;
        EvictDevice(toEvict + (256ULL * 1024 * 1024)); // Evict extra 256MB
    }
    
    // Allocate device buffer
    uint64_t deviceHandle = AllocateDeviceMemory(buffer->sizeBytes);
    if (!deviceHandle) {
        printf("[MemoryBridge] ERROR: Device allocation failed\n");
        return false;
    }
    
    void* devicePtr = MapDeviceMemory(deviceHandle);
    if (!devicePtr) {
        FreeDeviceMemory(deviceHandle);
        return false;
    }
    
    // Copy data
    SovereignBuffer temp;
    temp.ptr = devicePtr;
    temp.sizeBytes = buffer->sizeBytes;
    temp.domain = MEMORY_DOMAIN_DEVICE;
    
    if (!Copy(&temp, buffer)) {
        UnmapDeviceMemory(devicePtr);
        FreeDeviceMemory(deviceHandle);
        return false;
    }
    
    // Free old memory
    if (buffer->domain == MEMORY_DOMAIN_HOST && buffer->ptr) {
        FreeHostMemory(buffer->ptr);
        g_state.hostUsed -= buffer->sizeBytes;
    } else if (buffer->domain == MEMORY_DOMAIN_PINNED && buffer->ptr) {
        FreePinnedMemory(buffer->ptr, buffer->sizeBytes);
        g_state.pinnedUsed -= buffer->sizeBytes;
    }
    
    // Update buffer
    buffer->ptr = devicePtr;
    buffer->deviceHandle = deviceHandle;
    buffer->domain = MEMORY_DOMAIN_DEVICE;
    buffer->lastAccessTime = GetTimestamp();
    
    g_state.deviceUsed += buffer->sizeBytes;
    g_state.deviceBuffers.push_back(buffer);
    
    return true;
}

bool MemoryBridge::EnsureOnHost(SovereignBuffer* buffer) {
    if (!buffer) return false;
    
    if (buffer->domain == MEMORY_DOMAIN_HOST || buffer->domain == MEMORY_DOMAIN_PINNED) {
        buffer->lastAccessTime = GetTimestamp();
        return true; // Already there
    }
    
    // Need to migrate from device
    printf("[MemoryBridge] Migrating buffer to HOST domain...\n");
    
    // Allocate host buffer
    void* hostPtr = AllocateHostMemory(buffer->sizeBytes);
    if (!hostPtr) {
        printf("[MemoryBridge] ERROR: Host allocation failed\n");
        return false;
    }
    
    // Copy data
    SovereignBuffer temp;
    temp.ptr = hostPtr;
    temp.sizeBytes = buffer->sizeBytes;
    temp.domain = MEMORY_DOMAIN_HOST;
    
    if (!Copy(&temp, buffer)) {
        FreeHostMemory(hostPtr);
        return false;
    }
    
    // Free device memory
    if (buffer->deviceHandle) {
        FreeDeviceMemory(buffer->deviceHandle);
        g_state.deviceUsed -= buffer->sizeBytes;
        
        auto it = std::find(g_state.deviceBuffers.begin(),
                           g_state.deviceBuffers.end(), buffer);
        if (it != g_state.deviceBuffers.end()) {
            g_state.deviceBuffers.erase(it);
        }
    }
    if (buffer->ptr) {
        UnmapDeviceMemory(buffer->ptr);
    }
    
    // Update buffer
    buffer->ptr = hostPtr;
    buffer->deviceHandle = 0;
    buffer->domain = MEMORY_DOMAIN_HOST;
    buffer->lastAccessTime = GetTimestamp();
    
    g_state.hostUsed += buffer->sizeBytes;
    
    return true;
}

bool MemoryBridge::EnsurePinned(SovereignBuffer* buffer) {
    if (!buffer) return false;
    
    if (buffer->domain == MEMORY_DOMAIN_PINNED) {
        buffer->lastAccessTime = GetTimestamp();
        return true;
    }
    
    // Similar to EnsureOnHost but with pinned memory
    printf("[MemoryBridge] Migrating buffer to PINNED domain...\n");
    
    void* pinnedPtr = AllocatePinnedMemory(buffer->sizeBytes);
    if (!pinnedPtr) {
        printf("[MemoryBridge] ERROR: Pinned allocation failed\n");
        return false;
    }
    
    // Copy data
    memcpy(pinnedPtr, buffer->ptr, buffer->sizeBytes);
    
    // Free old memory
    if (buffer->domain == MEMORY_DOMAIN_HOST) {
        FreeHostMemory(buffer->ptr);
        g_state.hostUsed -= buffer->sizeBytes;
    } else if (buffer->domain == MEMORY_DOMAIN_DEVICE) {
        if (buffer->deviceHandle) {
            FreeDeviceMemory(buffer->deviceHandle);
            g_state.deviceUsed -= buffer->sizeBytes;
        }
        UnmapDeviceMemory(buffer->ptr);
    }
    
    buffer->ptr = pinnedPtr;
    buffer->deviceHandle = 0;
    buffer->domain = MEMORY_DOMAIN_PINNED;
    buffer->lastAccessTime = GetTimestamp();
    
    g_state.pinnedUsed += buffer->sizeBytes;
    g_state.pinnedBuffers.push_back(buffer);
    
    return true;
}

MemoryDomain MemoryBridge::GetDomain(const SovereignBuffer* buffer) const {
    return buffer ? buffer->domain : MEMORY_DOMAIN_HOST;
}

bool MemoryBridge::IsResident(const SovereignBuffer* buffer, MemoryDomain domain) const {
    return buffer && buffer->domain == domain;
}

bool MemoryBridge::Prefetch(SovereignBuffer* buffer, MemoryDomain domain) {
    // Async prefetch - for now just do synchronous
    if (domain == MEMORY_DOMAIN_DEVICE) {
        return EnsureOnDevice(buffer);
    } else if (domain == MEMORY_DOMAIN_HOST) {
        return EnsureOnHost(buffer);
    }
    return false;
}

size_t MemoryBridge::EvictDevice(size_t targetBytes) {
    if (targetBytes == 0) return 0;
    
    printf("[MemoryBridge] Evicting %zu bytes from device...\n", targetBytes);
    
    // Sort by last access time (LRU)
    std::sort(g_state.deviceBuffers.begin(), g_state.deviceBuffers.end(),
              [](SovereignBuffer* a, SovereignBuffer* b) {
                  return a->lastAccessTime < b->lastAccessTime;
              });
    
    size_t evicted = 0;
    for (auto* buf : g_state.deviceBuffers) {
        if (buf->flags & BUFFER_FLAG_PERSISTENT) continue; // Don't evict persistent
        if (buf->refCount > 1) continue; // Still referenced
        
        if (EnsureOnHost(buf)) {
            evicted += buf->sizeBytes;
            if (evicted >= targetBytes) break;
        }
    }
    
    printf("[MemoryBridge] Evicted %zu bytes\n", evicted);
    return evicted;
}

void MemoryBridge::GetStats(uint64_t& hostUsed, uint64_t& deviceUsed, 
                            uint64_t& pinnedUsed, uint64_t& totalAllocated) const {
    hostUsed = g_state.hostUsed;
    deviceUsed = g_state.deviceUsed;
    pinnedUsed = g_state.pinnedUsed;
    totalAllocated = g_state.totalAllocated;
}

MemoryDomain MemoryBridge::SuggestDomain(size_t dataSize, bool frequentAccess, bool computeHeavy) {
    // Simple heuristic:
    // - Small data (< 1MB): Host
    // - Large data, compute heavy: Device
    // - Frequent access: Pinned
    
    if (dataSize < 1024 * 1024) {
        return MEMORY_DOMAIN_HOST;
    }
    
    if (frequentAccess && dataSize < 256 * 1024 * 1024) {
        return MEMORY_DOMAIN_PINNED;
    }
    
    if (computeHeavy && dataSize > 10 * 1024 * 1024) {
        return MEMORY_DOMAIN_DEVICE;
    }
    
    return MEMORY_DOMAIN_HOST;
}

} // namespace Sovereign

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

int MemoryBridge_Initialize(void) {
    return Sovereign::MemoryBridge::Instance().Initialize() ? 0 : 1;
}

void MemoryBridge_Shutdown(void) {
    Sovereign::MemoryBridge::Instance().Shutdown();
}

SovereignBuffer* MemoryBridge_Allocate(size_t sizeBytes, MemoryDomain domain) {
    return Sovereign::MemoryBridge::Instance().Allocate(sizeBytes, domain);
}

void MemoryBridge_Free(SovereignBuffer* buffer) {
    Sovereign::MemoryBridge::Instance().Free(buffer);
}

int MemoryBridge_Copy(SovereignBuffer* dst, const SovereignBuffer* src) {
    return Sovereign::MemoryBridge::Instance().Copy(dst, src) ? 0 : 1;
}

int MemoryBridge_EnsureOnDevice(SovereignBuffer* buffer) {
    return Sovereign::MemoryBridge::Instance().EnsureOnDevice(buffer) ? 0 : 1;
}

int MemoryBridge_EnsureOnHost(SovereignBuffer* buffer) {
    return Sovereign::MemoryBridge::Instance().EnsureOnHost(buffer) ? 0 : 1;
}

int MemoryBridge_EnsurePinned(SovereignBuffer* buffer) {
    return Sovereign::MemoryBridge::Instance().EnsurePinned(buffer) ? 0 : 1;
}

MemoryDomain MemoryBridge_GetDomain(const SovereignBuffer* buffer) {
    return Sovereign::MemoryBridge::Instance().GetDomain(buffer);
}

bool MemoryBridge_IsResident(const SovereignBuffer* buffer, MemoryDomain domain) {
    return Sovereign::MemoryBridge::Instance().IsResident(buffer, domain);
}

int MemoryBridge_Prefetch(SovereignBuffer* buffer, MemoryDomain domain) {
    return Sovereign::MemoryBridge::Instance().Prefetch(buffer, domain) ? 0 : 1;
}

void MemoryBridge_GetStats(uint64_t* hostUsed, uint64_t* deviceUsed, 
                           uint64_t* pinnedUsed, uint64_t* totalAllocated) {
    Sovereign::MemoryBridge::Instance().GetStats(*hostUsed, *deviceUsed, 
                                                  *pinnedUsed, *totalAllocated);
}

size_t MemoryBridge_EvictDevice(size_t targetBytes) {
    return Sovereign::MemoryBridge::Instance().EvictDevice(targetBytes);
}

} // extern "C"
