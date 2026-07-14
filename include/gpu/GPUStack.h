// =============================================================================
// GPUStack.h - Public API Header
// =============================================================================
// Reverse engineered GPU stack with hardware detection and native backends
// =============================================================================

#ifndef GPU_STACK_H
#define GPU_STACK_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Types and Constants
// =============================================================================

typedef enum {
    GPU_VENDOR_UNKNOWN = 0,
    GPU_VENDOR_NVIDIA = 1,
    GPU_VENDOR_AMD = 2,
    GPU_VENDOR_INTEL = 3,
    GPU_VENDOR_MICROSOFT = 4,
    GPU_VENDOR_QUALCOMM = 5
} GPUVendor;

typedef enum {
    GPU_ARCH_UNKNOWN = 0,
    // NVIDIA architectures
    GPU_ARCH_KEPLER = 0x100,
    GPU_ARCH_MAXWELL = 0x110,
    GPU_ARCH_PASCAL = 0x120,
    GPU_ARCH_VOLTA = 0x130,
    GPU_ARCH_TURING = 0x140,
    GPU_ARCH_AMPERE = 0x150,
    GPU_ARCH_ADA = 0x160,
    GPU_ARCH_BLACKWELL = 0x170,
    // AMD architectures
    GPU_ARCH_GCN = 0x200,
    GPU_ARCH_RDNA = 0x210,
    GPU_ARCH_RDNA2 = 0x220,
    GPU_ARCH_RDNA3 = 0x230,
    GPU_ARCH_RDNA4 = 0x240,
    // Intel architectures
    GPU_ARCH_GEN9 = 0x300,
    GPU_ARCH_GEN11 = 0x310,
    GPU_ARCH_XE = 0x320,
    GPU_ARCH_XE_HP = 0x330,
    GPU_ARCH_XE2 = 0x340
} GPUArchitecture;

typedef enum {
    BACKEND_NONE = 0,
    BACKEND_CUDA = 1,
    BACKEND_ROCM = 2,
    BACKEND_LEVELZERO = 3,
    BACKEND_DIRECTX12 = 4,
    BACKEND_VULKAN = 5,
    BACKEND_OPENCL = 6,
    BACKEND_METAL = 7
} GPUBackend;

typedef enum {
    MEMORY_TIER_GPU_VRAM = 0,
    MEMORY_TIER_RAM = 1,
    MEMORY_TIER_NVME = 2,
    MEMORY_TIER_HDD = 3
} MemoryTier;

typedef enum {
    MAP_FLAG_NONE = 0,
    MAP_FLAG_READ = 1,
    MAP_FLAG_WRITE = 2,
    MAP_FLAG_READ_WRITE = 3,
    MAP_FLAG_COHERENT = 4,
    MAP_FLAG_CACHED = 8,
    MAP_FLAG_UNCACHED = 16,
    MAP_FLAG_WRITE_COMBINE = 32
} MapFlags;

// =============================================================================
// Hardware Info Structure
// =============================================================================

typedef struct {
    GPUVendor vendor;
    GPUArchitecture architecture;
    GPUBackend preferredBackend;
    GPUBackend fallbackBackend;
    
    // Memory
    uint64_t dedicatedVideoMemory;
    uint64_t sharedSystemMemory;
    uint64_t totalMemory;
    
    // Compute
    uint32_t computeUnits;
    uint32_t maxClockSpeed;
    
    // PCI
    uint32_t pciVendorId;
    uint32_t pciDeviceId;
    uint32_t pciSubSystemId;
    
    // Capabilities
    bool supportsUnifiedMemory;
    bool supportsDMA;
    bool supportsAsyncCompute;
    bool supportsRayTracing;
    bool supportsMeshShaders;
    bool supportsVariableRateShading;
    bool supportsResizableBAR;
    bool supportsSmartAccessMemory;
    
    // Performance
    float memoryBandwidthGBps;
    float computePerformanceTFlops;
    uint32_t memoryBusWidth;
    uint32_t memoryType;
    
    // Strings
    char name[256];
    char driverVersion[64];
} GPUHardwareInfo;

// =============================================================================
// Public API
// =============================================================================

// Initialize/shutdown
bool GPUStack_Initialize(void);
void GPUStack_Shutdown(void);

// Hardware queries
uint32_t GPUStack_GetGPUCount(void);
const GPUHardwareInfo* GPUStack_GetGPUInfo(uint32_t index);
const GPUHardwareInfo* GPUStack_GetSelectedGPU(void);
bool GPUStack_SelectGPU(uint32_t index);

// Memory management
void* GPUStack_MapMemory(void* cpuAddress, uint64_t size, uint32_t flags);
void GPUStack_UnmapMemory(void* gpuAddress);
bool GPUStack_MakeResident(void* gpuAddress);
bool GPUStack_Evict(void* gpuAddress);

// Residency queries
void GPUStack_GetStats(uint64_t* totalMapped, uint64_t* totalResident, 
                       uint32_t* regionCount);
uint64_t GPUStack_GetTierSize(MemoryTier tier);
uint64_t GPUStack_GetTierUsed(MemoryTier tier);

// Backend control
GPUBackend GPUStack_GetActiveBackend(void);
const char* GPUStack_GetBackendName(GPUBackend backend);

// Utility
const char* GPUStack_GetVendorName(GPUVendor vendor);
const char* GPUStack_GetArchitectureName(GPUArchitecture arch);
void GPUStack_PrintInfo(void);

#ifdef __cplusplus
}
#endif

#endif // GPU_STACK_H