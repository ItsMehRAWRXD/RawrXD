// ============================================================================
// Sovereign GPU Bridge — Direct VRAM BAR Access for RX 7800 XT (RDNA3)
// ============================================================================
// Bypasses DirectX/Vulkan driver stacks. Uses PCIe BAR mapping for direct
// token/embedding injection into VRAM.
//
// Architecture:
//   CPU (Sovereign Arena) → PCIe BAR → GPU VRAM (RDNA3 Cache Hierarchy)
//
// Target: AMD Radeon RX 7800 XT (Navi 32, PCI Device ID 0x747E)
// BAR: Typically 256MB or 16GB mapped aperture (resizable BAR enabled)
// Alignment: 256-byte (RDNA3 cache line) / 4KB (PCIe page)
//
// WARNING: This bypasses ALL driver safety. Incorrect addresses will
//          cause immediate system instability.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants
// ============================================================================

#define SOVEREIGN_GPU_VENDOR_AMD        0x1002
#define SOVEREIGN_GPU_DEVICE_RX7800XT   0x747E      // Navi 32
#define SOVEREIGN_GPU_DEVICE_RX7900XTX 0x744C      // Navi 31 (fallback)

#define SOVEREIGN_VRAM_ALIGNMENT        256         // RDNA3 cache line
#define SOVEREIGN_VRAM_BAR_ALIGNMENT    4096        // PCIe page size
#define SOVEREIGN_DMA_CHUNK_SIZE        65536       // 64KB DMA chunks

// BAR types
#define SOVEREIGN_BAR_TYPE_MMIO         0           // Memory-mapped I/O
#define SOVEREIGN_BAR_TYPE_VRAM         1           // VRAM aperture

// Status codes
#define SOVEREIGN_GPU_OK                0
#define SOVEREIGN_GPU_ERR_NO_DEVICE     -1
#define SOVEREIGN_GPU_ERR_BAR_MAP       -2
#define SOVEREIGN_GPU_ERR_ALIGNMENT     -3
#define SOVEREIGN_GPU_ERR_DMA_TIMEOUT   -4

// ============================================================================
// Types
// ============================================================================

/// GPU device handle (opaque)
typedef struct SovereignGPUDevice* SovereignGPUHandle;

/// BAR region descriptor
typedef struct SovereignBARRegion {
    uint64_t    physicalBase;       // Physical BAR address (from PCI config)
    void*       virtualBase;        // Virtual address (mapped via MmMapIoSpace)
    size_t      size;               // BAR size in bytes
    int         type;               // SOVEREIGN_BAR_TYPE_*
    bool        is64Bit;            // 64-bit BAR
} SovereignBARRegion;

/// DMA transfer descriptor
typedef struct SovereignDMADescriptor {
    const void* hostSrc;            // Source in host memory (Sovereign Arena)
    uint64_t    gpuDstOffset;       // Destination offset in VRAM BAR
    size_t      size;               // Transfer size in bytes
    uint32_t    flags;              // Transfer flags (async, fence, etc.)
} SovereignDMADescriptor;

/// GPU capability flags
typedef struct SovereignGPUCaps {
    uint32_t    deviceId;           // PCI device ID
    uint32_t    vendorId;           // PCI vendor ID
    uint64_t    vramSize;           // Total VRAM size
    uint64_t    barSize;            // Resizable BAR size
    bool        resizableBAR;       // Resizable BAR supported
    bool        smartAccessMemory;  // SAM enabled
    uint32_t    maxDMAChunks;       // Max concurrent DMA operations
} SovereignGPUCaps;

// ============================================================================
// Lifecycle
// ============================================================================

/// Initialize GPU bridge and locate RX 7800 XT
/// @return Handle to GPU device, or nullptr on failure
SovereignGPUHandle SovereignGPU_Initialize(void);

/// Shutdown GPU bridge and unmap BARs
/// @param gpu GPU device handle
void SovereignGPU_Shutdown(SovereignGPUHandle gpu);

/// Get GPU capabilities
/// @param gpu GPU device handle
/// @param caps Output capability structure
/// @return SOVEREIGN_GPU_OK on success
int SovereignGPU_GetCaps(SovereignGPUHandle gpu, SovereignGPUCaps* caps);

// ============================================================================
// BAR Management
// ============================================================================

/// Map VRAM BAR for direct access
/// @param gpu GPU device handle
/// @param barIndex BAR index (typically 0 for VRAM)
/// @param region Output BAR region descriptor
/// @return SOVEREIGN_GPU_OK on success
int SovereignGPU_MapBAR(SovereignGPUHandle gpu, int barIndex, SovereignBARRegion* region);

/// Unmap VRAM BAR
/// @param region BAR region to unmap
void SovereignGPU_UnmapBAR(SovereignBARRegion* region);

/// Flush GPU caches after direct writes (RDNA3 specific)
/// @param gpu GPU device handle
void SovereignGPU_FlushCaches(SovereignGPUHandle gpu);

// ============================================================================
// Direct Memory Access (DMA)
// ============================================================================

/// Perform synchronous DMA transfer from host to VRAM
/// @param gpu GPU device handle
/// @param desc DMA descriptor
/// @return SOVEREIGN_GPU_OK on success
/// @note Blocks until transfer completes
int SovereignGPU_DMA_HostToDevice(SovereignGPUHandle gpu, const SovereignDMADescriptor* desc);

/// Perform asynchronous DMA transfer (non-blocking)
/// @param gpu GPU device handle
/// @param desc DMA descriptor
/// @param fenceId Output fence ID for completion tracking
/// @return SOVEREIGN_GPU_OK on success
int SovereignGPU_DMA_HostToDeviceAsync(SovereignGPUHandle gpu, const SovereignDMADescriptor* desc, uint64_t* fenceId);

/// Wait for DMA completion
/// @param gpu GPU device handle
/// @param fenceId Fence ID from async operation
/// @param timeoutMs Timeout in milliseconds (0 = infinite)
/// @return SOVEREIGN_GPU_OK on success, SOVEREIGN_GPU_ERR_DMA_TIMEOUT on timeout
int SovereignGPU_DMA_Wait(SovereignGPUHandle gpu, uint64_t fenceId, uint32_t timeoutMs);

/// High-speed bulk DMA (optimized MASM path)
/// @param gpu GPU device handle
/// @param hostSrc Source buffer (must be in Sovereign Arena)
/// @param gpuDst GPU destination (BAR-relative offset)
/// @param sizeBytes Size in bytes (must be 64-byte aligned)
/// @return SOVEREIGN_GPU_OK on success
/// @note Uses REP MOVSQ + SFENCE for maximum throughput
int SovereignGPU_DMA_Bulk(SovereignGPUHandle gpu, const void* hostSrc, uint64_t gpuDst, size_t sizeBytes);

// ============================================================================
// Token/Embedding Injection (High-Level)
// ============================================================================

/// Inject token embeddings directly to VRAM
/// @param gpu GPU device handle
/// @param tokens Token IDs array
/// @param tokenCount Number of tokens
/// @param embeddingTable Host-side embedding table (Sovereign Arena)
/// @param embeddingDim Embedding dimension (e.g., 4096 for Phi-3)
/// @param vramDstOffset Destination offset in VRAM
/// @return SOVEREIGN_GPU_OK on success
int SovereignGPU_InjectEmbeddings(
    SovereignGPUHandle gpu,
    const int32_t* tokens,
    size_t tokenCount,
    const float* embeddingTable,
    size_t embeddingDim,
    uint64_t vramDstOffset
);

/// Inject KV cache block directly to VRAM
/// @param gpu GPU device handle
/// @param kvData Host-side KV data (Sovereign Arena)
/// @param layerIndex Transformer layer index
/// @param seqPos Sequence position
/// @param vramDstOffset Destination offset in VRAM
/// @return SOVEREIGN_GPU_OK on success
int SovereignGPU_InjectKVBlock(
    SovereignGPUHandle gpu,
    const void* kvData,
    uint32_t layerIndex,
    uint32_t seqPos,
    uint64_t vramDstOffset
);

// ============================================================================
// Diagnostics
// ============================================================================

/// Run VRAM aperture test (write pattern, read back, verify)
/// @param gpu GPU device handle
/// @return SOVEREIGN_GPU_OK on success
/// @note This is the "smoking gun" test for direct VRAM access
int SovereignGPU_TestAperture(SovereignGPUHandle gpu);

/// Get last error string
/// @param gpu GPU device handle
/// @return Human-readable error message
const char* SovereignGPU_GetErrorString(SovereignGPUHandle gpu);

/// Dump GPU bridge state to log
/// @param gpu GPU device handle
void SovereignGPU_DumpState(SovereignGPUHandle gpu);

#ifdef __cplusplus
} // extern "C"
#endif

// ============================================================================
// C++ RAII Wrapper
// ============================================================================

#ifdef __cplusplus

namespace rxdn {

class SovereignGPUBridge {
public:
    SovereignGPUBridge() : handle_(SovereignGPU_Initialize()) {}
    ~SovereignGPUBridge() { if (handle_) SovereignGPU_Shutdown(handle_); }
    
    // Non-copyable
    SovereignGPUBridge(const SovereignGPUBridge&) = delete;
    SovereignGPUBridge& operator=(const SovereignGPUBridge&) = delete;
    
    // Movable
    SovereignGPUBridge(SovereignGPUBridge&& other) : handle_(other.handle_) { other.handle_ = nullptr; }
    SovereignGPUBridge& operator=(SovereignGPUBridge&& other) {
        if (this != &other) {
            if (handle_) SovereignGPU_Shutdown(handle_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }
    
    bool IsValid() const { return handle_ != nullptr; }
    SovereignGPUHandle Get() const { return handle_; }
    
    int GetCaps(SovereignGPUCaps* caps) { return SovereignGPU_GetCaps(handle_, caps); }
    int MapBAR(int barIndex, SovereignBARRegion* region) { return SovereignGPU_MapBAR(handle_, barIndex, region); }
    int DMA(const SovereignDMADescriptor* desc) { return SovereignGPU_DMA_HostToDevice(handle_, desc); }
    int TestAperture() { return SovereignGPU_TestAperture(handle_); }
    
private:
    SovereignGPUHandle handle_;
};

} // namespace rxdn

#endif // __cplusplus
