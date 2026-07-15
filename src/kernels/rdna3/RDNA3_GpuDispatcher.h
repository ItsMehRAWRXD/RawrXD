// RDNA3_GpuDispatcher.h
// C++ interface for RDNA3 GPU kernel dispatch
// Target: RX 7800 XT (gfx1101)

#ifndef RDNA3_GPU_DISPATCHER_H
#define RDNA3_GPU_DISPATCHER_H

#include <cstdint>
#include <cstddef>

namespace RDNA3 {

// Kernel binary info
struct KernelBinary {
    const uint8_t* data;
    uint32_t size;
};

// Dispatch result codes
enum class DispatchResult {
    SUCCESS = 0,
    NOT_INITIALIZED = 1,
    INVALID_DOORBELL = 2,
    INVALID_TILE = 3,
    GPU_NOT_FOUND = 4,
    TIMEOUT = 5,
    KERNEL_UPLOAD_FAILED = 6
};

// Hardware constants for RX 7800 XT
constexpr uint32_t GFX1101_DEVICE_ID = 0x73FF;
constexpr uint32_t NUM_CUS = 60;
constexpr uint32_t LDS_PER_CU = 128 * 1024;  // 128KB
constexpr uint32_t WAVEFRONT_SIZE = 64;
constexpr uint64_t VRAM_SIZE = 16ULL * 1024 * 1024 * 1024;  // 16GB
constexpr uint32_t PCIE_GEN = 4;
constexpr uint32_t PCIE_LANES = 16;

// Kernel launch configuration
constexpr uint32_t MATMUL_WAVES_PER_CU = 2;
constexpr uint32_t ATTENTION_WAVES_PER_CU = 4;
constexpr uint32_t STREAMER_WAVES_PER_CU = 8;

// Tile sizes for 120B Q4_K_M
constexpr uint32_t TILE_SIZE_KB = 2048;  // 2MB tiles
constexpr uint32_t TILE_SIZE_BYTES = TILE_SIZE_KB * 1024;

// GPU Dispatcher singleton
class GpuDispatcher {
public:
    static GpuDispatcher& GetInstance();
    
    // Initialize/shutdown
    bool Initialize();
    void Shutdown();
    
    // Dispatch kernels
    DispatchResult DispatchMatMul(uint32_t tileId, const void* args, size_t argsSize);
    DispatchResult DispatchAttention(uint32_t tileId, const void* args, size_t argsSize);
    DispatchResult DispatchStreamer(uint32_t tileId, const void* args, size_t argsSize);
    
    // Get kernel binaries
    const KernelBinary& GetQ4MatMulBinary() const;
    const KernelBinary& GetAttentionBinary() const;
    const KernelBinary& GetStreamerBinary() const;
    
    // Status
    bool IsInitialized() const;
    
private:
    GpuDispatcher();
    ~GpuDispatcher();
    GpuDispatcher(const GpuDispatcher&) = delete;
    GpuDispatcher& operator=(const GpuDispatcher&) = delete;
    
    static GpuDispatcher* s_instance;
    
    bool m_initialized;
    void* m_doorbellAddr;
    void* m_gpuMemoryBase;
    
    KernelBinary m_q4Binary;
    KernelBinary m_attnBinary;
    KernelBinary m_streamBinary;
};

} // namespace RDNA3

// C API for external linkage
extern "C" {
    bool RDNA3_Initialize(void);
    void RDNA3_Shutdown(void);
    int RDNA3_DispatchMatMul(uint32_t tileId);
    int RDNA3_DispatchAttention(uint32_t tileId);
    int RDNA3_DispatchStreamer(uint32_t tileId);
    bool RDNA3_IsInitialized(void);
}

#endif // RDNA3_GPU_DISPATCHER_H
