// RDNA3_Kernels.h
// C/C++ header for RDNA3 GPU kernel dispatch
// Target: RX 7800 XT (gfx1101)

#ifndef RDNA3_KERNELS_H
#define RDNA3_KERNELS_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// Kernel binary info structure
#pragma pack(push, 1)
typedef struct {
    const uint8_t* data;
    uint32_t size;
} RDNA3_KernelBinary;
#pragma pack(pop)

// Kernel dispatch result
typedef enum {
    RDNA3_DISPATCH_SUCCESS = 0,
    RDNA3_DISPATCH_ERROR_INVALID_DOORBELL = 1,
    RDNA3_DISPATCH_ERROR_INVALID_TILE = 2,
    RDNA3_DISPATCH_ERROR_GPU_NOT_FOUND = 3,
    RDNA3_DISPATCH_ERROR_TIMEOUT = 4
} RDNA3_DispatchResult;

// External assembly functions
extern "C" {
    // Get kernel binaries
    extern void* Get_Q4MatMul_Binary(void);
    extern uint32_t Get_Q4MatMul_BinarySize(void);
    
    extern void* Get_KVCacheAttention_Binary(void);
    extern uint32_t Get_KVCacheAttention_BinarySize(void);
    
    extern void* Get_TileStreamer_Binary(void);
    extern uint32_t Get_TileStreamer_BinarySize(void);
    
    // Dispatch kernels (returns 1 on success, 0 on failure)
    extern int Dispatch_Q4MatMul_RDNA3(void* doorbellAddr, uint32_t tileId);
    extern int Dispatch_KVCacheAttention_RDNA3(void* doorbellAddr, uint32_t tileId);
    extern int Dispatch_TileStreamer_RDNA3(void* doorbellAddr, uint32_t tileId);
}

// C++ wrapper functions
inline RDNA3_KernelBinary GetQ4MatMulKernelBinary() {
    return RDNA3_KernelBinary{
        static_cast<const uint8_t*>(Get_Q4MatMul_Binary()),
        Get_Q4MatMul_BinarySize()
    };
}

inline RDNA3_KernelBinary GetKVCacheAttentionKernelBinary() {
    return RDNA3_KernelBinary{
        static_cast<const uint8_t*>(Get_KVCacheAttention_Binary()),
        Get_KVCacheAttention_BinarySize()
    };
}

inline RDNA3_KernelBinary GetTileStreamerKernelBinary() {
    return RDNA3_KernelBinary{
        static_cast<const uint8_t*>(Get_TileStreamer_Binary()),
        Get_TileStreamer_BinarySize()
    };
}

// Dispatch wrapper with error handling
inline RDNA3_DispatchResult DispatchQ4MatMul(void* doorbellAddr, uint32_t tileId) {
    if (!doorbellAddr) return RDNA3_DISPATCH_ERROR_INVALID_DOORBELL;
    if (tileId > 0x7FFFFFFF) return RDNA3_DISPATCH_ERROR_INVALID_TILE;
    
    int result = Dispatch_Q4MatMul_RDNA3(doorbellAddr, tileId);
    return (result == 1) ? RDNA3_DISPATCH_SUCCESS : RDNA3_DISPATCH_ERROR_TIMEOUT;
}

inline RDNA3_DispatchResult DispatchKVCacheAttention(void* doorbellAddr, uint32_t tileId) {
    if (!doorbellAddr) return RDNA3_DISPATCH_ERROR_INVALID_DOORBELL;
    if (tileId > 0x7FFFFFFF) return RDNA3_DISPATCH_ERROR_INVALID_TILE;
    
    int result = Dispatch_KVCacheAttention_RDNA3(doorbellAddr, tileId);
    return (result == 1) ? RDNA3_DISPATCH_SUCCESS : RDNA3_DISPATCH_ERROR_TIMEOUT;
}

inline RDNA3_DispatchResult DispatchTileStreamer(void* doorbellAddr, uint32_t tileId) {
    if (!doorbellAddr) return RDNA3_DISPATCH_ERROR_INVALID_DOORBELL;
    if (tileId > 0x7FFFFFFF) return RDNA3_DISPATCH_ERROR_INVALID_TILE;
    
    int result = Dispatch_TileStreamer_RDNA3(doorbellAddr, tileId);
    return (result == 1) ? RDNA3_DISPATCH_SUCCESS : RDNA3_DISPATCH_ERROR_TIMEOUT;
}

// Hardware constants for RX 7800 XT
namespace RDNA3 {
    constexpr uint32_t GFX1101_DEVICE_ID = 0x73FF;  // RX 7800 XT
    constexpr uint32_t NUM_CUS = 60;
    constexpr uint32_t LDS_PER_CU = 128 * 1024;  // 128KB
    constexpr uint32_t WAVEFRONT_SIZE = 64;
    constexpr uint32_t VRAM_SIZE = 16ULL * 1024 * 1024 * 1024;  // 16GB
    constexpr uint32_t PCIE_GEN = 4;
    constexpr uint32_t PCIE_LANES = 16;
    
    // Kernel launch configuration
    constexpr uint32_t MATMUL_WAVES_PER_CU = 2;
    constexpr uint32_t ATTENTION_WAVES_PER_CU = 4;
    constexpr uint32_t STREAMER_WAVES_PER_CU = 8;
    
    // Tile sizes for 120B Q4_K_M
    constexpr uint32_t TILE_SIZE_KB = 2048;  // 2MB tiles
    constexpr uint32_t TILE_SIZE_BYTES = TILE_SIZE_KB * 1024;
}

#ifdef __cplusplus
}
#endif

#endif // RDNA3_KERNELS_H
