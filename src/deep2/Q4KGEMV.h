// ============================================================================
// Q4KGEMV.h - Q4_K_M GEMV Interface
// High-performance quantized matrix-vector multiplication
// ============================================================================

#ifndef Q4K_GEMV_H
#define Q4K_GEMV_H

#include <cstddef>
#include <cstdint>

namespace Deep2 {

// ============================================================================
// Q4_K_M Block Structure (GGUF format)
// ============================================================================
struct alignas(32) Q4_K_M_Block {
    uint16_t scales[32];    // FP16 scales for each group of 8
    uint16_t mins[32];      // FP16 minimums
    uint8_t qs[128];        // 256 x 4-bit weights packed
};

// ============================================================================
// Q4_K_M Tensor View
// Reference to quantized weights without copying
// ============================================================================
struct Q4KTensorView {
    const Q4_K_M_Block* blocks;     // Pointer to blocks
    size_t numRows;                 // Number of output rows
    size_t numCols;                 // Number of input columns
    size_t blockCols;               // Columns / 256
    
    // Calculate size in bytes
    size_t sizeBytes() const {
        return ((numRows + 255) / 256) * blockCols * sizeof(Q4_K_M_Block);
    }
};

// ============================================================================
// Q4_K_M GEMV Interface
// ============================================================================

// AVX2 implementation
extern "C" {
    void Sovereign_Q4K_GEMV_AVX2(
        const void* q4_weights,
        const float* input,
        float* output,
        size_t num_blocks,
        size_t block_stride
    );
    
    void Sovereign_Q4K_GEMV_AVX2_Optimized(
        const void* q4_weights,
        const float* input,
        float* output,
        size_t num_blocks,
        size_t block_stride
    );
}

// C++ wrapper class
class Q4KGEMV {
public:
    // Perform GEMV: output = weights @ input
    // weights: Q4_K_M quantized
    // input: FP32 vector
    // output: FP32 vector
    static void multiply(
        const Q4KTensorView& weights,
        const float* input,
        float* output
    );
    
    // Get kernel info
    static const char* getKernelName();
    static bool isAVX2Supported();
    static bool isAVX512Supported();
};

} // namespace Deep2

#endif // Q4K_GEMV_H
