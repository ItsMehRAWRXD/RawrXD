// ============================================================================
// Q4KGEMV_Wrapper.cpp - C++ Interface for Q4_K_M GEMV Kernel
// Bridges Deep2Engine to Sovereign Q4_K_M MASM kernel
// ============================================================================

#include <cstdint>
#include <cstddef>

// MASM kernel interface
extern "C" {
    void Sovereign_Q4K_GEMV_AVX2(
        const void* q4_weights,
        const float* input,
        float* output,
        uint32_t num_blocks,
        uint32_t rows
    );
}

namespace Deep2 {

// Q4_K_M Block structure (matches GGUF)
struct alignas(32) Q4_K_M_Block {
    uint16_t scales[32];      // FP16 scales
    uint16_t mins[32];      // FP16 mins
    uint8_t  weights[128];  // 256 x 4-bit packed
};

// Q4_K_M Weight Matrix View
class Q4KWeightMatrix {
public:
    const Q4_K_M_Block* blocks;
    size_t numBlocks;
    size_t rows;
    size_t cols;
    
    Q4KWeightMatrix(const void* data, size_t r, size_t c) 
        : rows(r), cols(c) {
        // Each block holds 256 weights
        numBlocks = (c + 255) / 256;
        blocks = static_cast<const Q4_K_M_Block*>(data);
    }
};

// ============================================================================
// Q4_K_M GEMV - Matrix-Vector Multiplication
// Computes: output = weights * input
// Where weights are Q4_K_M quantized
// ============================================================================
void Q4K_GEMV(
    const Q4KWeightMatrix& weights,
    const float* input,
    float* output,
    size_t numRows
) {
    // Call MASM kernel
    Sovereign_Q4K_GEMV_AVX2(
        weights.blocks,
        input,
        output,
        static_cast<uint32_t>(weights.numBlocks),
        static_cast<uint32_t>(numRows)
    );
}

// ============================================================================
// Q4_K_M GEMV with bias
// Computes: output = weights * input + bias
// ============================================================================
void Q4K_GEMV_Bias(
    const Q4KWeightMatrix& weights,
    const float* input,
    const float* bias,
    float* output,
    size_t numRows
) {
    // Call MASM kernel
    Sovereign_Q4K_GEMV_AVX2(
        weights.blocks,
        input,
        output,
        static_cast<uint32_t>(weights.numBlocks),
        static_cast<uint32_t>(numRows)
    );
    
    // Add bias
    for (size_t i = 0; i < numRows; i++) {
        output[i] += bias[i];
    }
}

// ============================================================================
// Transformer Linear Layer with Q4_K_M
// Replaces FP32 matmul in transformer layers
// ============================================================================
class Q4KLinearLayer {
public:
    Q4KWeightMatrix weights;
    float* bias;
    size_t inFeatures;
    size_t outFeatures;
    
    Q4KLinearLayer(const void* weightData, size_t inFeat, size_t outFeat)
        : weights(weightData, outFeat, inFeat),
          inFeatures(inFeat),
          outFeatures(outFeatures) {
        bias = new float[outFeatures]();
    }
    
    ~Q4KLinearLayer() {
        delete[] bias;
    }
    
    void forward(const float* input, float* output) {
        Q4K_GEMV_Bias(weights, input, bias, output, outFeatures);
    }
};

} // namespace Deep2

// ============================================================================
// C Interface for integration
// ============================================================================
extern "C" {

__declspec(dllexport) void Deep2_Q4K_GEMV(
    const void* weights,
    const float* input,
    float* output,
    uint32_t numBlocks,
    uint32_t rows
) {
    Sovereign_Q4K_GEMV_AVX2(weights, input, output, numBlocks, rows);
}

}
