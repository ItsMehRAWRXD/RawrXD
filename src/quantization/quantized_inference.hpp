// ============================================================================
// Quantized Inference - Q4_0 and Q8_0 Support
// ============================================================================
// Enables 4-bit and 8-bit quantized weights throughout the pipeline
// ============================================================================

#pragma once

#include <vector>
#include <cstdint>
#include <memory>
#include <cstring>
#include <cmath>

namespace rawrxd {
namespace quantization {

// ============================================================================
// Quantization Types
// ============================================================================

enum class QuantType {
    F32,      // Full precision (reference)
    Q8_0,     // 8-bit quantization
    Q4_0,     // 4-bit quantization
    Q4_K,     // 4-bit with K-quants
    Q6_K      // 6-bit with K-quants
};

// Block sizes for quantization
constexpr size_t Q4_0_BLOCK_SIZE = 32;
constexpr size_t Q8_0_BLOCK_SIZE = 32;
constexpr size_t Q4_K_BLOCK_SIZE = 256;

// ============================================================================
// Q4_0 Block Structure
// ============================================================================
// 18 bytes per 32 weights:
// - 2 bytes: scale (F16)
// - 16 bytes: 32 nibbles (4-bit values)
struct Q4_0Block {
    uint16_t scale_f16;           // Scale factor (F16)
    uint8_t quants[16];           // 32 nibbles packed into 16 bytes
    
    static constexpr size_t NUM_WEIGHTS = 32;
    static constexpr size_t BYTES = 18;
};

// ============================================================================
// Q8_0 Block Structure
// ============================================================================
// 34 bytes per 32 weights:
// - 2 bytes: scale (F16)
// - 32 bytes: 32 signed int8 values
struct Q8_0Block {
    uint16_t scale_f16;           // Scale factor (F16)
    int8_t quants[32];            // 32 signed int8 values
    
    static constexpr size_t NUM_WEIGHTS = 32;
    static constexpr size_t BYTES = 34;
};

// ============================================================================
// Quantized Tensor
// ============================================================================

class QuantizedTensor {
public:
    QuantizedTensor();
    ~QuantizedTensor();
    
    // Initialize with dimensions
    bool Initialize(QuantType type, size_t rows, size_t cols);
    
    // Load from GGUF data
    bool LoadFromGGUF(const uint8_t* data, size_t num_elements, QuantType type);
    
    // Dequantize to F32 (scalar)
    std::vector<float> DequantizeScalar() const;
    
    // Dequantize to F32 (AVX512 optimized)
    std::vector<float> DequantizeAVX512() const;
    
    // Matrix multiply: this @ input -> output
    // Input and output are F32, this is quantized
    bool MatMul(const float* input, float* output, 
                size_t batch_size, size_t input_dim, size_t output_dim) const;
    
    // Getters
    QuantType GetType() const { return type_; }
    size_t GetRows() const { return rows_; }
    size_t GetCols() const { return cols_; }
    size_t GetNumElements() const { return rows_ * cols_; }
    size_t GetNumBlocks() const { return num_blocks_; }
    
    // Memory usage
    size_t GetMemoryUsageBytes() const;
    size_t GetMemorySavingsBytes() const;  // vs F32
    
private:
    QuantType type_;
    size_t rows_;
    size_t cols_;
    size_t num_blocks_;
    
    std::vector<uint8_t> data_;  // Raw quantized data
    
    // Helper functions
    bool DequantizeQ4_0Scalar(std::vector<float>& output) const;
    bool DequantizeQ8_0Scalar(std::vector<float>& output) const;
    bool DequantizeQ4_0AVX512(std::vector<float>& output) const;
    bool DequantizeQ8_0AVX512(std::vector<float>& output) const;
    
    bool MatMulQ4_0(const float* input, float* output,
                     size_t batch_size, size_t input_dim, size_t output_dim) const;
    bool MatMulQ8_0(const float* input, float* output,
                     size_t batch_size, size_t input_dim, size_t output_dim) const;
};

// ============================================================================
// Quantized Layer Weights
// ============================================================================

struct QuantizedLayerWeights {
    // Attention weights
    std::unique_ptr<QuantizedTensor> q_weight;
    std::unique_ptr<QuantizedTensor> k_weight;
    std::unique_ptr<QuantizedTensor> v_weight;
    std::unique_ptr<QuantizedTensor> o_weight;
    std::unique_ptr<QuantizedTensor> attn_norm;
    
    // FFN weights
    std::unique_ptr<QuantizedTensor> ffn_gate;
    std::unique_ptr<QuantizedTensor> ffn_up;
    std::unique_ptr<QuantizedTensor> ffn_down;
    std::unique_ptr<QuantizedTensor> ffn_norm;
    
    // Load all weights from GGUF loader
    bool LoadFromGGUF(void* loader, int layer_idx);
    
    // Get total memory usage
    size_t GetTotalMemoryUsage() const;
    size_t GetTotalMemorySavings() const;
};

// ============================================================================
// Quantized Transformer Layer
// ============================================================================

class QuantizedTransformerLayer {
public:
    QuantizedTransformerLayer();
    ~QuantizedTransformerLayer();
    
    // Initialize with configuration
    bool Initialize(uint32_t hidden_size, uint32_t num_heads, 
                    uint32_t num_kv_heads, uint32_t intermediate_size);
    
    // Load quantized weights
    bool LoadWeights(std::unique_ptr<QuantizedLayerWeights> weights);
    
    // Forward pass with quantized weights
    bool Forward(const float* input, float* output,
                 void* kv_cache, uint32_t position);
    
    // Get memory stats
    size_t GetMemoryUsage() const;
    size_t GetMemorySavings() const;
    
private:
    uint32_t hidden_size_;
    uint32_t num_heads_;
    uint32_t num_kv_heads_;
    uint32_t intermediate_size_;
    
    std::unique_ptr<QuantizedLayerWeights> weights_;
    
    // Working buffers
    std::vector<float> normed_;
    std::vector<float> q_proj_;
    std::vector<float> k_proj_;
    std::vector<float> v_proj_;
    std::vector<float> attn_out_;
    std::vector<float> ffn_gate_;
    std::vector<float> ffn_up_;
    std::vector<float> ffn_act_;
};

// ============================================================================
// Quantization Utilities
// ============================================================================

class QuantizationUtils {
public:
    // F16 to F32 conversion
    static float F16ToF32(uint16_t f16);
    static uint16_t F32ToF16(float f32);
    
    // Quantize F32 to Q8_0
    static bool QuantizeF32ToQ8_0(const float* input, size_t num_elements,
                                   std::vector<uint8_t>& output);
    
    // Quantize F32 to Q4_0
    static bool QuantizeF32ToQ4_0(const float* input, size_t num_elements,
                                   std::vector<uint8_t>& output);
    
    // Calculate quantization error
    static float CalculateError(const float* original, const float* dequantized,
                                 size_t num_elements);
    
    // Get quantization type name
    static const char* GetTypeName(QuantType type);
    
    // Get compression ratio
    static float GetCompressionRatio(QuantType type);
};

// ============================================================================
// Performance Metrics
// ============================================================================

struct QuantizedPerformanceMetrics {
    double dequantize_ms = 0.0;
    double matmul_ms = 0.0;
    double total_ms = 0.0;
    
    size_t memory_used_bytes = 0;
    size_t memory_saved_bytes = 0;
    float compression_ratio = 1.0f;
    
    double throughput_gops = 0.0;
    double tokens_per_second = 0.0;
};

} // namespace quantization
} // namespace rawrxd
