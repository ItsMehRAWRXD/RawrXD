// ============================================================================
// Quantized Inference Implementation
// ============================================================================

#include "quantized_inference.hpp"
#include <algorithm>
#include <cstring>
#include <cmath>

namespace rawrxd {
namespace quantization {

// ============================================================================
// F16/F32 Conversion
// ============================================================================

float QuantizationUtils::F16ToF32(uint16_t f16) {
    uint32_t sign = (f16 >> 15) & 0x1;
    uint32_t exp = (f16 >> 10) & 0x1F;
    uint32_t mant = f16 & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float val = mant / 1024.0f;
        return (sign ? -1.0f : 1.0f) * val * std::pow(2.0f, -14);
    }
    if (exp == 31) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    
    float val = 1.0f + mant / 1024.0f;
    int32_t exp32 = exp - 15 + 127;
    uint32_t f32 = (sign << 31) | (exp32 << 23) | (mant << 13);
    float result;
    std::memcpy(&result, &f32, sizeof(result));
    return result;
}

uint16_t QuantizationUtils::F32ToF16(float f32) {
    uint32_t f32_bits;
    std::memcpy(&f32_bits, &f32, sizeof(f32_bits));
    
    uint32_t sign = (f32_bits >> 31) & 0x1;
    uint32_t exp = (f32_bits >> 23) & 0xFF;
    uint32_t mant = f32_bits & 0x7FFFFF;
    
    if (exp == 0) {
        return sign << 15;  // Zero or subnormal -> zero
    }
    if (exp == 255) {
        return (sign << 15) | 0x7C00;  // Inf or NaN
    }
    
    int32_t exp16 = exp - 127 + 15;
    if (exp16 <= 0) {
        return sign << 15;  // Underflow to zero
    }
    if (exp16 >= 31) {
        return (sign << 15) | 0x7C00;  // Overflow to inf
    }
    
    uint16_t mant16 = mant >> 13;
    return (sign << 15) | (exp16 << 10) | mant16;
}

// ============================================================================
// QuantizedTensor Implementation
// ============================================================================

QuantizedTensor::QuantizedTensor() 
    : type_(QuantType::F32), rows_(0), cols_(0), num_blocks_(0) {}

QuantizedTensor::~QuantizedTensor() = default;

bool QuantizedTensor::Initialize(QuantType type, size_t rows, size_t cols) {
    type_ = type;
    rows_ = rows;
    cols_ = cols;
    
    size_t num_elements = rows * cols;
    
    switch (type_) {
        case QuantType::Q4_0:
            num_blocks_ = (num_elements + Q4_0_BLOCK_SIZE - 1) / Q4_0_BLOCK_SIZE;
            data_.resize(num_blocks_ * sizeof(Q4_0Block));
            break;
        case QuantType::Q8_0:
            num_blocks_ = (num_elements + Q8_0_BLOCK_SIZE - 1) / Q8_0_BLOCK_SIZE;
            data_.resize(num_blocks_ * sizeof(Q8_0Block));
            break;
        case QuantType::F32:
            data_.resize(num_elements * sizeof(float));
            break;
        default:
            return false;
    }
    
    return true;
}

bool QuantizedTensor::LoadFromGGUF(const uint8_t* data, size_t num_elements, QuantType type) {
    type_ = type;
    rows_ = 1;  // Treat as 1D tensor for simple loading
    cols_ = num_elements;
    
    switch (type_) {
        case QuantType::Q4_0: {
            num_blocks_ = (num_elements + Q4_0_BLOCK_SIZE - 1) / Q4_0_BLOCK_SIZE;
            size_t bytes_needed = num_blocks_ * sizeof(Q4_0Block);
            data_.resize(bytes_needed);
            std::memcpy(data_.data(), data, bytes_needed);
            break;
        }
        case QuantType::Q8_0: {
            num_blocks_ = (num_elements + Q8_0_BLOCK_SIZE - 1) / Q8_0_BLOCK_SIZE;
            size_t bytes_needed = num_blocks_ * sizeof(Q8_0Block);
            data_.resize(bytes_needed);
            std::memcpy(data_.data(), data, bytes_needed);
            break;
        }
        default:
            return false;
    }
    
    return true;
}

std::vector<float> QuantizedTensor::DequantizeScalar() const {
    std::vector<float> output;
    output.resize(rows_ * cols_);
    
    switch (type_) {
        case QuantType::Q4_0:
            DequantizeQ4_0Scalar(output);
            break;
        case QuantType::Q8_0:
            DequantizeQ8_0Scalar(output);
            break;
        default:
            break;
    }
    
    return output;
}

bool QuantizedTensor::DequantizeQ4_0Scalar(std::vector<float>& output) const {
    const Q4_0Block* blocks = reinterpret_cast<const Q4_0Block*>(data_.data());
    size_t idx = 0;
    
    for (size_t b = 0; b < num_blocks_ && idx < output.size(); b++) {
        float scale = QuantizationUtils::F16ToF32(blocks[b].scale_f16);
        
        for (int i = 0; i < 16 && idx < output.size(); i++) {
            uint8_t byte = blocks[b].quants[i];
            int8_t nibble0 = (byte & 0x0F) - 8;
            int8_t nibble1 = ((byte >> 4) & 0x0F) - 8;
            
            output[idx++] = nibble0 * scale;
            if (idx < output.size()) {
                output[idx++] = nibble1 * scale;
            }
        }
    }
    
    return true;
}

bool QuantizedTensor::DequantizeQ8_0Scalar(std::vector<float>& output) const {
    const Q8_0Block* blocks = reinterpret_cast<const Q8_0Block*>(data_.data());
    size_t idx = 0;
    
    for (size_t b = 0; b < num_blocks_ && idx < output.size(); b++) {
        float scale = QuantizationUtils::F16ToF32(blocks[b].scale_f16);
        
        for (int i = 0; i < 32 && idx < output.size(); i++) {
            output[idx++] = blocks[b].quants[i] * scale;
        }
    }
    
    return true;
}

bool QuantizedTensor::MatMul(const float* input, float* output,
                              size_t batch_size, size_t input_dim, size_t output_dim) const {
    switch (type_) {
        case QuantType::Q4_0:
            return MatMulQ4_0(input, output, batch_size, input_dim, output_dim);
        case QuantType::Q8_0:
            return MatMulQ8_0(input, output, batch_size, input_dim, output_dim);
        default:
            return false;
    }
}

bool QuantizedTensor::MatMulQ4_0(const float* input, float* output,
                                  size_t batch_size, size_t input_dim, size_t output_dim) const {
    const Q4_0Block* blocks = reinterpret_cast<const Q4_0Block*>(data_.data());
    
    // Initialize output to zero
    std::memset(output, 0, batch_size * output_dim * sizeof(float));
    
    for (size_t b = 0; b < batch_size; b++) {
        const float* in_batch = input + b * input_dim;
        float* out_batch = output + b * output_dim;
        
        for (size_t o = 0; o < output_dim; o++) {
            float sum = 0.0f;
            size_t block_idx = (o * input_dim) / Q4_0_BLOCK_SIZE;
            size_t idx_in_block = (o * input_dim) % Q4_0_BLOCK_SIZE;
            
            for (size_t i = 0; i < input_dim; i++) {
                size_t current_block = (o * input_dim + i) / Q4_0_BLOCK_SIZE;
                size_t current_idx = (o * input_dim + i) % Q4_0_BLOCK_SIZE;
                
                if (current_block < num_blocks_) {
                    float scale = QuantizationUtils::F16ToF32(blocks[current_block].scale_f16);
                    uint8_t byte = blocks[current_block].quants[current_idx / 2];
                    int8_t nibble = (current_idx % 2 == 0) ? 
                        (byte & 0x0F) - 8 : ((byte >> 4) & 0x0F) - 8;
                    
                    sum += in_batch[i] * (nibble * scale);
                }
            }
            
            out_batch[o] = sum;
        }
    }
    
    return true;
}

bool QuantizedTensor::MatMulQ8_0(const float* input, float* output,
                                  size_t batch_size, size_t input_dim, size_t output_dim) const {
    const Q8_0Block* blocks = reinterpret_cast<const Q8_0Block*>(data_.data());
    
    // Initialize output to zero
    std::memset(output, 0, batch_size * output_dim * sizeof(float));
    
    for (size_t b = 0; b < batch_size; b++) {
        const float* in_batch = input + b * input_dim;
        float* out_batch = output + b * output_dim;
        
        for (size_t o = 0; o < output_dim; o++) {
            float sum = 0.0f;
            
            for (size_t i = 0; i < input_dim; i++) {
                size_t current_block = (o * input_dim + i) / Q8_0_BLOCK_SIZE;
                size_t current_idx = (o * input_dim + i) % Q8_0_BLOCK_SIZE;
                
                if (current_block < num_blocks_) {
                    float scale = QuantizationUtils::F16ToF32(blocks[current_block].scale_f16);
                    sum += in_batch[i] * (blocks[current_block].quants[current_idx] * scale);
                }
            }
            
            out_batch[o] = sum;
        }
    }
    
    return true;
}

size_t QuantizedTensor::GetMemoryUsageBytes() const {
    return data_.size();
}

size_t QuantizedTensor::GetMemorySavingsBytes() const {
    size_t f32_size = rows_ * cols_ * sizeof(float);
    return f32_size - data_.size();
}

// ============================================================================
// QuantizationUtils Implementation
// ============================================================================

bool QuantizationUtils::QuantizeF32ToQ8_0(const float* input, size_t num_elements,
                                            std::vector<uint8_t>& output) {
    size_t num_blocks = (num_elements + Q8_0_BLOCK_SIZE - 1) / Q8_0_BLOCK_SIZE;
    output.resize(num_blocks * sizeof(Q8_0Block));
    Q8_0Block* blocks = reinterpret_cast<Q8_0Block*>(output.data());
    
    for (size_t b = 0; b < num_blocks; b++) {
        // Find max abs value in block
        float max_abs = 0.0f;
        size_t start = b * Q8_0_BLOCK_SIZE;
        size_t end = std::min(start + Q8_0_BLOCK_SIZE, num_elements);
        
        for (size_t i = start; i < end; i++) {
            max_abs = std::max(max_abs, std::abs(input[i]));
        }
        
        // Calculate scale (avoid division by zero)
        float scale = (max_abs > 0.0f) ? (max_abs / 127.0f) : 1.0f;
        blocks[b].scale_f16 = QuantizationUtils::F32ToF16(scale);
        
        // Quantize
        for (size_t i = start; i < end; i++) {
            blocks[b].quants[i - start] = static_cast<int8_t>(std::round(input[i] / scale));
        }
        // Pad remaining
        for (size_t i = end - start; i < Q8_0_BLOCK_SIZE; i++) {
            blocks[b].quants[i] = 0;
        }
    }
    
    return true;
}

bool QuantizationUtils::QuantizeF32ToQ4_0(const float* input, size_t num_elements,
                                          std::vector<uint8_t>& output) {
    size_t num_blocks = (num_elements + Q4_0_BLOCK_SIZE - 1) / Q4_0_BLOCK_SIZE;
    output.resize(num_blocks * sizeof(Q4_0Block));
    Q4_0Block* blocks = reinterpret_cast<Q4_0Block*>(output.data());
    
    for (size_t b = 0; b < num_blocks; b++) {
        // Find max abs value in block
        float max_abs = 0.0f;
        size_t start = b * Q4_0_BLOCK_SIZE;
        size_t end = std::min(start + Q4_0_BLOCK_SIZE, num_elements);
        
        for (size_t i = start; i < end; i++) {
            max_abs = std::max(max_abs, std::abs(input[i]));
        }
        
        // Calculate scale (avoid division by zero)
        float scale = (max_abs > 0.0f) ? (max_abs / 7.0f) : 1.0f;
        blocks[b].scale_f16 = QuantizationUtils::F32ToF16(scale);
        
        // Quantize (pack nibbles)
        for (size_t i = start; i < end; i += 2) {
            int8_t nibble0 = static_cast<int8_t>(std::round(input[i] / scale)) + 8;
            int8_t nibble1 = (i + 1 < end) ? 
                static_cast<int8_t>(std::round(input[i + 1] / scale)) + 8 : 8;
            
            blocks[b].quants[(i - start) / 2] = 
                (static_cast<uint8_t>(nibble0) & 0x0F) | 
                ((static_cast<uint8_t>(nibble1) & 0x0F) << 4);
        }
    }
    
    return true;
}

float QuantizationUtils::CalculateError(const float* original, const float* dequantized,
                                       size_t num_elements) {
    float sum_error = 0.0f;
    float sum_original = 0.0f;
    
    for (size_t i = 0; i < num_elements; i++) {
        sum_error += std::abs(original[i] - dequantized[i]);
        sum_original += std::abs(original[i]);
    }
    
    return (sum_original > 0.0f) ? sum_error / sum_original : 0.0f;
}

const char* QuantizationUtils::GetTypeName(QuantType type) {
    switch (type) {
        case QuantType::F32: return "F32";
        case QuantType::Q8_0: return "Q8_0";
        case QuantType::Q4_0: return "Q4_0";
        case QuantType::Q4_K: return "Q4_K";
        case QuantType::Q6_K: return "Q6_K";
        default: return "Unknown";
    }
}

float QuantizationUtils::GetCompressionRatio(QuantType type) {
    switch (type) {
        case QuantType::F32: return 1.0f;
        case QuantType::Q8_0: return 4.0f;  // 32 bits -> 8 bits
        case QuantType::Q4_0: return 8.0f;  // 32 bits -> 4 bits
        case QuantType::Q4_K: return 8.0f;
        case QuantType::Q6_K: return 5.33f;
        default: return 1.0f;
    }
}

// ============================================================================
// QuantizedTransformerLayer Stub Implementation
// ============================================================================
// These are stubs - full implementation is in quantized_transformer_layer.cpp

QuantizedTransformerLayer::QuantizedTransformerLayer() 
    : hidden_size_(0), num_heads_(0), num_kv_heads_(0), intermediate_size_(0) {}

QuantizedTransformerLayer::~QuantizedTransformerLayer() = default;

bool QuantizedTransformerLayer::Initialize(uint32_t hidden_size, uint32_t num_heads,
                                            uint32_t num_kv_heads, uint32_t intermediate_size) {
    hidden_size_ = hidden_size;
    num_heads_ = num_heads;
    num_kv_heads_ = num_kv_heads;
    intermediate_size_ = intermediate_size;
    return true;
}

bool QuantizedTransformerLayer::LoadWeights(std::unique_ptr<QuantizedLayerWeights> weights) {
    weights_ = std::move(weights);
    return true;
}

bool QuantizedTransformerLayer::Forward(const float* input, float* output,
                                         void* kv_cache, uint32_t position) {
    // Stub - full implementation in quantized_transformer_layer.cpp
    return true;
}

size_t QuantizedTransformerLayer::GetMemoryUsage() const {
    return 0;
}

size_t QuantizedTransformerLayer::GetMemorySavings() const {
    return 0;
}

// ============================================================================
// QuantizedLayerWeights Stub Implementation
// ============================================================================

bool QuantizedLayerWeights::LoadFromGGUF(void* loader, int layer_idx) {
    // Stub
    return true;
}

size_t QuantizedLayerWeights::GetTotalMemoryUsage() const {
    size_t total = 0;
    if (q_weight) total += q_weight->GetMemoryUsageBytes();
    if (k_weight) total += k_weight->GetMemoryUsageBytes();
    if (v_weight) total += v_weight->GetMemoryUsageBytes();
    if (o_weight) total += o_weight->GetMemoryUsageBytes();
    if (ffn_gate) total += ffn_gate->GetMemoryUsageBytes();
    if (ffn_up) total += ffn_up->GetMemoryUsageBytes();
    if (ffn_down) total += ffn_down->GetMemoryUsageBytes();
    return total;
}

size_t QuantizedLayerWeights::GetTotalMemorySavings() const {
    size_t total = 0;
    if (q_weight) total += q_weight->GetMemorySavingsBytes();
    if (k_weight) total += k_weight->GetMemorySavingsBytes();
    if (v_weight) total += v_weight->GetMemorySavingsBytes();
    if (o_weight) total += o_weight->GetMemorySavingsBytes();
    if (ffn_gate) total += ffn_gate->GetMemorySavingsBytes();
    if (ffn_up) total += ffn_up->GetMemorySavingsBytes();
    if (ffn_down) total += ffn_down->GetMemorySavingsBytes();
    return total;
}

} // namespace quantization
} // namespace rawrxd
