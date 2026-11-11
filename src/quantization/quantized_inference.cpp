// ============================================================================
// Quantized Inference Implementation
// ============================================================================

#include "quantized_inference.hpp"
#include <algorithm>
#include <cstring>
#include <cmath>
#include <iostream>

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
        case QuantType::Q4_K:
            num_blocks_ = (num_elements + Q4_K_BLOCK_SIZE - 1) / Q4_K_BLOCK_SIZE;
            data_.resize(num_blocks_ * sizeof(Q4_KBlock));
            break;
        case QuantType::Q2_K:
            num_blocks_ = (num_elements + Q2_K_BLOCK_SIZE - 1) / Q2_K_BLOCK_SIZE;
            data_.resize(num_blocks_ * sizeof(Q2_KBlock));
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
    // Only update type if not already set (preserve dimensions from Initialize)
    if (type_ == QuantType::F32 && rows_ == 0 && cols_ == 0) {
        // Not initialized yet - set as 1D tensor
        type_ = type;
        rows_ = 1;
        cols_ = num_elements;
    } else {
        // Already initialized - just update type and verify size
        type_ = type;
        size_t expected_elements = rows_ * cols_;
        if (num_elements != expected_elements && expected_elements > 0) {
            // Size mismatch - warn but continue
            // This can happen when loading into pre-initialized tensor
        }
    }
    
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
        case QuantType::Q4_K: {
            num_blocks_ = (num_elements + Q4_K_BLOCK_SIZE - 1) / Q4_K_BLOCK_SIZE;
            size_t bytes_needed = num_blocks_ * sizeof(Q4_KBlock);
            data_.resize(bytes_needed);
            std::memcpy(data_.data(), data, bytes_needed);
            break;
        }
        case QuantType::Q2_K: {
            num_blocks_ = (num_elements + Q2_K_BLOCK_SIZE - 1) / Q2_K_BLOCK_SIZE;
            size_t bytes_needed = num_blocks_ * sizeof(Q2_KBlock);
            data_.resize(bytes_needed);
            std::memcpy(data_.data(), data, bytes_needed);
            break;
        }
        case QuantType::Q6_K: {
            num_blocks_ = (num_elements + 255) / 256;  // 256 weights per Q6_K block
            size_t bytes_needed = num_blocks_ * sizeof(Q6_KBlock);
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
    size_t num_elements = rows_ * cols_;
    if (num_elements == 0) {
        return output;  // Empty tensor
    }
    output.resize(num_elements);
    
    switch (type_) {
        case QuantType::Q4_0:
            DequantizeQ4_0Scalar(output);
            break;
        case QuantType::Q8_0:
            DequantizeQ8_0Scalar(output);
            break;
        case QuantType::Q4_K:
            DequantizeQ4_KScalar(output);
            break;
        case QuantType::Q2_K:
            DequantizeQ2_KScalar(output);
            break;
        case QuantType::Q6_K:
            DequantizeQ6_KScalar(output);
            break;
        default:
            std::fill(output.begin(), output.end(), 0.0f);
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

bool QuantizedTensor::DequantizeQ4_KScalar(std::vector<float>& output) const {
    const Q4_KBlock* blocks = reinterpret_cast<const Q4_KBlock*>(data_.data());
    size_t idx = 0;
    
    for (size_t b = 0; b < num_blocks_ && idx < output.size(); b++) {
        float d = QuantizationUtils::F16ToF32(blocks[b].d);
        float dmin = QuantizationUtils::F16ToF32(blocks[b].dmin);
        
        // Unpack 6-bit scales (8 groups of 32 weights each)
        // 12 bytes contain 8 scales * 6 bits = 48 bits
        float scales[8];
        for (int i = 0; i < 8; i++) {
            // Extract 6-bit scale from packed bytes
            int byte_idx = i * 6 / 8;
            int bit_offset = (i * 6) % 8;
            uint32_t scale_bits = (blocks[b].scales[byte_idx] >> bit_offset) |
                                 ((blocks[b].scales[byte_idx + 1] << (8 - bit_offset)) & 0x3F);
            scales[i] = scale_bits / 63.0f;  // Normalize to 0-1
        }
        
        // Dequantize 256 weights
        for (int g = 0; g < 8 && idx < output.size(); g++) {
            float group_scale = d * scales[g];
            float group_min = dmin * scales[g];
            
            for (int i = 0; i < 32 && idx < output.size(); i++) {
                int quant_idx = g * 32 + i;
                int byte_idx = quant_idx / 2;
                int nibble = (quant_idx % 2 == 0) ? 
                    (blocks[b].quants[byte_idx] & 0x0F) : 
                    ((blocks[b].quants[byte_idx] >> 4) & 0x0F);
                
                output[idx++] = group_min + nibble * group_scale;
            }
        }
    }
    
    return true;
}

bool QuantizedTensor::DequantizeQ2_KScalar(std::vector<float>& output) const {
    const Q2_KBlock* blocks = reinterpret_cast<const Q2_KBlock*>(data_.data());
    size_t idx = 0;
    
    for (size_t b = 0; b < num_blocks_ && idx < output.size(); b++) {
        float d = QuantizationUtils::F16ToF32(blocks[b].d);
        float dmin = QuantizationUtils::F16ToF32(blocks[b].dmin);
        
        // Unpack 4-bit scales (16 groups of 16 weights each)
        // 32 bytes contain 16 scales * 4 bits = 64 bits per scale set
        float scales[16];
        for (int i = 0; i < 16; i++) {
            // Extract 4-bit scale from packed bytes
            int byte_idx = i / 2;
            int bit_offset = (i % 2) * 4;
            uint8_t scale_bits = (blocks[b].scales[byte_idx] >> bit_offset) & 0x0F;
            scales[i] = scale_bits / 15.0f;  // Normalize to 0-1
        }
        
        // Dequantize 256 weights (2-bit values)
        for (int g = 0; g < 16 && idx < output.size(); g++) {
            float group_scale = d * scales[g];
            float group_min = dmin * scales[g];
            
            for (int i = 0; i < 16 && idx < output.size(); i++) {
                int quant_idx = g * 16 + i;
                int byte_idx = quant_idx / 4;
                int bit_offset = (quant_idx % 4) * 2;
                uint8_t quant_bits = (blocks[b].quants[byte_idx] >> bit_offset) & 0x03;
                
                output[idx++] = group_min + quant_bits * group_scale;
            }
        }
    }
    
    return true;
}

bool QuantizedTensor::DequantizeQ6_KScalar(std::vector<float>& output) const {
    const Q6_KBlock* blocks = reinterpret_cast<const Q6_KBlock*>(data_.data());
    size_t idx = 0;
    
    for (size_t b = 0; b < num_blocks_ && idx < output.size(); b++) {
        float d = QuantizationUtils::F16ToF32(blocks[b].d);
        float dmin = QuantizationUtils::F16ToF32(blocks[b].dmin);
        
        // 16 groups of 16 weights each
        // scales[16] are 8-bit values
        for (int g = 0; g < 16 && idx < output.size(); g++) {
            float group_scale = d * blocks[b].scales[g] / 63.0f;  // 6-bit max
            float group_min = dmin * blocks[b].scales[g] / 63.0f;
            
            // Dequantize 16 weights (6-bit values packed in quants)
            for (int i = 0; i < 16 && idx < output.size(); i++) {
                int quant_idx = g * 16 + i;
                // 6-bit values packed: 4 values per 3 bytes
                int byte_idx = quant_idx * 3 / 4;
                int bit_offset = (quant_idx % 4) * 6;
                
                uint32_t packed = blocks[b].quants[byte_idx] |
                                 (blocks[b].quants[byte_idx + 1] << 8) |
                                 (blocks[b].quants[byte_idx + 2] << 16);
                uint8_t quant_bits = (packed >> bit_offset) & 0x3F;
                
                output[idx++] = group_min + quant_bits * group_scale;
            }
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
        case QuantType::Q4_K:
            return MatMulQ4_K(input, output, batch_size, input_dim, output_dim);
        case QuantType::Q2_K:
            return MatMulQ2_K(input, output, batch_size, input_dim, output_dim);
        case QuantType::Q6_K:
            // Q6_K: Dequantize to F32 then do MatMul
            return MatMulQ6_K(input, output, batch_size, input_dim, output_dim);
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

bool QuantizedTensor::MatMulQ4_K(const float* input, float* output,
                                  size_t batch_size, size_t input_dim, size_t output_dim) const {
    const Q4_KBlock* blocks = reinterpret_cast<const Q4_KBlock*>(data_.data());
    
    // Initialize output to zero
    std::memset(output, 0, batch_size * output_dim * sizeof(float));
    
    for (size_t b = 0; b < batch_size; b++) {
        const float* in_batch = input + b * input_dim;
        float* out_batch = output + b * output_dim;
        
        for (size_t o = 0; o < output_dim; o++) {
            float sum = 0.0f;
            
            for (size_t i = 0; i < input_dim; i++) {
                size_t current_block = (o * input_dim + i) / Q4_K_BLOCK_SIZE;
                size_t current_idx = (o * input_dim + i) % Q4_K_BLOCK_SIZE;
                
                if (current_block < num_blocks_) {
                    float d = QuantizationUtils::F16ToF32(blocks[current_block].d);
                    float dmin = QuantizationUtils::F16ToF32(blocks[current_block].dmin);
                    
                    // Get group (8 groups of 32 weights each)
                    int group = current_idx / 32;
                    int idx_in_group = current_idx % 32;
                    
                    // Extract 6-bit scale for this group
                    int scale_byte_idx = group * 6 / 8;
                    int scale_bit_offset = (group * 6) % 8;
                    uint32_t scale_bits = (blocks[current_block].scales[scale_byte_idx] >> scale_bit_offset) |
                                         ((blocks[current_block].scales[scale_byte_idx + 1] << (8 - scale_bit_offset)) & 0x3F);
                    float scale = scale_bits / 63.0f;
                    
                    // Get quantized value
                    int quant_idx = current_idx;
                    int byte_idx = quant_idx / 2;
                    int nibble = (quant_idx % 2 == 0) ? 
                        (blocks[current_block].quants[byte_idx] & 0x0F) : 
                        ((blocks[current_block].quants[byte_idx] >> 4) & 0x0F);
                    
                    float weight = dmin * scale + nibble * d * scale;
                    sum += in_batch[i] * weight;
                }
            }
            
            out_batch[o] = sum;
        }
    }
    
    return true;
}

bool QuantizedTensor::MatMulQ2_K(const float* input, float* output,
                                  size_t batch_size, size_t input_dim, size_t output_dim) const {
    const Q2_KBlock* blocks = reinterpret_cast<const Q2_KBlock*>(data_.data());
    
    // Initialize output to zero
    std::memset(output, 0, batch_size * output_dim * sizeof(float));
    
    for (size_t b = 0; b < batch_size; b++) {
        const float* in_batch = input + b * input_dim;
        float* out_batch = output + b * output_dim;
        
        for (size_t o = 0; o < output_dim; o++) {
            float sum = 0.0f;
            
            for (size_t i = 0; i < input_dim; i++) {
                size_t current_block = (o * input_dim + i) / Q2_K_BLOCK_SIZE;
                size_t current_idx = (o * input_dim + i) % Q2_K_BLOCK_SIZE;
                
                if (current_block < num_blocks_) {
                    float d = QuantizationUtils::F16ToF32(blocks[current_block].d);
                    float dmin = QuantizationUtils::F16ToF32(blocks[current_block].dmin);
                    
                    // Get group (16 groups of 16 weights each)
                    int group = current_idx / 16;
                    int idx_in_group = current_idx % 16;
                    
                    // Extract 4-bit scale for this group
                    int scale_byte_idx = group / 2;
                    int scale_bit_offset = (group % 2) * 4;
                    uint8_t scale_bits = (blocks[current_block].scales[scale_byte_idx] >> scale_bit_offset) & 0x0F;
                    float scale = scale_bits / 15.0f;
                    
                    // Get quantized value (2-bit)
                    int quant_idx = current_idx;
                    int byte_idx = quant_idx / 4;
                    int bit_offset = (quant_idx % 4) * 2;
                    uint8_t quant_bits = (blocks[current_block].quants[byte_idx] >> bit_offset) & 0x03;
                    
                    float weight = dmin * scale + quant_bits * d * scale;
                    sum += in_batch[i] * weight;
                }
            }
            
            out_batch[o] = sum;
        }
    }
    
    return true;
}

bool QuantizedTensor::MatMulQ6_K(const float* input, float* output,
                                  size_t batch_size, size_t input_dim, size_t output_dim) const {
    // Q6_K: Dequantize to F32 then do standard MatMul
    std::vector<float> dequant = DequantizeScalar();
    if (dequant.empty()) {
        return false;
    }
    
    // Initialize output to zero
    std::memset(output, 0, batch_size * output_dim * sizeof(float));
    
    // Standard matrix multiply: output = input @ weight^T
    for (size_t b = 0; b < batch_size; b++) {
        const float* in_batch = input + b * input_dim;
        float* out_batch = output + b * output_dim;
        
        for (size_t o = 0; o < output_dim; o++) {
            float sum = 0.0f;
            for (size_t i = 0; i < input_dim; i++) {
                size_t weight_idx = o * input_dim + i;
                if (weight_idx < dequant.size()) {
                    sum += in_batch[i] * dequant[weight_idx];
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
// Embedding Lookup Implementation
// ============================================================================

bool QuantizedTensor::GetEmbedding(int32_t token_id, float* output) const {
    // Embedding tensors can be stored as [hidden_size, vocab_size] (transposed)
    // In this case, we need to extract a column, not a row
    // Check if this looks like a transposed embedding (cols > rows, and cols is vocab-sized)
    if (cols_ > rows_ && cols_ > 10000) {
        // Likely transposed: [hidden_size, vocab_size]
        // For phi2: token_embd.weight is [2560, 51200] = [hidden_size, vocab_size]
        // So token_id is the column index
        if (token_id < 0 || token_id >= static_cast<int32_t>(cols_)) {
            return false;
        }
        return DequantizeColumn(static_cast<size_t>(token_id), output);
    }
    
    // Standard case: [vocab_size, hidden_size], token_id is row index
    if (token_id < 0 || token_id >= static_cast<int32_t>(rows_)) {
        return false;
    }
    return DequantizeRow(static_cast<size_t>(token_id), output);
}

bool QuantizedTensor::DequantizeColumn(size_t col_idx, float* output) const {
    if (col_idx >= cols_) {
        return false;
    }
    
    // For transposed embeddings, we need to extract one value from each row
    // This is inefficient but necessary for the transposed layout
    switch (type_) {
        case QuantType::Q2_K: {
            // Q2_K: 256 weights per block, need to find which block contains col_idx
            const Q2_KBlock* blocks = reinterpret_cast<const Q2_KBlock*>(data_.data());
            size_t weights_per_block = Q2_KBlock::NUM_WEIGHTS;  // 256
            
            for (size_t r = 0; r < rows_; r++) {
                // Calculate which block contains the value at (r, col_idx)
                size_t global_idx = r * cols_ + col_idx;
                size_t block_idx = global_idx / weights_per_block;
                size_t idx_in_block = global_idx % weights_per_block;
                
                if (block_idx < num_blocks_) {
                    const Q2_KBlock* block = &blocks[block_idx];
                    float d = QuantizationUtils::F16ToF32(block->d);
                    float dmin = QuantizationUtils::F16ToF32(block->dmin);
                    
                    // Get scale for this group of 16 weights
                    size_t group_idx = idx_in_block / 16;
                    uint8_t scale_byte = block->scales[group_idx / 2];
                    int scale = (group_idx % 2 == 0) ? (scale_byte & 0x0F) : ((scale_byte >> 4) & 0x0F);
                    
                    // Get quantized value
                    size_t quant_idx = idx_in_block / 4;
                    size_t nibble_idx = idx_in_block % 4;
                    uint8_t quant_byte = block->quants[quant_idx];
                    int quant = (quant_byte >> (2 * nibble_idx)) & 0x03;
                    
                    output[r] = dmin + d * scale * quant;
                } else {
                    output[r] = 0.0f;
                }
            }
            return true;
        }
        
        case QuantType::Q4_0: {
            const Q4_0Block* blocks = reinterpret_cast<const Q4_0Block*>(data_.data());
            size_t weights_per_block = Q4_0_BLOCK_SIZE;  // 32
            
            for (size_t r = 0; r < rows_; r++) {
                size_t global_idx = r * cols_ + col_idx;
                size_t block_idx = global_idx / weights_per_block;
                size_t idx_in_block = global_idx % weights_per_block;
                
                if (block_idx < num_blocks_) {
                    const Q4_0Block* block = &blocks[block_idx];
                    float scale = QuantizationUtils::F16ToF32(block->scale_f16);
                    uint8_t byte = block->quants[idx_in_block / 2];
                    int8_t nibble = (idx_in_block % 2 == 0) ? 
                        (byte & 0x0F) - 8 : ((byte >> 4) & 0x0F) - 8;
                    output[r] = nibble * scale;
                } else {
                    output[r] = 0.0f;
                }
            }
            return true;
        }
        
        case QuantType::Q8_0: {
            const Q8_0Block* blocks = reinterpret_cast<const Q8_0Block*>(data_.data());
            size_t weights_per_block = Q8_0_BLOCK_SIZE;  // 32
            
            for (size_t r = 0; r < rows_; r++) {
                size_t global_idx = r * cols_ + col_idx;
                size_t block_idx = global_idx / weights_per_block;
                size_t idx_in_block = global_idx % weights_per_block;
                
                if (block_idx < num_blocks_) {
                    const Q8_0Block* block = &blocks[block_idx];
                    float scale = QuantizationUtils::F16ToF32(block->scale_f16);
                    output[r] = block->quants[idx_in_block] * scale;
                } else {
                    output[r] = 0.0f;
                }
            }
            return true;
        }
        
        default:
            std::fill(output, output + rows_, 0.0f);
            return false;
    }
}

bool QuantizedTensor::DequantizeRow(size_t row_idx, float* output) const {
    if (row_idx >= rows_) {
        return false;
    }
    
    switch (type_) {
        case QuantType::Q4_0: {
            const Q4_0Block* blocks = reinterpret_cast<const Q4_0Block*>(data_.data());
            size_t blocks_per_row = (cols_ + Q4_0_BLOCK_SIZE - 1) / Q4_0_BLOCK_SIZE;
            size_t row_block_start = row_idx * blocks_per_row;
            
            for (size_t c = 0; c < cols_; c++) {
                size_t block_idx = row_block_start + (c / Q4_0_BLOCK_SIZE);
                size_t idx_in_block = c % Q4_0_BLOCK_SIZE;
                
                if (block_idx < num_blocks_) {
                    float scale = QuantizationUtils::F16ToF32(blocks[block_idx].scale_f16);
                    uint8_t byte = blocks[block_idx].quants[idx_in_block / 2];
                    int8_t nibble = (idx_in_block % 2 == 0) ? 
                        (byte & 0x0F) - 8 : ((byte >> 4) & 0x0F) - 8;
                    output[c] = nibble * scale;
                } else {
                    output[c] = 0.0f;
                }
            }
            return true;
        }
        
        case QuantType::Q8_0: {
            const Q8_0Block* blocks = reinterpret_cast<const Q8_0Block*>(data_.data());
            size_t blocks_per_row = (cols_ + Q8_0_BLOCK_SIZE - 1) / Q8_0_BLOCK_SIZE;
            size_t row_block_start = row_idx * blocks_per_row;
            
            for (size_t c = 0; c < cols_; c++) {
                size_t block_idx = row_block_start + (c / Q8_0_BLOCK_SIZE);
                size_t idx_in_block = c % Q8_0_BLOCK_SIZE;
                
                if (block_idx < num_blocks_) {
                    float scale = QuantizationUtils::F16ToF32(blocks[block_idx].scale_f16);
                    output[c] = blocks[block_idx].quants[idx_in_block] * scale;
                } else {
                    output[c] = 0.0f;
                }
            }
            return true;
        }
        
        case QuantType::F32: {
            // For F32, data is stored as raw floats
            const float* float_data = reinterpret_cast<const float*>(data_.data());
            std::memcpy(output, float_data + row_idx * cols_, cols_ * sizeof(float));
            return true;
        }
        
        default:
            // Other quantization types not yet implemented
            std::fill(output, output + cols_, 0.0f);
            return false;
    }
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

// ============================================================================
// QuantizedTensor SplitByColumns Implementation
// ============================================================================

bool QuantizedTensor::SplitByColumns(QuantizedTensor& out1, QuantizedTensor& out2, 
                                      QuantizedTensor& out3, size_t num_splits) const {
    if (num_splits != 3) {
        std::cerr << "SplitByColumns: Only 3-way split supported" << std::endl;
        return false;
    }
    
    if (cols_ % num_splits != 0) {
        std::cerr << "SplitByColumns: Columns not evenly divisible by " << num_splits << std::endl;
        return false;
    }
    
    size_t split_cols = cols_ / num_splits;
    
    // Initialize output tensors
    if (!out1.Initialize(type_, rows_, split_cols) ||
        !out2.Initialize(type_, rows_, split_cols) ||
        !out3.Initialize(type_, rows_, split_cols)) {
        std::cerr << "SplitByColumns: Failed to initialize output tensors" << std::endl;
        return false;
    }
    
    // For F32 tensors, we can directly copy the data
    if (type_ == QuantType::F32) {
        const float* src = reinterpret_cast<const float*>(data_.data());
        float* dst1 = reinterpret_cast<float*>(out1.data_.data());
        float* dst2 = reinterpret_cast<float*>(out2.data_.data());
        float* dst3 = reinterpret_cast<float*>(out3.data_.data());
        
        for (size_t r = 0; r < rows_; r++) {
            const float* src_row = src + r * cols_;
            std::memcpy(dst1 + r * split_cols, src_row, split_cols * sizeof(float));
            std::memcpy(dst2 + r * split_cols, src_row + split_cols, split_cols * sizeof(float));
            std::memcpy(dst3 + r * split_cols, src_row + 2 * split_cols, split_cols * sizeof(float));
        }
        return true;
    }
    
    // For quantized tensors, we need to dequantize, split, and re-quantize
    // This is a simplified implementation - for production, we'd want to split at block boundaries
    std::cerr << "SplitByColumns: Quantized tensor splitting requires dequantize/re-quantize" << std::endl;
    
    // Dequantize the entire tensor
    std::vector<float> dequant = DequantizeScalar();
    if (dequant.empty()) {
        std::cerr << "SplitByColumns: Failed to dequantize tensor" << std::endl;
        return false;
    }
    
    // Split the dequantized data
    std::vector<float> split1(rows_ * split_cols);
    std::vector<float> split2(rows_ * split_cols);
    std::vector<float> split3(rows_ * split_cols);
    
    for (size_t r = 0; r < rows_; r++) {
        const float* src_row = dequant.data() + r * cols_;
        std::memcpy(split1.data() + r * split_cols, src_row, split_cols * sizeof(float));
        std::memcpy(split2.data() + r * split_cols, src_row + split_cols, split_cols * sizeof(float));
        std::memcpy(split3.data() + r * split_cols, src_row + 2 * split_cols, split_cols * sizeof(float));
    }
    
    // Re-quantize each split
    bool success = true;
    switch (type_) {
        case QuantType::Q8_0:
            success &= QuantizationUtils::QuantizeF32ToQ8_0(split1.data(), split1.size(), out1.data_);
            success &= QuantizationUtils::QuantizeF32ToQ8_0(split2.data(), split2.size(), out2.data_);
            success &= QuantizationUtils::QuantizeF32ToQ8_0(split3.data(), split3.size(), out3.data_);
            break;
        case QuantType::Q4_0:
            success &= QuantizationUtils::QuantizeF32ToQ4_0(split1.data(), split1.size(), out1.data_);
            success &= QuantizationUtils::QuantizeF32ToQ4_0(split2.data(), split2.size(), out2.data_);
            success &= QuantizationUtils::QuantizeF32ToQ4_0(split3.data(), split3.size(), out3.data_);
            break;
        case QuantType::Q4_1:
            // Q4_1 uses same quantization as Q4_0 but with different block structure
            // For now, convert to Q4_0 (they're compatible)
            success &= QuantizationUtils::QuantizeF32ToQ4_0(split1.data(), split1.size(), out1.data_);
            success &= QuantizationUtils::QuantizeF32ToQ4_0(split2.data(), split2.size(), out2.data_);
            success &= QuantizationUtils::QuantizeF32ToQ4_0(split3.data(), split3.size(), out3.data_);
            // Update type to Q4_0 since that's what we actually created
            out1.type_ = QuantType::Q4_0;
            out2.type_ = QuantType::Q4_0;
            out3.type_ = QuantType::Q4_0;
            break;
        case QuantType::Q2_K:
            // Q2_K uses K-quants - convert to Q4_0 for simplicity
            success &= QuantizationUtils::QuantizeF32ToQ4_0(split1.data(), split1.size(), out1.data_);
            success &= QuantizationUtils::QuantizeF32ToQ4_0(split2.data(), split2.size(), out2.data_);
            success &= QuantizationUtils::QuantizeF32ToQ4_0(split3.data(), split3.size(), out3.data_);
            // Update type to Q4_0 since that's what we actually created
            out1.type_ = QuantType::Q4_0;
            out2.type_ = QuantType::Q4_0;
            out3.type_ = QuantType::Q4_0;
            break;
        default:
            std::cerr << "SplitByColumns: Unsupported quantization type " << static_cast<int>(type_) << std::endl;
            return false;
    }
    
    return success;
}

} // namespace quantization
} // namespace rawrxd
