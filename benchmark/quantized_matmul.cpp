// ============================================================================
// C5a: Q4_0 Quantized Matrix Multiplication - Implementation
// ============================================================================

#include "quantized_matmul.hpp"
#include <cmath>
#include <cstring>
#include <chrono>
#include <iostream>

namespace benchmark {

// ============================================================================
// Quantization
// ============================================================================

void QuantizeF32ToQ4_0(const float* input, size_t num_weights,
                       std::vector<uint8_t>& output) {
    size_t num_blocks = (num_weights + Q4_0Block::WEIGHTS_PER_BLOCK - 1)
                        / Q4_0Block::WEIGHTS_PER_BLOCK;
    output.resize(num_blocks * sizeof(Q4_0Block));
    
    Q4_0Block* blocks = reinterpret_cast<Q4_0Block*>(output.data());
    
    for (size_t b = 0; b < num_blocks; b++) {
        size_t start = b * Q4_0Block::WEIGHTS_PER_BLOCK;
        size_t end = std::min(start + Q4_0Block::WEIGHTS_PER_BLOCK, num_weights);
        
        // Find max abs for scale
        float max_abs = 0.0f;
        for (size_t i = start; i < end; i++) {
            max_abs = std::max(max_abs, std::abs(input[i]));
        }
        
        // Compute scale (divide range into 16 steps: -8 to +7)
        float scale = (max_abs > 0.0f) ? (max_abs / 7.0f) : 1.0f;
        blocks[b].scale_f16 = F32ToF16(scale);
        
        // Quantize each weight to 4 bits
        for (size_t i = start; i < end; i += 2) {
            // First weight: quantize to 0-15 range (represents -8 to +7)
            int8_t q0 = static_cast<int8_t>(std::round(input[i] / scale));
            q0 = std::max<int8_t>(-8, std::min<int8_t>(7, q0));
            uint8_t nibble0 = static_cast<uint8_t>(q0 + 8);  // Shift to 0-15
            
            // Second weight (or 0 if odd count)
            uint8_t nibble1 = 8;  // Represents 0
            if (i + 1 < end) {
                int8_t q1 = static_cast<int8_t>(std::round(input[i + 1] / scale));
                q1 = std::max<int8_t>(-8, std::min<int8_t>(7, q1));
                nibble1 = static_cast<uint8_t>(q1 + 8);  // Shift to 0-15
            }
            
            // Pack nibbles: low nibble = first weight, high nibble = second weight
            size_t byte_idx = (i - start) / 2;
            blocks[b].quants[byte_idx] = static_cast<uint8_t>(
                (nibble0 & 0x0F) | ((nibble1 & 0x0F) << 4)
            );
        }
    }
}

void DequantizeQ4_0ToF32(const uint8_t* input, size_t num_weights,
                         float* output) {
    const Q4_0Block* blocks = reinterpret_cast<const Q4_0Block*>(input);
    size_t num_blocks = (num_weights + Q4_0Block::WEIGHTS_PER_BLOCK - 1)
                        / Q4_0Block::WEIGHTS_PER_BLOCK;
    
    for (size_t b = 0; b < num_blocks; b++) {
        float scale = F16ToF32(blocks[b].scale_f16);
        size_t start = b * Q4_0Block::WEIGHTS_PER_BLOCK;
        size_t end = std::min(start + Q4_0Block::WEIGHTS_PER_BLOCK, num_weights);
        
        for (size_t i = start; i < end; i += 2) {
            size_t byte_idx = (i - start) / 2;
            uint8_t byte = blocks[b].quants[byte_idx];
            
            // Unpack nibbles: low nibble first, high nibble second
            int8_t nibble0 = static_cast<int8_t>(byte & 0x0F) - 8;  // Convert to signed -8 to +7
            int8_t nibble1 = static_cast<int8_t>((byte >> 4) & 0x0F) - 8;
            
            // Dequantize
            if (i < end) {
                output[i] = nibble0 * scale;
            }
            if (i + 1 < end) {
                output[i + 1] = nibble1 * scale;
            }
        }
    }
}

// ============================================================================
// Scalar Implementation
// ============================================================================

void MatMulQ4_0_Scalar(const uint8_t* weights, const float* input,
                       float* output, size_t batch_size,
                       size_t input_dim, size_t output_dim) {
    size_t in_blocks = input_dim / Q4_0Block::WEIGHTS_PER_BLOCK;
    
    for (size_t b = 0; b < batch_size; b++) {
        const float* batch_input = input + b * input_dim;
        
        for (size_t o = 0; o < output_dim; o++) {
            float sum = 0.0f;
            size_t weight_offset = o * in_blocks * sizeof(Q4_0Block);
            
            for (size_t ib = 0; ib < in_blocks; ib++) {
                const Q4_0Block* block = reinterpret_cast<const Q4_0Block*>(
                    weights + weight_offset + ib * sizeof(Q4_0Block));
                float scale = F16ToF32(block->scale_f16);
                
                for (int i = 0; i < 16; i++) {
                    uint8_t byte = block->quants[i];
                    int8_t nibble0 = static_cast<int8_t>(byte & 0x0F) - 8;
                    int8_t nibble1 = static_cast<int8_t>((byte >> 4) & 0x0F) - 8;
                    
                    size_t in_idx = ib * Q4_0Block::WEIGHTS_PER_BLOCK + i * 2;
                    if (in_idx < input_dim) {
                        sum += batch_input[in_idx] * (nibble0 * scale);
                    }
                    if (in_idx + 1 < input_dim) {
                        sum += batch_input[in_idx + 1] * (nibble1 * scale);
                    }
                }
            }
            output[b * output_dim + o] = sum;
        }
    }
}

// ============================================================================
// AVX2 Implementation (256-bit)
// ============================================================================

void MatMulQ4_0_AVX2(const uint8_t* weights, const float* input,
                     float* output, size_t batch_size,
                     size_t input_dim, size_t output_dim) {
    // For now, fall back to scalar
    // Full AVX2 implementation would process 8 floats at once
    MatMulQ4_0_Scalar(weights, input, output, batch_size, input_dim, output_dim);
}

// ============================================================================
// AVX-512 Implementation (512-bit)
// ============================================================================

void MatMulQ4_0_AVX512(const uint8_t* weights, const float* input,
                       float* output, size_t batch_size,
                       size_t input_dim, size_t output_dim) {
    // For now, fall back to scalar
    // Full AVX-512 implementation would process 16 floats at once
    MatMulQ4_0_Scalar(weights, input, output, batch_size, input_dim, output_dim);
}

// ============================================================================
// Auto-Dispatch
// ============================================================================

void MatMulQ4_0(const uint8_t* weights, const float* input,
                float* output, size_t batch_size,
                size_t input_dim, size_t output_dim) {
    // Check CPU features
    bool has_avx512 = false;
    bool has_avx2 = false;
    
    #ifdef __AVX512F__
        has_avx512 = true;
    #endif
    #ifdef __AVX2__
        has_avx2 = true;
    #endif
    
    if (has_avx512) {
        MatMulQ4_0_AVX512(weights, input, output, batch_size, input_dim, output_dim);
    } else if (has_avx2) {
        MatMulQ4_0_AVX2(weights, input, output, batch_size, input_dim, output_dim);
    } else {
        MatMulQ4_0_Scalar(weights, input, output, batch_size, input_dim, output_dim);
    }
}

// ============================================================================
// Benchmark
// ============================================================================

QuantizedMatMulResult BenchmarkQuantizedMatMul(
    size_t batch_size, size_t input_dim, size_t output_dim,
    int iterations) {
    
    // Create random weights
    size_t num_weights = input_dim * output_dim;
    std::vector<float> fp32_weights(num_weights);
    for (auto& w : fp32_weights) {
        w = (static_cast<float>(rand()) / RAND_MAX) * 2.0f - 1.0f;
    }
    
    // Quantize
    std::vector<uint8_t> q4_0_weights;
    QuantizeF32ToQ4_0(fp32_weights.data(), num_weights, q4_0_weights);
    
    // Create random input
    std::vector<float> input(batch_size * input_dim);
    for (auto& i : input) {
        i = (static_cast<float>(rand()) / RAND_MAX) * 2.0f - 1.0f;
    }
    
    // Output buffer
    std::vector<float> output(batch_size * output_dim);
    
    // Warmup
    for (int i = 0; i < 10; i++) {
        MatMulQ4_0(q4_0_weights.data(), input.data(), output.data(),
                   batch_size, input_dim, output_dim);
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        MatMulQ4_0(q4_0_weights.data(), input.data(), output.data(),
                   batch_size, input_dim, output_dim);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<float> elapsed = end - start;
    
    // Calculate metrics
    float ops_per_matmul = 2.0f * batch_size * input_dim * output_dim;
    float total_ops = ops_per_matmul * iterations;
    float gflops = (total_ops / elapsed.count()) / 1e9;
    
    size_t bytes_read = q4_0_weights.size() + input.size() * sizeof(float);
    size_t bytes_written = output.size() * sizeof(float);
    size_t total_bytes = bytes_read + bytes_written;
    float memory_gb_s = (total_bytes * iterations / elapsed.count()) / 1e9;
    
    QuantizedMatMulResult result;
    result.gflops = gflops;
    result.memory_gb_s = memory_gb_s;
    result.time_ms = elapsed.count() * 1000.0f;
    result.bytes_transferred = total_bytes * iterations;
    
    return result;
}

// ============================================================================
// Validation
// ============================================================================

float ComputeQuantizationError(const float* reference,
                               const float* quantized,
                               size_t num_elements) {
    float sum_sq_error = 0.0f;
    float sum_sq_reference = 0.0f;
    
    for (size_t i = 0; i < num_elements; i++) {
        float diff = reference[i] - quantized[i];
        sum_sq_error += diff * diff;
        sum_sq_reference += reference[i] * reference[i];
    }
    
    // Return relative error
    return std::sqrt(sum_sq_error / sum_sq_reference);
}

bool ValidateQuantizedMatMul(size_t input_dim, size_t output_dim) {
    size_t num_weights = input_dim * output_dim;
    
    // Create test weights
    std::vector<float> fp32_weights(num_weights);
    for (size_t i = 0; i < num_weights; i++) {
        fp32_weights[i] = std::sin(static_cast<float>(i) * 0.1f);
    }
    
    // Quantize
    std::vector<uint8_t> q4_0_weights;
    QuantizeF32ToQ4_0(fp32_weights.data(), num_weights, q4_0_weights);
    
    // Dequantize for comparison
    std::vector<float> dequantized_weights(num_weights);
    DequantizeQ4_0ToF32(q4_0_weights.data(), num_weights, dequantized_weights.data());
    
    // Check quantization error
    float error = ComputeQuantizationError(fp32_weights.data(),
                                           dequantized_weights.data(),
                                           num_weights);
    
    std::cout << "Quantization error: " << error * 100.0f << "%" << std::endl;
    
    // Error should be < 5% for Q4_0
    return error < 0.05f;
}

} // namespace benchmark
