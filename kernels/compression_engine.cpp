/**
 * @file compression_engine.cpp
 * @brief RawrXD Tunable Compression Engine Implementation
 *
 * Statically linked compression with runtime tune selection.
 * Like swapping pistons without rebuilding the motor.
 *
 * @copyright RawrXD 2026
 */

#include "compression_engine.h"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <immintrin.h>
#include <thread>
#include <vector>

namespace rawrxd {
namespace compression {

// ============================================================================
// Static Dispatch Functions (The "Cam Profiles")
// ============================================================================

// Street NA: INT8 compression
static size_t CompressStreetNA(const float* input, uint8_t* output, size_t num_weights,
                                const CompressionConfig& config) {
    size_t blocks = (num_weights + config.block_size - 1) / config.block_size;
    size_t out_idx = 0;
    
    for (size_t b = 0; b < blocks; b++) {
        size_t start = b * config.block_size;
        size_t end = std::min(start + config.block_size, num_weights);
        
        // Find scale
        float max_abs = 0.0f;
        for (size_t i = start; i < end; i++) {
            max_abs = std::max(max_abs, std::fabs(input[i]));
        }
        float scale = max_abs / 127.0f;
        if (scale == 0.0f) scale = 1.0f;
        
        // Store scale (FP16)
        uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(&scale);
        output[out_idx++] = scale_f16 & 0xFF;
        output[out_idx++] = (scale_f16 >> 8) & 0xFF;
        
        // Quantize to INT8
        for (size_t i = start; i < end; i++) {
            int quantized = static_cast<int>(round(input[i] / scale));
            quantized = std::max(-128, std::min(127, quantized));
            output[out_idx++] = static_cast<uint8_t>(quantized + 128);
        }
    }
    
    return out_idx;
}

// Strong NA: Q8_0 compression
static size_t CompressStrongNA(const float* input, uint8_t* output, size_t num_weights,
                                const CompressionConfig& config) {
    size_t blocks = num_weights / config.block_size;
    size_t out_idx = 0;
    
    for (size_t b = 0; b < blocks; b++) {
        const float* block_input = &input[b * config.block_size];
        
        // Find max abs
        float max_abs = 0.0f;
        for (uint32_t i = 0; i < config.block_size; i++) {
            max_abs = std::max(max_abs, std::fabs(block_input[i]));
        }
        
        float scale = max_abs / 127.0f;
        if (scale == 0.0f) scale = 1.0f;
        
        // Store FP16 scale
        uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(&scale);
        memcpy(&output[out_idx], &scale_f16, 2);
        out_idx += 2;
        
        // Quantize
        for (uint32_t i = 0; i < config.block_size; i++) {
            int quantized = static_cast<int>(round(block_input[i] / scale)) + 128;
            quantized = std::max(0, std::min(255, quantized));
            output[out_idx++] = static_cast<uint8_t>(quantized);
        }
    }
    
    return out_idx;
}

// Forced Induction: Q4_0 compression
static size_t CompressForcedInduction(const float* input, uint8_t* output, size_t num_weights,
                                       const CompressionConfig& config) {
    size_t blocks = num_weights / config.block_size;
    size_t out_idx = 0;
    
    for (size_t b = 0; b < blocks; b++) {
        const float* block_input = &input[b * config.block_size];
        
        float max_abs = 0.0f;
        for (uint32_t i = 0; i < config.block_size; i++) {
            max_abs = std::max(max_abs, std::fabs(block_input[i]));
        }
        
        float scale = max_abs / 7.0f;
        if (scale == 0.0f) scale = 1.0f;
        
        // Store FP16 scale
        uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(&scale);
        memcpy(&output[out_idx], &scale_f16, 2);
        out_idx += 2;
        
        // Pack nibbles
        for (uint32_t i = 0; i < config.block_size; i += 2) {
            int q1 = static_cast<int>(round(block_input[i] / scale)) + 8;
            q1 = std::max(0, std::min(15, q1));
            
            int q2 = static_cast<int>(round(block_input[i + 1] / scale)) + 8;
            q2 = std::max(0, std::min(15, q2));
            
            output[out_idx++] = (q2 << 4) | q1;
        }
    }
    
    return out_idx;
}

// Race Forced: Q4_K_M compression (simplified)
static size_t CompressRaceForced(const float* input, uint8_t* output, size_t num_weights,
                                  const CompressionConfig& config) {
    // Simplified: Use Q4_0 with larger blocks
    return CompressForcedInduction(input, output, num_weights, config);
}

// ============================================================================
// Static Decompression Functions
// ============================================================================

static size_t DecompressStreetNA(const uint8_t* input, float* output, size_t num_weights,
                                  const CompressionConfig& config) {
    size_t in_idx = 0;
    size_t blocks = (num_weights + config.block_size - 1) / config.block_size;
    
    for (size_t b = 0; b < blocks; b++) {
        size_t start = b * config.block_size;
        size_t end = std::min(start + config.block_size, num_weights);
        
        // Read scale
        uint16_t scale_f16 = input[in_idx] | (input[in_idx + 1] << 8);
        in_idx += 2;
        float scale = *reinterpret_cast<const float*>(&scale_f16);
        
        // Dequantize
        for (size_t i = start; i < end; i++) {
            int quantized = static_cast<int>(input[in_idx++]) - 128;
            output[i] = static_cast<float>(quantized) * scale;
        }
    }
    
    return num_weights;
}

static size_t DecompressForcedInduction(const uint8_t* input, float* output, size_t num_weights,
                                           const CompressionConfig& config) {
    size_t in_idx = 0;
    size_t blocks = num_weights / config.block_size;
    
    for (size_t b = 0; b < blocks; b++) {
        // Read scale
        uint16_t scale_f16;
        memcpy(&scale_f16, &input[in_idx], 2);
        in_idx += 2;
        float scale = *reinterpret_cast<const float*>(&scale_f16);
        
        // Dequantize nibbles
        for (uint32_t i = 0; i < config.block_size; i += 2) {
            uint8_t packed = input[in_idx++];
            int q1 = (packed & 0x0F) - 8;
            int q2 = ((packed >> 4) & 0x0F) - 8;
            
            output[b * config.block_size + i] = static_cast<float>(q1) * scale;
            output[b * config.block_size + i + 1] = static_cast<float>(q2) * scale;
        }
    }
    
    return num_weights;
}

// ============================================================================
// Static GEMV Functions (Fused Dequant + GEMM)
// ============================================================================

static void GemvStreetNA(const uint8_t* weights, const float* input, float* output,
                          int rows, int cols, const CompressionConfig& config) {
    // Scalar implementation
    for (int i = 0; i < rows; i++) {
        float sum = 0.0f;
        for (int j = 0; j < cols; j++) {
            // Simplified - would need proper block indexing
            sum += weights[i * cols + j] * input[j];
        }
        output[i] = sum;
    }
}

static void GemvForcedInduction(const uint8_t* weights, const float* input, float* output,
                                 int rows, int cols, const CompressionConfig& config) {
    int blocks_per_row = cols / config.block_size;
    size_t bytes_per_block = config.bytes_per_block;
    
    for (int i = 0; i < rows; i++) {
        __m256 sum_vec = _mm256_setzero_ps();
        const uint8_t* row_weights = &weights[i * blocks_per_row * bytes_per_block];
        
        for (int b = 0; b < blocks_per_row; b++) {
            const uint8_t* block = &row_weights[b * bytes_per_block];
            
            // Read scale
            uint16_t scale_f16;
            memcpy(&scale_f16, block, 2);
            float scale = *reinterpret_cast<const float*>(&scale_f16);
            __m256 scale_vec = _mm256_set1_ps(scale);
            
            // Decompress on-the-fly and dot product
            const float* input_slice = &input[b * config.block_size];
            
            for (uint32_t j = 0; j < config.block_size; j += 8) {
                // Load and decompress 8 weights
                float decompressed[8];
                for (int k = 0; k < 8 && (j + k) < config.block_size; k += 2) {
                    uint8_t packed = block[2 + (j + k) / 2];
                    int q1 = (packed & 0x0F) - 8;
                    int q2 = ((packed >> 4) & 0x0F) - 8;
                    decompressed[k] = static_cast<float>(q1) * scale;
                    if (k + 1 < 8) decompressed[k + 1] = static_cast<float>(q2) * scale;
                }
                
                __m256 w = _mm256_loadu_ps(decompressed);
                __m256 x = _mm256_loadu_ps(&input_slice[j]);
                sum_vec = _mm256_add_ps(sum_vec, _mm256_mul_ps(w, x));
            }
        }
        
        // Horizontal sum
        float sum_arr[8];
        _mm256_storeu_ps(sum_arr, sum_vec);
        output[i] = sum_arr[0] + sum_arr[1] + sum_arr[2] + sum_arr[3] +
                    sum_arr[4] + sum_arr[5] + sum_arr[6] + sum_arr[7];
    }
}

// ============================================================================
// CompressionEngine Implementation
// ============================================================================

CompressionEngine::CompressionEngine() : current_tune_(CompressionTune::FORCED_INDUCTION) {
    current_config_ = FORCED_INDUCTION_CONFIG;
    InitializeDispatchTables();
}

CompressionEngine::~CompressionEngine() = default;

void CompressionEngine::InitializeDispatchTables() {
    // Initialize all dispatch entries
    compress_dispatch_[static_cast<int>(CompressionTune::STREET_NA)] = CompressStreetNA;
    compress_dispatch_[static_cast<int>(CompressionTune::STRONG_NA)] = CompressStrongNA;
    compress_dispatch_[static_cast<int>(CompressionTune::RACE_NA)] = CompressStrongNA;  // Placeholder
    compress_dispatch_[static_cast<int>(CompressionTune::FORCED_INDUCTION)] = CompressForcedInduction;
    compress_dispatch_[static_cast<int>(CompressionTune::RACE_FORCED)] = CompressRaceForced;
    compress_dispatch_[static_cast<int>(CompressionTune::CUSTOM)] = CompressForcedInduction;
    
    decompress_dispatch_[static_cast<int>(CompressionTune::STREET_NA)] = DecompressStreetNA;
    decompress_dispatch_[static_cast<int>(CompressionTune::STRONG_NA)] = DecompressStreetNA;
    decompress_dispatch_[static_cast<int>(CompressionTune::RACE_NA)] = DecompressStreetNA;
    decompress_dispatch_[static_cast<int>(CompressionTune::FORCED_INDUCTION)] = DecompressForcedInduction;
    decompress_dispatch_[static_cast<int>(CompressionTune::RACE_FORCED)] = DecompressForcedInduction;
    decompress_dispatch_[static_cast<int>(CompressionTune::CUSTOM)] = DecompressForcedInduction;
    
    gemv_dispatch_[static_cast<int>(CompressionTune::STREET_NA)] = GemvStreetNA;
    gemv_dispatch_[static_cast<int>(CompressionTune::STRONG_NA)] = GemvStreetNA;
    gemv_dispatch_[static_cast<int>(CompressionTune::RACE_NA)] = GemvStreetNA;
    gemv_dispatch_[static_cast<int>(CompressionTune::FORCED_INDUCTION)] = GemvForcedInduction;
    gemv_dispatch_[static_cast<int>(CompressionTune::RACE_FORCED)] = GemvForcedInduction;
    gemv_dispatch_[static_cast<int>(CompressionTune::CUSTOM)] = GemvForcedInduction;
}

void CompressionEngine::SelectTune(CompressionTune tune) {
    current_tune_ = tune;
    switch (tune) {
        case CompressionTune::STREET_NA:
            current_config_ = STREET_NA_CONFIG;
            break;
        case CompressionTune::STRONG_NA:
            current_config_ = STRONG_NA_CONFIG;
            break;
        case CompressionTune::RACE_NA:
            current_config_ = RACE_NA_CONFIG;
            break;
        case CompressionTune::FORCED_INDUCTION:
            current_config_ = FORCED_INDUCTION_CONFIG;
            break;
        case CompressionTune::RACE_FORCED:
            current_config_ = RACE_FORCED_CONFIG;
            break;
        default:
            current_config_ = FORCED_INDUCTION_CONFIG;
            break;
    }
}

void CompressionEngine::SelectCustom(const CompressionConfig& config) {
    current_tune_ = CompressionTune::CUSTOM;
    current_config_ = config;
}

size_t CompressionEngine::Compress(const float* input, uint8_t* output, size_t num_weights) {
    int tune_idx = static_cast<int>(current_tune_);
    if (compress_dispatch_[tune_idx]) {
        return compress_dispatch_[tune_idx](input, output, num_weights, current_config_);
    }
    return 0;
}

size_t CompressionEngine::Decompress(const uint8_t* input, float* output, size_t num_weights) {
    int tune_idx = static_cast<int>(current_tune_);
    if (decompress_dispatch_[tune_idx]) {
        return decompress_dispatch_[tune_idx](input, output, num_weights, current_config_);
    }
    return 0;
}

void CompressionEngine::GemvFused(const uint8_t* weights_compressed, const float* input,
                                   float* output, int rows, int cols) {
    int tune_idx = static_cast<int>(current_tune_);
    if (gemv_dispatch_[tune_idx]) {
        gemv_dispatch_[tune_idx](weights_compressed, input, output, rows, cols, current_config_);
    }
}

float CompressionEngine::GetMemoryReduction() const {
    return 1.0f - (1.0f / current_config_.compression_ratio);
}

float CompressionEngine::GetBandwidthSavings() const {
    return GetMemoryReduction();
}

bool CompressionEngine::ValidateError(float max_error) const {
    return max_error <= current_config_.max_error_target;
}

// ============================================================================
// Singleton Instance (Statically Linked)
// ============================================================================

CompressionEngine& GetCompressionEngine() {
    static CompressionEngine instance;
    return instance;
}

// ============================================================================
// CompressionBuilder Implementation
// ============================================================================

CompressionBuilder::CompressionBuilder() {
    config_ = FORCED_INDUCTION_CONFIG;  // Default baseline
}

CompressionBuilder& CompressionBuilder::BlockSize(uint32_t size) {
    config_.block_size = size;
    return *this;
}

CompressionBuilder& CompressionBuilder::BitsPerWeight(uint32_t bits) {
    config_.bits_per_weight = bits;
    return *this;
}

CompressionBuilder& CompressionBuilder::ScaleBits(uint32_t bits) {
    config_.scale_bits = bits;
    return *this;
}

CompressionBuilder& CompressionBuilder::MinBits(uint32_t bits) {
    config_.min_bits = bits;
    return *this;
}

CompressionBuilder& CompressionBuilder::MaxError(float error) {
    config_.max_error_target = error;
    return *this;
}

CompressionBuilder& CompressionBuilder::MixedPrecision(bool enable) {
    config_.use_mixed_precision = enable;
    return *this;
}

CompressionBuilder& CompressionBuilder::SuperBlocks(bool enable) {
    config_.use_superblocks = enable;
    return *this;
}

CompressionConfig CompressionBuilder::Build() const {
    CompressionConfig result = config_;
    result.effective_bits = CalculateEffectiveBits(result);
    result.compression_ratio = CalculateCompressionRatio(result);
    result.bytes_per_block = CalculateBytesPerBlock(result);
    return result;
}

float CompressionBuilder::CalculateCompressionRatio(const CompressionConfig& config) {
    float metadata_per_weight = static_cast<float>(config.scale_bits + config.min_bits) / config.block_size;
    float total_bits = static_cast<float>(config.bits_per_weight) + metadata_per_weight;
    return 32.0f / total_bits;
}

float CompressionBuilder::CalculateEffectiveBits(const CompressionConfig& config) {
    float metadata_bits = static_cast<float>(config.scale_bits + config.min_bits);
    float metadata_per_weight = metadata_bits / config.block_size;
    return static_cast<float>(config.bits_per_weight) + metadata_per_weight;
}

size_t CompressionBuilder::CalculateBytesPerBlock(const CompressionConfig& config) {
    size_t weight_bytes = (config.block_size * config.bits_per_weight + 7) / 8;
    size_t metadata_bytes = (config.scale_bits + config.min_bits + 7) / 8;
    return weight_bytes + metadata_bytes;
}

} // namespace compression
} // namespace rawrxd
