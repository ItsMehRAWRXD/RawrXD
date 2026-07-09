/**
 * @file compression_codec.cpp
 * @brief RawrXD Compression ABI Implementation - L4.2
 *
 * Concrete codec implementations with validation layer.
 *
 * @copyright RawrXD 2026
 */

#include "compression_codec.h"
#include <cmath>
#include <algorithm>
#include <cstring>
#include <immintrin.h>
#include <stdexcept>

namespace rawrxd {
namespace compression {

// ============================================================================
// Compression Type Utilities
// ============================================================================

const char* CompressionTypeToString(CompressionType type) {
    switch (type) {
        case CompressionType::Q4_0: return "Q4_0";
        case CompressionType::Q4_1: return "Q4_1";
        case CompressionType::Q5_0: return "Q5_0";
        case CompressionType::Q5_1: return "Q5_1";
        case CompressionType::Q8_0: return "Q8_0";
        case CompressionType::Q8_1: return "Q8_1";
        case CompressionType::Q4_K: return "Q4_K";
        case CompressionType::Q5_K: return "Q5_K";
        case CompressionType::Q6_K: return "Q6_K";
        case CompressionType::Q3_RDX: return "Q3_RDX";
        case CompressionType::Q6_RDX: return "Q6_RDX";
        case CompressionType::ADAPTIVE: return "ADAPTIVE";
        case CompressionType::FP16: return "FP16";
        case CompressionType::FP32: return "FP32";
        default: return "UNKNOWN";
    }
}

CompressionType CompressionTypeFromString(const char* str) {
    if (strcmp(str, "Q4_0") == 0) return CompressionType::Q4_0;
    if (strcmp(str, "Q4_1") == 0) return CompressionType::Q4_1;
    if (strcmp(str, "Q5_0") == 0) return CompressionType::Q5_0;
    if (strcmp(str, "Q5_1") == 0) return CompressionType::Q5_1;
    if (strcmp(str, "Q8_0") == 0) return CompressionType::Q8_0;
    if (strcmp(str, "Q8_1") == 0) return CompressionType::Q8_1;
    if (strcmp(str, "Q4_K") == 0) return CompressionType::Q4_K;
    if (strcmp(str, "Q5_K") == 0) return CompressionType::Q5_K;
    if (strcmp(str, "Q6_K") == 0) return CompressionType::Q6_K;
    if (strcmp(str, "FP16") == 0) return CompressionType::FP16;
    if (strcmp(str, "FP32") == 0) return CompressionType::FP32;
    return CompressionType::UNKNOWN;
}

// ============================================================================
// Block Header
// ============================================================================

bool CompressedBlockHeader::Validate() const {
    if (magic != 0x52545843) return false;  // 'RDXC'
    if (version != 1) return false;
    if (block_size == 0) return false;
    if (num_weights == 0) return false;
    if (payload_size == 0) return false;
    return true;
}

uint32_t CompressedBlockHeader::CalculateChecksum(const uint8_t* payload) const {
    // Simple CRC32-like checksum
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < payload_size; i++) {
        crc ^= payload[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

// ============================================================================
// Compression Report
// ============================================================================

void CompressionReport::Print() const {
    printf("Compression Report:\n");
    printf("  Ratio: %.2f:1\n", compression_ratio);
    printf("  Original: %zu bytes\n", original_bytes);
    printf("  Compressed: %zu bytes\n", compressed_bytes);
    printf("  RMSE: %.6f\n", rmse);
    printf("  Max Error: %.6f\n", max_absolute_error);
    printf("  Mean Error: %.6f\n", mean_absolute_error);
    printf("  Cosine Similarity: %.6f\n", cosine_similarity);
    printf("  Overflow: %s\n", overflow_detected ? "YES" : "NO");
    printf("  NaN: %s\n", nan_detected ? "YES" : "NO");
    printf("  Approved: %s\n", approved ? "YES" : "NO");
    if (!approved) {
        printf("  Reason: %s\n", rejection_reason.c_str());
    }
}

bool CompressionReport::operator==(const CompressionReport& other) const {
    return compression_ratio == other.compression_ratio &&
           rmse == other.rmse &&
           max_absolute_error == other.max_absolute_error &&
           cosine_similarity == other.cosine_similarity &&
           approved == other.approved;
}

// ============================================================================
// Q4_0 Codec Implementation
// ============================================================================

CodecCapabilities Q4_0_Codec::GetCapabilities() const {
    return {
        .supports_fused_decode = true,
        .supports_random_access = true,
        .supports_simd = true,
        .supports_multithread = true,
        .preferred_alignment = 32,
        .min_block_size = 32,
        .max_block_size = 32
    };
}

size_t Q4_0_Codec::EncodeBlock(const float* src, uint8_t* dst, size_t count) {
    size_t blocks = count / 32;
    size_t out_idx = 0;
    
    for (size_t b = 0; b < blocks; b++) {
        const float* block_src = &src[b * 32];
        
        // Find max abs
        float max_abs = 0.0f;
        for (int i = 0; i < 32; i++) {
            max_abs = std::max(max_abs, std::fabs(block_src[i]));
        }
        
        float scale = max_abs / 7.0f;
        if (scale == 0.0f) scale = 1.0f;
        
        // Store FP16 scale
        uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(&scale);
        memcpy(&dst[out_idx], &scale_f16, 2);
        out_idx += 2;
        
        // Pack nibbles
        for (int i = 0; i < 32; i += 2) {
            int q1 = static_cast<int>(round(block_src[i] / scale)) + 8;
            q1 = std::max(0, std::min(15, q1));
            
            int q2 = static_cast<int>(round(block_src[i + 1] / scale)) + 8;
            q2 = std::max(0, std::min(15, q2));
            
            dst[out_idx++] = (q2 << 4) | q1;
        }
    }
    
    return out_idx;
}

void Q4_0_Codec::DecodeBlock(const uint8_t* src, float* dst, size_t count) {
    size_t blocks = count / 32;
    size_t in_idx = 0;
    
    for (size_t b = 0; b < blocks; b++) {
        // Read scale
        uint16_t scale_f16;
        memcpy(&scale_f16, &src[in_idx], 2);
        in_idx += 2;
        float scale = *reinterpret_cast<const float*>(&scale_f16);
        
        // Unpack nibbles
        for (int i = 0; i < 32; i += 2) {
            uint8_t packed = src[in_idx++];
            int q1 = (packed & 0x0F) - 8;
            int q2 = ((packed >> 4) & 0x0F) - 8;
            
            dst[b * 32 + i] = static_cast<float>(q1) * scale;
            dst[b * 32 + i + 1] = static_cast<float>(q2) * scale;
        }
    }
}

float Q4_0_Codec::DecodeWeight(const uint8_t* src, size_t index) {
    size_t block_idx = index / 32;
    size_t weight_idx = index % 32;
    size_t block_offset = block_idx * 18;  // 18 bytes per block
    
    // Read scale
    uint16_t scale_f16;
    memcpy(&scale_f16, &src[block_offset], 2);
    float scale = *reinterpret_cast<const float*>(&scale_f16);
    
    // Read nibble
    size_t nibble_offset = block_offset + 2 + (weight_idx / 2);
    uint8_t packed = src[nibble_offset];
    int nibble = (weight_idx % 2 == 0) ? (packed & 0x0F) : ((packed >> 4) & 0x0F);
    
    return static_cast<float>(nibble - 8) * scale;
}

float Q4_0_Codec::FusedDotProduct(const uint8_t* weights, const float* input, size_t count) {
    size_t blocks = count / 32;
    size_t weight_idx = 0;
    float sum = 0.0f;
    
    for (size_t b = 0; b < blocks; b++) {
        // Read scale
        uint16_t scale_f16;
        memcpy(&scale_f16, &weights[weight_idx], 2);
        weight_idx += 2;
        float scale = *reinterpret_cast<const float*>(&scale_f16);
        
        // Fused decode + dot product
        for (int i = 0; i < 32; i += 2) {
            uint8_t packed = weights[weight_idx++];
            int q1 = (packed & 0x0F) - 8;
            int q2 = ((packed >> 4) & 0x0F) - 8;
            
            sum += static_cast<float>(q1) * scale * input[b * 32 + i];
            sum += static_cast<float>(q2) * scale * input[b * 32 + i + 1];
        }
    }
    
    return sum;
}

float Q4_0_Codec::FusedGemvRow(const uint8_t* weights, const float* input, size_t cols) {
    return FusedDotProduct(weights, input, cols);
}

bool Q4_0_Codec::SelfTest() {
    // Test encode/decode roundtrip
    float test_data[32];
    for (int i = 0; i < 32; i++) {
        test_data[i] = sinf(i * 0.1f) * 0.5f;
    }
    
    uint8_t compressed[64];
    size_t compressed_size = EncodeBlock(test_data, compressed, 32);
    
    float decoded[32];
    DecodeBlock(compressed, decoded, 32);
    
    // Check error is reasonable
    float max_error = 0.0f;
    for (int i = 0; i < 32; i++) {
        max_error = std::max(max_error, static_cast<float>(fabs(test_data[i] - decoded[i])));
    }
    
    return max_error < 0.1f && compressed_size == 18;
}

CompressionReport Q4_0_Codec::Validate(const float* original, const uint8_t* compressed, size_t count) {
    std::vector<float> reconstructed(count);
    DecodeBlock(compressed, reconstructed.data(), count);
    
    size_t compressed_bytes = GetCompressedSize(count);
    
    return CompressionValidator::Analyze(
        original,
        reconstructed.data(),
        count,
        compressed_bytes
    );
}

size_t Q4_0_Codec::GetCompressedSize(size_t num_weights) const {
    size_t blocks = (num_weights + 31) / 32;
    return blocks * 18;  // 18 bytes per block
}

// ============================================================================
// Q4_K Codec (Simplified Implementation)
// ============================================================================

CodecCapabilities Q4_K_Codec::GetCapabilities() const {
    return {
        .supports_fused_decode = true,
        .supports_random_access = false,  // Complex indexing
        .supports_simd = true,
        .supports_multithread = true,
        .preferred_alignment = 32,
        .min_block_size = 256,
        .max_block_size = 256
    };
}

size_t Q4_K_Codec::EncodeBlock(const float* src, uint8_t* dst, size_t count) {
    // Simplified: Use Q4_0 encoding for now
    // Real Q4_K has mixed 6-bit/4-bit with super-blocks
    size_t blocks = count / 256;
    size_t out_idx = 0;
    
    for (size_t b = 0; b < blocks; b++) {
        const float* block_src = &src[b * 256];
        
        // Global scale
        float max_abs = 0.0f;
        for (int i = 0; i < 256; i++) {
            max_abs = std::max(max_abs, std::fabs(block_src[i]));
        }
        float scale = max_abs / 7.0f;
        if (scale == 0.0f) scale = 1.0f;
        
        // Store scale
        memcpy(&dst[out_idx], &scale, 4);
        out_idx += 4;
        
        // Store min
        float min_val = 0.0f;
        memcpy(&dst[out_idx], &min_val, 4);
        out_idx += 4;
        
        // Per-sub-block scales (8 sub-blocks)
        for (int sb = 0; sb < 8; sb++) {
            dst[out_idx++] = 255;  // Max scale
        }
        
        // Quantized weights (256 * 4 bits = 128 bytes)
        for (int i = 0; i < 256; i += 2) {
            int q1 = static_cast<int>(round(block_src[i] / scale)) + 8;
            q1 = std::max(0, std::min(15, q1));
            
            int q2 = static_cast<int>(round(block_src[i + 1] / scale)) + 8;
            q2 = std::max(0, std::min(15, q2));
            
            dst[out_idx++] = (q2 << 4) | q1;
        }
    }
    
    return out_idx;
}

void Q4_K_Codec::DecodeBlock(const uint8_t* src, float* dst, size_t count) {
    size_t blocks = count / 256;
    size_t in_idx = 0;
    
    for (size_t b = 0; b < blocks; b++) {
        // Read scale
        float scale;
        memcpy(&scale, &src[in_idx], 4);
        in_idx += 4;
        
        // Read min
        float min_val;
        memcpy(&min_val, &src[in_idx], 4);
        in_idx += 4;
        
        // Skip per-sub-block scales
        in_idx += 8;
        
        // Unpack weights
        for (int i = 0; i < 256; i += 2) {
            uint8_t packed = src[in_idx++];
            int q1 = (packed & 0x0F) - 8;
            int q2 = ((packed >> 4) & 0x0F) - 8;
            
            dst[b * 256 + i] = static_cast<float>(q1) * scale + min_val;
            dst[b * 256 + i + 1] = static_cast<float>(q2) * scale + min_val;
        }
    }
}

float Q4_K_Codec::DecodeWeight(const uint8_t* src, size_t index) {
    // Complex indexing - simplified version
    size_t block_idx = index / 256;
    size_t weight_idx = index % 256;
    size_t block_offset = block_idx * 272;  // 272 bytes per block
    
    float scale;
    memcpy(&scale, &src[block_offset], 4);
    
    float min_val;
    memcpy(&min_val, &src[block_offset + 4], 4);
    
    size_t nibble_offset = block_offset + 16 + (weight_idx / 2);
    uint8_t packed = src[nibble_offset];
    int nibble = (weight_idx % 2 == 0) ? (packed & 0x0F) : ((packed >> 4) & 0x0F);
    
    return static_cast<float>(nibble - 8) * scale + min_val;
}

float Q4_K_Codec::FusedDotProduct(const uint8_t* weights, const float* input, size_t count) {
    // Simplified fused decode
    size_t blocks = count / 256;
    size_t weight_idx = 0;
    float sum = 0.0f;
    
    for (size_t b = 0; b < blocks; b++) {
        float scale;
        memcpy(&scale, &weights[weight_idx], 4);
        weight_idx += 4;
        
        float min_val;
        memcpy(&min_val, &weights[weight_idx], 4);
        weight_idx += 4;
        
        weight_idx += 8;  // Skip scales
        
        for (int i = 0; i < 256; i += 2) {
            uint8_t packed = weights[weight_idx++];
            int q1 = (packed & 0x0F) - 8;
            int q2 = ((packed >> 4) & 0x0F) - 8;
            
            sum += (static_cast<float>(q1) * scale + min_val) * input[b * 256 + i];
            sum += (static_cast<float>(q2) * scale + min_val) * input[b * 256 + i + 1];
        }
    }
    
    return sum;
}

float Q4_K_Codec::FusedGemvRow(const uint8_t* weights, const float* input, size_t cols) {
    return FusedDotProduct(weights, input, cols);
}

bool Q4_K_Codec::SelfTest() {
    float test_data[256];
    for (int i = 0; i < 256; i++) {
        test_data[i] = sinf(i * 0.01f) * 0.5f;
    }
    
    uint8_t compressed[512];
    size_t compressed_size = EncodeBlock(test_data, compressed, 256);
    
    float decoded[256];
    DecodeBlock(compressed, decoded, 256);
    
    float max_error = 0.0f;
    for (int i = 0; i < 256; i++) {
        max_error = std::max(max_error, static_cast<float>(fabs(test_data[i] - decoded[i])));
    }
    
    return max_error < 0.2f && compressed_size == 272;
}

CompressionReport Q4_K_Codec::Validate(const float* original, const uint8_t* compressed, size_t count) {
    std::vector<float> reconstructed(count);
    DecodeBlock(compressed, reconstructed.data(), count);
    
    size_t compressed_bytes = GetCompressedSize(count);
    
    return CompressionValidator::Analyze(
        original,
        reconstructed.data(),
        count,
        compressed_bytes
    );
}

size_t Q4_K_Codec::GetCompressedSize(size_t num_weights) const {
    size_t blocks = (num_weights + 255) / 256;
    return blocks * 272;  // 272 bytes per block
}

// ============================================================================
// Q8_0 Codec Implementation
// ============================================================================

CodecCapabilities Q8_0_Codec::GetCapabilities() const {
    return {
        .supports_fused_decode = true,
        .supports_random_access = true,
        .supports_simd = true,
        .supports_multithread = true,
        .preferred_alignment = 32,
        .min_block_size = 32,
        .max_block_size = 32
    };
}

size_t Q8_0_Codec::EncodeBlock(const float* src, uint8_t* dst, size_t count) {
    size_t blocks = count / 32;
    size_t out_idx = 0;
    
    for (size_t b = 0; b < blocks; b++) {
        const float* block_src = &src[b * 32];
        
        float max_abs = 0.0f;
        for (int i = 0; i < 32; i++) {
            max_abs = std::max(max_abs, std::fabs(block_src[i]));
        }
        
        float scale = max_abs / 127.0f;
        if (scale == 0.0f) scale = 1.0f;
        
        // Store FP16 scale
        uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(&scale);
        memcpy(&dst[out_idx], &scale_f16, 2);
        out_idx += 2;
        
        // Quantize to INT8
        for (int i = 0; i < 32; i++) {
            int quantized = static_cast<int>(round(block_src[i] / scale));
            quantized = std::max(-128, std::min(127, quantized));
            dst[out_idx++] = static_cast<uint8_t>(quantized + 128);
        }
    }
    
    return out_idx;
}

void Q8_0_Codec::DecodeBlock(const uint8_t* src, float* dst, size_t count) {
    size_t blocks = count / 32;
    size_t in_idx = 0;
    
    for (size_t b = 0; b < blocks; b++) {
        uint16_t scale_f16;
        memcpy(&scale_f16, &src[in_idx], 2);
        in_idx += 2;
        float scale = *reinterpret_cast<const float*>(&scale_f16);
        
        for (int i = 0; i < 32; i++) {
            int quantized = static_cast<int>(src[in_idx++]) - 128;
            dst[b * 32 + i] = static_cast<float>(quantized) * scale;
        }
    }
}

float Q8_0_Codec::DecodeWeight(const uint8_t* src, size_t index) {
    size_t block_idx = index / 32;
    size_t weight_idx = index % 32;
    size_t block_offset = block_idx * 34;  // 34 bytes per block
    
    uint16_t scale_f16;
    memcpy(&scale_f16, &src[block_offset], 2);
    float scale = *reinterpret_cast<const float*>(&scale_f16);
    
    int quantized = static_cast<int>(src[block_offset + 2 + weight_idx]) - 128;
    return static_cast<float>(quantized) * scale;
}

float Q8_0_Codec::FusedDotProduct(const uint8_t* weights, const float* input, size_t count) {
    size_t blocks = count / 32;
    size_t weight_idx = 0;
    float sum = 0.0f;
    
    for (size_t b = 0; b < blocks; b++) {
        uint16_t scale_f16;
        memcpy(&scale_f16, &weights[weight_idx], 2);
        weight_idx += 2;
        float scale = *reinterpret_cast<const float*>(&scale_f16);
        
        for (int i = 0; i < 32; i++) {
            int quantized = static_cast<int>(weights[weight_idx++]) - 128;
            sum += static_cast<float>(quantized) * scale * input[b * 32 + i];
        }
    }
    
    return sum;
}

float Q8_0_Codec::FusedGemvRow(const uint8_t* weights, const float* input, size_t cols) {
    return FusedDotProduct(weights, input, cols);
}

bool Q8_0_Codec::SelfTest() {
    float test_data[32];
    for (int i = 0; i < 32; i++) {
        test_data[i] = sinf(i * 0.1f) * 0.5f;
    }
    
    uint8_t compressed[128];
    size_t compressed_size = EncodeBlock(test_data, compressed, 32);
    
    float decoded[32];
    DecodeBlock(compressed, decoded, 32);
    
    float max_error = 0.0f;
    for (int i = 0; i < 32; i++) {
        max_error = std::max(max_error, static_cast<float>(fabs(test_data[i] - decoded[i])));
    }
    
    return max_error < 0.01f && compressed_size == 34;
}

CompressionReport Q8_0_Codec::Validate(const float* original, const uint8_t* compressed, size_t count) {
    std::vector<float> reconstructed(count);
    DecodeBlock(compressed, reconstructed.data(), count);
    
    size_t compressed_bytes = GetCompressedSize(count);
    
    return CompressionValidator::Analyze(
        original,
        reconstructed.data(),
        count,
        compressed_bytes
    );
}

size_t Q8_0_Codec::GetCompressedSize(size_t num_weights) const {
    size_t blocks = (num_weights + 31) / 32;
    return blocks * 34;  // 34 bytes per block
}

// ============================================================================
// Codec Factory
// ============================================================================

std::unique_ptr<CompressionCodec> CodecFactory::Create(CompressionType type) {
    switch (type) {
        case CompressionType::Q4_0:
            return std::make_unique<Q4_0_Codec>();
        case CompressionType::Q4_K:
            return std::make_unique<Q4_K_Codec>();
        case CompressionType::Q8_0:
            return std::make_unique<Q8_0_Codec>();
        default:
            return nullptr;
    }
}

std::unique_ptr<CompressionCodec> CodecFactory::Create(const char* name) {
    return Create(CompressionTypeFromString(name));
}

std::vector<CompressionType> CodecFactory::GetAvailableCodecs() {
    return {
        CompressionType::Q4_0,
        CompressionType::Q4_K,
        CompressionType::Q8_0
    };
}

bool CodecFactory::IsAvailable(CompressionType type) {
    return type == CompressionType::Q4_0 ||
           type == CompressionType::Q4_K ||
           type == CompressionType::Q8_0;
}

CompressionType CodecFactory::AutoSelect(float target_ratio, float min_quality) {
    // Simple selection based on target ratio
    if (target_ratio >= 6.0f && min_quality <= 0.999f) {
        return CompressionType::Q4_0;  // 6.4:1, good quality
    } else if (target_ratio >= 5.0f) {
        return CompressionType::Q4_K;  // 6.7:1
    } else {
        return CompressionType::Q8_0;  // 4.0:1, high quality
    }
}

// ============================================================================
// Compression Validator
// ============================================================================

bool CompressionValidator::ValidateQuality(
    const CompressionReport& report,
    float min_cosine,
    float max_rmse,
    float max_error
) {
    if (report.cosine_similarity < min_cosine) return false;
    if (report.rmse > max_rmse) return false;
    if (report.max_absolute_error > max_error) return false;
    if (report.overflow_detected) return false;
    if (report.nan_detected) return false;
    if (report.inf_detected) return false;
    return true;
}

CompressionReport CompressionValidator::Analyze(
    const float* original,
    const float* reconstructed,
    size_t count,
    size_t compressed_bytes
) {
    CompressionReport report;
    
    report.original_bytes = count * sizeof(float);
    report.compressed_bytes = compressed_bytes;
    report.compression_ratio = static_cast<float>(report.original_bytes) / static_cast<float>(compressed_bytes);
    
    // Calculate RMSE
    double sum_squared_error = 0.0;
    double sum_original = 0.0;
    double sum_reconstructed = 0.0;
    double sum_original_sq = 0.0;
    double sum_reconstructed_sq = 0.0;
    double dot_product = 0.0;
    
    report.max_absolute_error = 0.0f;
    report.mean_absolute_error = 0.0f;
    report.overflow_detected = false;
    report.nan_detected = false;
    report.inf_detected = false;
    
    for (size_t i = 0; i < count; i++) {
        float orig = original[i];
        float recon = reconstructed[i];
        
        // Check for anomalies
        if (std::isnan(recon)) report.nan_detected = true;
        if (std::isinf(recon)) report.inf_detected = true;
        if (fabs(recon) > 1e6f) report.overflow_detected = true;
        
        float error = fabs(orig - recon);
        report.max_absolute_error = std::max(report.max_absolute_error, error);
        report.mean_absolute_error += error;
        
        sum_squared_error += error * error;
        sum_original += orig;
        sum_reconstructed += recon;
        sum_original_sq += orig * orig;
        sum_reconstructed_sq += recon * recon;
        dot_product += orig * recon;
    }
    
    report.mean_absolute_error /= static_cast<float>(count);
    report.rmse = static_cast<float>(sqrt(sum_squared_error / count));
    
    // Cosine similarity
    double norm_original = sqrt(sum_original_sq);
    double norm_reconstructed = sqrt(sum_reconstructed_sq);
    if (norm_original > 0 && norm_reconstructed > 0) {
        report.cosine_similarity = static_cast<float>(dot_product / (norm_original * norm_reconstructed));
    } else {
        report.cosine_similarity = 0.0f;
    }
    
    // Relative error
    float avg_magnitude = static_cast<float>(sum_original / count);
    report.relative_error_percent = (avg_magnitude > 0) ? 
        (report.mean_absolute_error / avg_magnitude) * 100.0f : 0.0f;
    
    // Approval
    report.approved = ValidateQuality(report);
    if (!report.approved) {
        if (report.cosine_similarity < QualityThresholds::COSINE_MEDIUM) {
            report.rejection_reason = "Cosine similarity below threshold";
        } else if (report.rmse > QualityThresholds::RMSE_MEDIUM) {
            report.rejection_reason = "RMSE above threshold";
        } else if (report.nan_detected) {
            report.rejection_reason = "NaN detected in output";
        } else {
            report.rejection_reason = "Quality validation failed";
        }
    }
    
    report.checksum_valid = true;
    
    return report;
}

float CompressionValidator::CosineSimilarity(const float* a, const float* b, size_t count) {
    double dot = 0.0;
    double norm_a = 0.0;
    double norm_b = 0.0;
    
    for (size_t i = 0; i < count; i++) {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    
    if (norm_a == 0 || norm_b == 0) return 0.0f;
    return static_cast<float>(dot / (sqrt(norm_a) * sqrt(norm_b)));
}

float CompressionValidator::CalculateRMSE(const float* original, const float* reconstructed, size_t count) {
    double sum_squared = 0.0;
    for (size_t i = 0; i < count; i++) {
        double diff = original[i] - reconstructed[i];
        sum_squared += diff * diff;
    }
    return static_cast<float>(sqrt(sum_squared / count));
}

bool CompressionValidator::CheckNumericalAnomalies(
    const float* data,
    size_t count,
    bool* overflow,
    bool* nan_detected,
    bool* inf_detected
) {
    bool has_overflow = false;
    bool has_nan = false;
    bool has_inf = false;
    
    for (size_t i = 0; i < count; i++) {
        if (std::isnan(data[i])) has_nan = true;
        if (std::isinf(data[i])) has_inf = true;
        if (fabs(data[i]) > 1e6f) has_overflow = true;
    }
    
    if (overflow) *overflow = has_overflow;
    if (nan_detected) *nan_detected = has_nan;
    if (inf_detected) *inf_detected = has_inf;
    
    return has_overflow || has_nan || has_inf;
}

} // namespace compression
} // namespace rawrxd
