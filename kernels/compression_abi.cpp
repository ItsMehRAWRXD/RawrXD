/**
 * @file compression_abi.cpp
 * @brief RawrXD Compression ABI Implementation
 *
 * The contract layer between storage and execution.
 *
 * @copyright RawrXD 2026
 */

#include "compression_abi.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <unordered_map>
#include <immintrin.h>

namespace rawrxd {
namespace compression {

// ============================================================================
// PIMPL Implementation
// ============================================================================

class CompressionABI::Impl {
public:
    std::unordered_map<uint8_t, DecoderRegistryEntry> decoders_;
    
    Impl() {
        RegisterBuiltinDecoders();
    }
    
    void RegisterBuiltinDecoders() {
        // Q4_0 decoder
        decoders_[static_cast<uint8_t>(QuantType::Q4_0)] = {
            QuantType::Q4_0,
            "Q4_0",
            DecodeQ4_0,
            BatchDecodeQ4_0,
            FusedGemvQ4_0,
            true,   // AVX2 accelerated
            false   // No outlier support
        };
        
        // Q8_0 decoder
        decoders_[static_cast<uint8_t>(QuantType::Q8_0)] = {
            QuantType::Q8_0,
            "Q8_0",
            DecodeQ8_0,
            BatchDecodeQ8_0,
            nullptr, // No fused kernel yet
            true,
            false
        };
        
        // FP32 passthrough
        decoders_[static_cast<uint8_t>(QuantType::FP32)] = {
            QuantType::FP32,
            "FP32",
            DecodeFP32,
            BatchDecodeFP32,
            nullptr,
            true,
            false
        };
    }
    
    // Q4_0 decode
    static float DecodeQ4_0(const void* block, uint32_t index, 
                            const CompressionProfile& profile) {
        const uint8_t* data = static_cast<const uint8_t*>(block);
        
        // Skip header if present
        const BlockHeader* header = reinterpret_cast<const BlockHeader*>(data);
        if (header->magic == BLOCK_MAGIC) {
            data += sizeof(BlockHeader);
        }
        
        // Read scale (FP16)
        uint16_t scale_bits;
        memcpy(&scale_bits, data, 2);
        float scale = *reinterpret_cast<const float*>(&scale_bits);
        
        // Read nibbles
        uint8_t nibble_byte = data[2 + (index / 2)];
        uint8_t nibble = (index % 2 == 0) ? (nibble_byte & 0x0F) : ((nibble_byte >> 4) & 0x0F);
        
        // Dequantize
        return (static_cast<float>(nibble) - 8.0f) * scale;
    }
    
    static void BatchDecodeQ4_0(const void* block, uint32_t start, uint32_t count,
                                   float* output, const CompressionProfile& profile) {
        for (uint32_t i = 0; i < count; i++) {
            output[i] = DecodeQ4_0(block, start + i, profile);
        }
    }
    
    static void FusedGemvQ4_0(const void* weights, const float* input,
                               float* output, int rows, int cols,
                               const CompressionProfile& profile) {
        // Simplified scalar implementation
        for (int i = 0; i < rows; i++) {
            float sum = 0.0f;
            for (int j = 0; j < cols; j++) {
                float w = DecodeQ4_0(weights, i * cols + j, profile);
                sum += w * input[j];
            }
            output[i] = sum;
        }
    }
    
    // Q8_0 decode
    static float DecodeQ8_0(const void* block, uint32_t index,
                            const CompressionProfile& profile) {
        const uint8_t* data = static_cast<const uint8_t*>(block);
        
        const BlockHeader* header = reinterpret_cast<const BlockHeader*>(data);
        if (header->magic == BLOCK_MAGIC) {
            data += sizeof(BlockHeader);
        }
        
        uint16_t scale_bits;
        memcpy(&scale_bits, data, 2);
        float scale = *reinterpret_cast<const float*>(&scale_bits);
        
        int8_t quantized = static_cast<int8_t>(data[2 + index]);
        return static_cast<float>(quantized) * scale;
    }
    
    static void BatchDecodeQ8_0(const void* block, uint32_t start, uint32_t count,
                                 float* output, const CompressionProfile& profile) {
        for (uint32_t i = 0; i < count; i++) {
            output[i] = DecodeQ8_0(block, start + i, profile);
        }
    }
    
    // FP32 passthrough
    static float DecodeFP32(const void* block, uint32_t index,
                            const CompressionProfile& profile) {
        const float* data = static_cast<const float*>(block);
        return data[index];
    }
    
    static void BatchDecodeFP32(const void* block, uint32_t start, uint32_t count,
                                 float* output, const CompressionProfile& profile) {
        const float* data = static_cast<const float*>(block);
        memcpy(output, data + start, count * sizeof(float));
    }
};

// ============================================================================
// CompressionABI Public Interface
// ============================================================================

CompressionABI::CompressionABI() : impl_(std::make_unique<Impl>()) {}
CompressionABI::~CompressionABI() = default;

void CompressionABI::RegisterDecoder(const DecoderRegistryEntry& entry) {
    impl_->decoders_[static_cast<uint8_t>(entry.quant_type)] = entry;
}

void CompressionABI::UnregisterDecoder(QuantType quant_type) {
    impl_->decoders_.erase(static_cast<uint8_t>(quant_type));
}

bool CompressionABI::HasDecoder(QuantType quant_type) const {
    return impl_->decoders_.find(static_cast<uint8_t>(quant_type)) != impl_->decoders_.end();
}

float CompressionABI::DecodeWeight(const void* block, uint32_t index,
                                     const CompressionProfile& profile) {
    auto it = impl_->decoders_.find(static_cast<uint8_t>(profile.quant_type));
    if (it != impl_->decoders_.end() && it->second.decode_fn) {
        return it->second.decode_fn(block, index, profile);
    }
    return 0.0f;
}

void CompressionABI::DecodeBatch(const void* block, uint32_t start, uint32_t count,
                                  float* output, const CompressionProfile& profile) {
    auto it = impl_->decoders_.find(static_cast<uint8_t>(profile.quant_type));
    if (it != impl_->decoders_.end() && it->second.batch_decode_fn) {
        it->second.batch_decode_fn(block, start, count, output, profile);
    }
}

CompressionProfile CompressionABI::CreateProfile(RuntimeProfile runtime_profile) {
    CompressionProfile profile{};
    profile.abi_version = COMPRESSION_ABI_VERSION;
    
    switch (runtime_profile) {
        case RuntimeProfile::ECO:
            profile.quant_type = QuantType::Q3_R;
            profile.bits_per_weight = 3;
            profile.block_size = 256;
            profile.scale_type = ScaleType::FP16;
            profile.outlier_budget = 0.01f;
            strncpy(profile.name, "ECO", 31);
            break;
            
        case RuntimeProfile::BALANCED:
            profile.quant_type = QuantType::Q4_0;
            profile.bits_per_weight = 4;
            profile.block_size = 32;
            profile.scale_type = ScaleType::FP16;
            profile.outlier_budget = 0.0f;
            strncpy(profile.name, "BALANCED", 31);
            break;
            
        case RuntimeProfile::PERFORMANCE:
            profile.quant_type = QuantType::Q6_R;
            profile.bits_per_weight = 6;
            profile.block_size = 64;
            profile.scale_type = ScaleType::FP16;
            profile.outlier_budget = 0.0f;
            strncpy(profile.name, "PERFORMANCE", 31);
            break;
            
        case RuntimeProfile::QUALITY:
            profile.quant_type = QuantType::Q8_0;
            profile.bits_per_weight = 8;
            profile.block_size = 32;
            profile.scale_type = ScaleType::FP16;
            profile.outlier_budget = 0.0f;
            strncpy(profile.name, "QUALITY", 31);
            break;
            
        case RuntimeProfile::ADAPTIVE:
            profile.quant_type = QuantType::Q4_R;
            profile.bits_per_weight = 4;
            profile.block_size = 64;
            profile.scale_type = ScaleType::FP16;
            profile.flags = COMPRESS_FLAG_ADAPTIVE;
            strncpy(profile.name, "ADAPTIVE", 31);
            break;
            
        default:
            profile = CreateProfile(RuntimeProfile::BALANCED);
            break;
    }
    
    // Calculate derived fields
    profile.effective_bits = profile.bits_per_weight + 
        (16.0f / profile.block_size);  // Scale overhead
    profile.compression_ratio = 32.0f / profile.effective_bits;
    profile.bytes_per_block = CalculateBlockSize(profile);
    
    return profile;
}

CompressionProfile CompressionABI::CreateAdaptiveProfile(const AdaptiveStrategy& strategy) {
    CompressionProfile profile{};
    profile.abi_version = COMPRESSION_ABI_VERSION;
    profile.quant_type = QuantType::Q4_R;
    profile.bits_per_weight = strategy.ffn_up_bits;  // Base on most aggressive
    profile.block_size = 64;
    profile.scale_type = ScaleType::FP16;
    profile.outlier_threshold = strategy.outlier_threshold;
    profile.outlier_budget = strategy.outlier_budget;
    profile.flags = COMPRESS_FLAG_ADAPTIVE | COMPRESS_FLAG_OUTLIERS;
    strncpy(profile.name, "ADAPTIVE_CUSTOM", 31);
    
    profile.effective_bits = profile.bits_per_weight + (16.0f / profile.block_size);
    profile.compression_ratio = 32.0f / profile.effective_bits;
    profile.bytes_per_block = CalculateBlockSize(profile);
    
    return profile;
}

CompressionProfile CompressionABI::CreateCustomProfile(QuantType quant_type,
                                                        uint32_t block_size,
                                                        uint8_t bits_per_weight) {
    CompressionProfile profile{};
    profile.abi_version = COMPRESSION_ABI_VERSION;
    profile.quant_type = quant_type;
    profile.bits_per_weight = bits_per_weight;
    profile.block_size = block_size;
    profile.scale_type = ScaleType::FP16;
    strncpy(profile.name, "CUSTOM", 31);
    
    profile.effective_bits = bits_per_weight + (16.0f / block_size);
    profile.compression_ratio = 32.0f / profile.effective_bits;
    profile.bytes_per_block = CalculateBlockSize(profile);
    
    return profile;
}

TensorCompressionInfo CompressionABI::AnalyzeTensor(const std::string& name,
                                                     const float* data,
                                                     size_t num_elements) {
    TensorCompressionInfo info{};
    info.tensor_name = name;
    info.original_size_mb = (num_elements * sizeof(float)) / (1024.0f * 1024.0f);
    
    // Calculate statistics
    float min_val = data[0];
    float max_val = data[0];
    float sum = 0.0f;
    float sum_sq = 0.0f;
    
    for (size_t i = 0; i < num_elements; i++) {
        min_val = std::min(min_val, data[i]);
        max_val = std::max(max_val, data[i]);
        sum += data[i];
        sum_sq += data[i] * data[i];
    }
    
    float mean = sum / num_elements;
    float variance = (sum_sq / num_elements) - (mean * mean);
    info.measured_error = std::sqrt(variance);
    
    // Determine sensitivity based on tensor name patterns
    if (name.find("embed") != std::string::npos) {
        info.is_sensitive = true;
        info.recommended_bits = 5;
    } else if (name.find("output") != std::string::npos || 
               name.find("lm_head") != std::string::npos) {
        info.is_sensitive = true;
        info.recommended_bits = 6;
    } else if (name.find("attention") != std::string::npos) {
        info.is_sensitive = true;
        info.recommended_bits = 4;
    } else if (name.find("ffn") != std::string::npos || 
               name.find("mlp") != std::string::npos) {
        info.is_sensitive = false;
        info.recommended_bits = 3;
    } else {
        info.is_sensitive = false;
        info.recommended_bits = 4;
    }
    
    return info;
}

void CompressionABI::ApplyAdaptiveCompression(std::vector<TensorCompressionInfo>& tensors) {
    for (auto& tensor : tensors) {
        // Create profile based on sensitivity
        if (tensor.is_sensitive) {
            tensor.profile = CreateCustomProfile(
                QuantType::Q4_R, 256, tensor.recommended_bits);
        } else {
            tensor.profile = CreateCustomProfile(
                QuantType::Q3_R, 256, tensor.recommended_bits);
        }
        
        // Estimate compressed size
        float compression = tensor.profile.compression_ratio;
        tensor.compressed_size_mb = tensor.original_size_mb / compression;
        tensor.compression_ratio = compression;
    }
}

bool CompressionABI::ValidateBlock(const void* block, size_t size) {
    if (size < sizeof(BlockHeader)) return false;
    
    const BlockHeader* header = reinterpret_cast<const BlockHeader*>(block);
    return header->magic == BLOCK_MAGIC;
}

float CompressionABI::MeasureError(const float* original, const float* decoded,
                                      size_t num_elements) {
    float max_error = 0.0f;
    for (size_t i = 0; i < num_elements; i++) {
        float error = std::fabs(original[i] - decoded[i]);
        max_error = std::max(max_error, error);
    }
    return max_error;
}

const char* CompressionABI::QuantTypeToString(QuantType type) {
    switch (type) {
        case QuantType::Q4_0: return "Q4_0";
        case QuantType::Q4_1: return "Q4_1";
        case QuantType::Q5_0: return "Q5_0";
        case QuantType::Q5_1: return "Q5_1";
        case QuantType::Q8_0: return "Q8_0";
        case QuantType::Q8_1: return "Q8_1";
        case QuantType::Q2_K: return "Q2_K";
        case QuantType::Q3_K: return "Q3_K";
        case QuantType::Q4_K: return "Q4_K";
        case QuantType::Q5_K: return "Q5_K";
        case QuantType::Q6_K: return "Q6_K";
        case QuantType::Q3_R: return "Q3_R";
        case QuantType::Q4_R: return "Q4_R";
        case QuantType::Q6_R: return "Q6_R";
        case QuantType::Q8_R: return "Q8_R";
        case QuantType::FP16: return "FP16";
        case QuantType::FP32: return "FP32";
        default: return "UNKNOWN";
    }
}

QuantType CompressionABI::StringToQuantType(const char* str) {
    if (strcmp(str, "Q4_0") == 0) return QuantType::Q4_0;
    if (strcmp(str, "Q4_1") == 0) return QuantType::Q4_1;
    if (strcmp(str, "Q5_0") == 0) return QuantType::Q5_0;
    if (strcmp(str, "Q5_1") == 0) return QuantType::Q5_1;
    if (strcmp(str, "Q8_0") == 0) return QuantType::Q8_0;
    if (strcmp(str, "Q8_1") == 0) return QuantType::Q8_1;
    if (strcmp(str, "FP16") == 0) return QuantType::FP16;
    if (strcmp(str, "FP32") == 0) return QuantType::FP32;
    return QuantType::UNQUANTIZED;
}

size_t CompressionABI::CalculateBlockSize(const CompressionProfile& profile) {
    size_t weight_bytes = (profile.block_size * profile.bits_per_weight + 7) / 8;
    size_t scale_bytes = 2;  // FP16 scale
    size_t zero_bytes = profile.zero_type == ScaleType::FP16 ? 2 : 0;
    return weight_bytes + scale_bytes + zero_bytes;
}

// ============================================================================
// Global Instance
// ============================================================================

CompressionABI& GetCompressionABI() {
    static CompressionABI instance;
    return instance;
}

} // namespace compression
} // namespace rawrxd
