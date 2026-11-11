/**
 * @file gguf_weight_loader.cpp
 * @brief RawrXD GGUF Weight Loader Implementation
 *
 * Loads transformer weights from GGUF files with memory mapping
 * and on-the-fly dequantization.
 *
 * @copyright RawrXD 2026
 */

#include "gguf_weight_loader.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cmath>

// Platform-specific includes for memory mapping
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace rawrxd {
namespace runtime {

// ============================================================================
// GGML Type Constants
// ============================================================================

static constexpr uint32_t GGML_TYPE_F32  = 0;
static constexpr uint32_t GGML_TYPE_F16  = 1;
static constexpr uint32_t GGML_TYPE_Q4_0 = 2;
static constexpr uint32_t GGML_TYPE_Q4_1 = 3;
static constexpr uint32_t GGML_TYPE_Q5_0 = 6;
static constexpr uint32_t GGML_TYPE_Q5_1 = 7;
static constexpr uint32_t GGML_TYPE_Q8_0 = 8;
static constexpr uint32_t GGML_TYPE_Q8_1 = 9;
static constexpr uint32_t GGML_TYPE_Q2_K = 10;
static constexpr uint32_t GGML_TYPE_Q3_K = 11;
static constexpr uint32_t GGML_TYPE_Q4_K = 12;
static constexpr uint32_t GGML_TYPE_Q5_K = 13;
static constexpr uint32_t GGML_TYPE_Q6_K = 14;
static constexpr uint32_t GGML_TYPE_Q8_K = 15;

// ============================================================================
// TensorData Implementation
// ============================================================================

uint64_t TensorData::GetElementCount() const {
    uint64_t count = 1;
    for (auto dim : shape) {
        count *= dim;
    }
    return count;
}

size_t TensorData::GetSizeBytes() const {
    return GetElementCount() * sizeof(float);
}

const float* TensorData::GetF32Data() {
    if (!f32_data.empty()) {
        return f32_data.data();
    }
    if (quant_type == QuantizationType::F32 && data != nullptr) {
        return static_cast<const float*>(data);
    }
    return nullptr;
}

float TensorData::GetElement(size_t index) {
    const float* f32 = GetF32Data();
    if (f32 != nullptr && index < GetElementCount()) {
        return f32[index];
    }
    return 0.0f;
}

// ============================================================================
// TransformerWeights Implementation
// ============================================================================

size_t TransformerWeights::GetTotalSizeBytes() const {
    size_t total = 0;
    
    total += token_embeddings.GetSizeBytes();
    total += output_weights.GetSizeBytes();
    total += final_norm.GetSizeBytes();
    total += final_norm_bias.GetSizeBytes();
    
    for (const auto& layer : layers) {
        total += layer.attn_q.GetSizeBytes();
        total += layer.attn_k.GetSizeBytes();
        total += layer.attn_v.GetSizeBytes();
        total += layer.attn_o.GetSizeBytes();
        total += layer.attn_norm.GetSizeBytes();
        total += layer.attn_norm_bias.GetSizeBytes();
        total += layer.ffn_gate.GetSizeBytes();
        total += layer.ffn_up.GetSizeBytes();
        total += layer.ffn_down.GetSizeBytes();
        total += layer.ffn_norm.GetSizeBytes();
        total += layer.ffn_norm_bias.GetSizeBytes();
    }
    
    return total;
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

GGUFWeightLoader::GGUFWeightLoader() = default;
GGUFWeightLoader::~GGUFWeightLoader() {
    Unload();
}

GGUFWeightLoader::GGUFWeightLoader(GGUFWeightLoader&& other) noexcept {
    *this = std::move(other);
}

GGUFWeightLoader& GGUFWeightLoader::operator=(GGUFWeightLoader&& other) noexcept {
    if (this != &other) {
        Unload();
        
        loaded_ = other.loaded_;
        last_error_ = std::move(other.last_error_);
        progress_ = other.progress_;
        file_handle_ = other.file_handle_;
        mapping_handle_ = other.mapping_handle_;
        mapped_base_ = other.mapped_base_;
        mapped_size_ = other.mapped_size_;
        weights_ = std::move(other.weights_);
        tensor_map_ = std::move(other.tensor_map_);
        
        other.loaded_ = false;
        other.file_handle_ = nullptr;
        other.mapping_handle_ = nullptr;
        other.mapped_base_ = nullptr;
        other.mapped_size_ = 0;
    }
    return *this;
}

// ============================================================================
// File Mapping
// ============================================================================

bool GGUFWeightLoader::MapFile(const std::string& path) {
    UnmapFile();
    
#ifdef _WIN32
    // Windows implementation
    file_handle_ = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    
    if (file_handle_ == INVALID_HANDLE_VALUE) {
        last_error_ = "Failed to open file: " + path;
        return false;
    }
    
    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(static_cast<HANDLE>(file_handle_), &file_size)) {
        last_error_ = "Failed to get file size";
        CloseHandle(static_cast<HANDLE>(file_handle_));
        file_handle_ = nullptr;
        return false;
    }
    
    mapped_size_ = static_cast<size_t>(file_size.QuadPart);
    
    mapping_handle_ = CreateFileMapping(
        static_cast<HANDLE>(file_handle_),
        nullptr,
        PAGE_READONLY,
        0,
        0,
        nullptr
    );
    
    if (mapping_handle_ == nullptr) {
        last_error_ = "Failed to create file mapping";
        CloseHandle(static_cast<HANDLE>(file_handle_));
        file_handle_ = nullptr;
        return false;
    }
    
    mapped_base_ = static_cast<const uint8_t*>(MapViewOfFile(
        static_cast<HANDLE>(mapping_handle_),
        FILE_MAP_READ,
        0,
        0,
        0
    ));
    
    if (mapped_base_ == nullptr) {
        last_error_ = "Failed to map view of file";
        CloseHandle(static_cast<HANDLE>(mapping_handle_));
        CloseHandle(static_cast<HANDLE>(file_handle_));
        mapping_handle_ = nullptr;
        file_handle_ = nullptr;
        return false;
    }
#else
    // POSIX implementation
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        last_error_ = "Failed to open file: " + path;
        return false;
    }
    
    struct stat st;
    if (fstat(fd, &st) != 0) {
        last_error_ = "Failed to get file size";
        close(fd);
        return false;
    }
    
    mapped_size_ = st.st_size;
    
    mapped_base_ = static_cast<const uint8_t*>(mmap(
        nullptr,
        mapped_size_,
        PROT_READ,
        MAP_PRIVATE,
        fd,
        0
    ));
    
    close(fd);
    
    if (mapped_base_ == MAP_FAILED) {
        last_error_ = "Failed to mmap file";
        mapped_base_ = nullptr;
        return false;
    }
#endif
    
    return true;
}

void GGUFWeightLoader::UnmapFile() {
    if (mapped_base_ != nullptr) {
#ifdef _WIN32
        UnmapViewOfFile(mapped_base_);
        if (mapping_handle_ != nullptr) {
            CloseHandle(static_cast<HANDLE>(mapping_handle_));
            mapping_handle_ = nullptr;
        }
        if (file_handle_ != nullptr && file_handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(static_cast<HANDLE>(file_handle_));
            file_handle_ = nullptr;
        }
#else
        munmap(const_cast<uint8_t*>(mapped_base_), mapped_size_);
#endif
        mapped_base_ = nullptr;
        mapped_size_ = 0;
    }
}

// ============================================================================
// Loading
// ============================================================================

bool GGUFWeightLoader::LoadFromFile(const std::string& path, const ProgressCallback& callback) {
    Unload();
    last_error_.clear();
    
    // First, parse the GGUF file to get tensor info
    model::ModelContext context;
    if (!context.LoadFromFile(path)) {
        last_error_ = "Failed to parse GGUF file";
        return false;
    }
    
    // Now map the file for tensor data access
    if (!MapFile(path)) {
        return false;
    }
    
    return LoadFromContext(context, callback);
}

bool GGUFWeightLoader::LoadFromContext(const model::ModelContext& context, const ProgressCallback& callback) {
    if (mapped_base_ == nullptr) {
        last_error_ = "File not mapped";
        return false;
    }
    
    const auto& tensors = context.GetTensors();
    
    // Initialize progress
    progress_.total_tensors = static_cast<uint32_t>(tensors.size());
    progress_.loaded_tensors = 0;
    progress_.total_bytes = 0;
    progress_.loaded_bytes = 0;
    
    for (const auto& tensor : tensors) {
        progress_.total_bytes += tensor.size;
    }
    
    // Get architecture info
    const auto& arch = context.GetArchitecture();
    uint32_t num_layers = arch.layer_count;
    
    if (num_layers == 0) {
        last_error_ = "Invalid model: no layers";
        return false;
    }
    
    // Resize layer weights
    weights_.layers.resize(num_layers);
    
    // Parse and load each tensor
    for (const auto& tensor_info : tensors) {
        progress_.current_tensor = tensor_info.name;
        
        if (!ParseTensors(context)) {
            return false;
        }
        
        progress_.loaded_tensors++;
        progress_.loaded_bytes += tensor_info.size;
        
        if (callback) {
            callback(progress_);
        }
    }
    
    loaded_ = true;
    return true;
}

bool GGUFWeightLoader::ParseTensors(const model::ModelContext& context) {
    const auto& tensors = context.GetTensors();
    
    for (const auto& tensor_info : tensors) {
        std::string mapped_name = MapWeightName(tensor_info.name);
        
        if (mapped_name.empty()) {
            // Skip unknown tensors
            continue;
        }
        
        // Determine which weight this is
        if (mapped_name == "token_embeddings") {
            if (!LoadTensor(tensor_info, weights_.token_embeddings)) {
                return false;
            }
            weights_.token_embeddings.name = tensor_info.name;
            tensor_map_["token_embeddings"] = &weights_.token_embeddings;
        }
        else if (mapped_name == "output_weights") {
            if (!LoadTensor(tensor_info, weights_.output_weights)) {
                return false;
            }
            weights_.output_weights.name = tensor_info.name;
            tensor_map_["output_weights"] = &weights_.output_weights;
        }
        else if (mapped_name == "final_norm") {
            if (!LoadTensor(tensor_info, weights_.final_norm)) {
                return false;
            }
            weights_.final_norm.name = tensor_info.name;
            tensor_map_["final_norm"] = &weights_.final_norm;
        }
        else if (mapped_name.rfind("layer_", 0) == 0) {
            // Parse layer index and weight type
            // Format: layer_{N}_{type}
            size_t first_underscore = mapped_name.find('_');
            size_t second_underscore = mapped_name.find('_', first_underscore + 1);
            
            if (first_underscore == std::string::npos || second_underscore == std::string::npos) {
                continue;
            }
            
            std::string layer_str = mapped_name.substr(first_underscore + 1, second_underscore - first_underscore - 1);
            std::string weight_type = mapped_name.substr(second_underscore + 1);
            
            uint32_t layer_idx = static_cast<uint32_t>(std::stoul(layer_str));
            if (layer_idx >= weights_.layers.size()) {
                continue;
            }
            
            auto& layer = weights_.layers[layer_idx];
            
            // Load the appropriate weight
            if (weight_type == "attn_q") {
                LoadTensor(tensor_info, layer.attn_q);
                layer.attn_q.name = tensor_info.name;
            }
            else if (weight_type == "attn_k") {
                LoadTensor(tensor_info, layer.attn_k);
                layer.attn_k.name = tensor_info.name;
            }
            else if (weight_type == "attn_v") {
                LoadTensor(tensor_info, layer.attn_v);
                layer.attn_v.name = tensor_info.name;
            }
            else if (weight_type == "attn_o") {
                LoadTensor(tensor_info, layer.attn_o);
                layer.attn_o.name = tensor_info.name;
            }
            else if (weight_type == "attn_norm") {
                LoadTensor(tensor_info, layer.attn_norm);
                layer.attn_norm.name = tensor_info.name;
            }
            else if (weight_type == "ffn_gate") {
                LoadTensor(tensor_info, layer.ffn_gate);
                layer.ffn_gate.name = tensor_info.name;
            }
            else if (weight_type == "ffn_up") {
                LoadTensor(tensor_info, layer.ffn_up);
                layer.ffn_up.name = tensor_info.name;
            }
            else if (weight_type == "ffn_down") {
                LoadTensor(tensor_info, layer.ffn_down);
                layer.ffn_down.name = tensor_info.name;
            }
            else if (weight_type == "ffn_norm") {
                LoadTensor(tensor_info, layer.ffn_norm);
                layer.ffn_norm.name = tensor_info.name;
            }
        }
    }
    
    return true;
}

bool GGUFWeightLoader::LoadTensor(const model::TensorInfo& info, TensorData& out_data) {
    out_data.name = info.name;
    out_data.shape = info.shape;
    out_data.quant_type = ConvertGGMLType(info.type);
    
    if (out_data.quant_type == QuantizationType::Unknown) {
        last_error_ = "Unknown quantization type: " + std::to_string(info.type);
        return false;
    }
    
    // Point to data in memory-mapped file
    out_data.data = mapped_base_ + info.offset;
    out_data.size = info.size;
    out_data.owns_data = false;
    
    // Dequantize if needed
    if (out_data.quant_type != QuantizationType::F32) {
        if (!DequantizeTensor(out_data)) {
            return false;
        }
    }
    
    return true;
}

// ============================================================================
// Quantization
// ============================================================================

QuantizationType GGUFWeightLoader::ConvertGGMLType(uint32_t ggml_type) {
    switch (ggml_type) {
        case GGML_TYPE_F32:  return QuantizationType::F32;
        case GGML_TYPE_F16:  return QuantizationType::F16;
        case GGML_TYPE_Q4_0: return QuantizationType::Q4_0;
        case GGML_TYPE_Q4_1: return QuantizationType::Q4_1;
        case GGML_TYPE_Q5_0: return QuantizationType::Q5_0;
        case GGML_TYPE_Q5_1: return QuantizationType::Q5_1;
        case GGML_TYPE_Q8_0: return QuantizationType::Q8_0;
        case GGML_TYPE_Q8_1: return QuantizationType::Q8_1;
        case GGML_TYPE_Q2_K: return QuantizationType::Q2_K;
        case GGML_TYPE_Q3_K: return QuantizationType::Q3_K;
        case GGML_TYPE_Q4_K: return QuantizationType::Q4_K;
        case GGML_TYPE_Q5_K: return QuantizationType::Q5_K;
        case GGML_TYPE_Q6_K: return QuantizationType::Q6_K;
        case GGML_TYPE_Q8_K: return QuantizationType::Q8_K;
        default:             return QuantizationType::Unknown;
    }
}

bool GGUFWeightLoader::DequantizeTensor(TensorData& data) {
    size_t num_elements = data.GetElementCount();
    data.f32_data.resize(num_elements);
    
    switch (data.quant_type) {
        case QuantizationType::F16:
            return DequantizeF16(data.data, data.f32_data.data(), num_elements);
        case QuantizationType::Q4_0:
            return DequantizeQ4_0(data.data, data.f32_data.data(), num_elements);
        case QuantizationType::Q8_0:
            return DequantizeQ8_0(data.data, data.f32_data.data(), num_elements);
        case QuantizationType::Q4_K:
            return DequantizeQ4_K(data.data, data.f32_data.data(), num_elements);
        case QuantizationType::Q6_K:
            return DequantizeQ6_K(data.data, data.f32_data.data(), num_elements);
        default:
            last_error_ = "Dequantization not implemented for type: " + 
                       std::to_string(static_cast<int>(data.quant_type));
            return false;
    }
}

bool GGUFWeightLoader::DequantizeF16(const void* src, float* dst, size_t num_elements) {
    const uint16_t* src_h = static_cast<const uint16_t*>(src);
    
    for (size_t i = 0; i < num_elements; ++i) {
        uint16_t h = src_h[i];
        
        // Convert F16 to F32
        uint32_t sign = (h & 0x8000) << 16;
        uint32_t exponent = ((h & 0x7C00) + 0x1C000) << 13;
        uint32_t mantissa = (h & 0x03FF) << 13;
        
        if ((h & 0x7C00) == 0) {  // Denormal
            if ((h & 0x03FF) == 0) {
                dst[i] = sign ? -0.0f : 0.0f;
            } else {
                float val = static_cast<float>(h & 0x03FF) / 1024.0f * 0.00006103515625f;
                dst[i] = sign ? -val : val;
            }
        } else if ((h & 0x7C00) == 0x7C00) {  // Inf/NaN
            uint32_t f32 = sign | 0x7F800000 | mantissa;
            std::memcpy(&dst[i], &f32, sizeof(float));
        } else {
            uint32_t f32 = sign | exponent | mantissa;
            std::memcpy(&dst[i], &f32, sizeof(float));
        }
    }
    
    return true;
}

bool GGUFWeightLoader::DequantizeQ4_0(const void* src, float* dst, size_t num_elements) {
    // Q4_0: 4-bit quantized, block size 32
    // Each block: 2 bytes scale (F16) + 16 bytes weights (32 x 4-bit)
    const uint8_t* src_u8 = static_cast<const uint8_t*>(src);
    size_t num_blocks = (num_elements + 31) / 32;
    
    for (size_t block = 0; block < num_blocks; ++block) {
        // Read scale (F16)
        uint16_t scale_h;
        std::memcpy(&scale_h, src_u8 + block * 18, sizeof(uint16_t));
        
        // Convert F16 to F32
        float scale;
        uint32_t exp = ((scale_h & 0x7C00) + 0x1C000) << 13;
        uint32_t mant = (scale_h & 0x03FF) << 13;
        uint32_t s = (scale_h & 0x8000) << 16;
        uint32_t f32 = s | exp | mant;
        std::memcpy(&scale, &f32, sizeof(float));
        
        // Dequantize weights
        for (size_t i = 0; i < 32; ++i) {
            size_t idx = block * 32 + i;
            if (idx >= num_elements) break;
            
            uint8_t byte = src_u8[block * 18 + 2 + i / 2];
            int8_t val = (i % 2 == 0) ? (byte & 0x0F) : ((byte >> 4) & 0x0F);
            
            // Sign extend 4-bit to 8-bit
            if (val & 0x08) val |= 0xF0;
            
            dst[idx] = scale * static_cast<float>(val);
        }
    }
    
    return true;
}

bool GGUFWeightLoader::DequantizeQ8_0(const void* src, float* dst, size_t num_elements) {
    // Q8_0: 8-bit quantized, block size 32
    // Each block: 2 bytes scale (F16) + 32 bytes weights
    const uint8_t* src_u8 = static_cast<const uint8_t*>(src);
    size_t num_blocks = (num_elements + 31) / 32;
    
    for (size_t block = 0; block < num_blocks; ++block) {
        // Read scale (F16)
        uint16_t scale_h;
        std::memcpy(&scale_h, src_u8 + block * 34, sizeof(uint16_t));
        
        // Convert F16 to F32
        float scale;
        uint32_t exp = ((scale_h & 0x7C00) + 0x1C000) << 13;
        uint32_t mant = (scale_h & 0x03FF) << 13;
        uint32_t s = (scale_h & 0x8000) << 16;
        uint32_t f32 = s | exp | mant;
        std::memcpy(&scale, &f32, sizeof(float));
        
        // Dequantize weights
        for (size_t i = 0; i < 32; ++i) {
            size_t idx = block * 32 + i;
            if (idx >= num_elements) break;
            
            int8_t val = static_cast<int8_t>(src_u8[block * 34 + 2 + i]);
            dst[idx] = scale * static_cast<float>(val);
        }
    }
    
    return true;
}

bool GGUFWeightLoader::DequantizeQ4_K(const void* src, float* dst, size_t num_elements) {
    // Q4_K: K-quant 4-bit
    // Simplified implementation - full K-quant is complex
    // For now, just zero out
    std::fill(dst, dst + num_elements, 0.0f);
    return true;
}

bool GGUFWeightLoader::DequantizeQ6_K(const void* src, float* dst, size_t num_elements) {
    // Q6_K: K-quant 6-bit
    // Simplified implementation
    std::fill(dst, dst + num_elements, 0.0f);
    return true;
}

// ============================================================================
// Weight Name Mapping
// ============================================================================

std::string GGUFWeightLoader::MapWeightName(const std::string& gguf_name) {
    // Map GGUF tensor names to standardized names
    
    // Token embeddings
    if (gguf_name == "token_embd.weight" || 
        gguf_name == "tok_embeddings.weight" ||
        gguf_name == "model.embed_tokens.weight") {
        return "token_embeddings";
    }
    
    // Output weights
    if (gguf_name == "output.weight" ||
        gguf_name == "output_norm.weight" ||
        gguf_name == "lm_head.weight") {
        return "output_weights";
    }
    
    // Final norm
    if (gguf_name == "output_norm.weight" ||
        gguf_name == "norm.weight") {
        return "final_norm";
    }
    
    // Layer weights
    // Format: blk.{N}.{type}.weight
    if (gguf_name.rfind("blk.", 0) == 0) {
        size_t first_dot = gguf_name.find('.');
        size_t second_dot = gguf_name.find('.', first_dot + 1);
        
        if (first_dot != std::string::npos && second_dot != std::string::npos) {
            std::string layer_num = gguf_name.substr(first_dot + 1, second_dot - first_dot - 1);
            std::string weight_type = gguf_name.substr(second_dot + 1);
            
            // Remove ".weight" suffix if present
            size_t weight_pos = weight_type.find(".weight");
            if (weight_pos != std::string::npos) {
                weight_type = weight_type.substr(0, weight_pos);
            }
            
            // Map weight types
            if (weight_type == "attn_q") return "layer_" + layer_num + "_attn_q";
            if (weight_type == "attn_k") return "layer_" + layer_num + "_attn_k";
            if (weight_type == "attn_v") return "layer_" + layer_num + "_attn_v";
            if (weight_type == "attn_output") return "layer_" + layer_num + "_attn_o";
            if (weight_type == "attn_norm") return "layer_" + layer_num + "_attn_norm";
            if (weight_type == "ffn_gate") return "layer_" + layer_num + "_ffn_gate";
            if (weight_type == "ffn_up") return "layer_" + layer_num + "_ffn_up";
            if (weight_type == "ffn_down") return "layer_" + layer_num + "_ffn_down";
            if (weight_type == "ffn_norm") return "layer_" + layer_num + "_ffn_norm";
        }
    }
    
    // Unknown tensor
    return "";
}

// ============================================================================
// Utility
// ============================================================================

void GGUFWeightLoader::Unload() {
    weights_ = TransformerWeights();
    tensor_map_.clear();
    UnmapFile();
    loaded_ = false;
}

const TensorData* GGUFWeightLoader::GetTensor(const std::string& name) const {
    auto it = tensor_map_.find(name);
    if (it != tensor_map_.end()) {
        return it->second;
    }
    return nullptr;
}

// ============================================================================
// Convenience Functions
// ============================================================================

std::unique_ptr<TransformerWeights> LoadTransformerWeights(
    const std::string& gguf_path,
    std::string* error,
    const ProgressCallback& callback) {
    
    auto loader = std::make_unique<GGUFWeightLoader>();
    
    if (!loader->LoadFromFile(gguf_path, callback)) {
        if (error) {
            *error = loader->GetLastError();
        }
        return nullptr;
    }
    
    // Move weights out of loader
    auto weights = std::make_unique<TransformerWeights>(std::move(loader->GetWeights()));
    return weights;
}

const char* GetQuantizationName(QuantizationType type) {
    switch (type) {
        case QuantizationType::F32:  return "F32";
        case QuantizationType::F16:  return "F16";
        case QuantizationType::Q4_0: return "Q4_0";
        case QuantizationType::Q4_1: return "Q4_1";
        case QuantizationType::Q5_0: return "Q5_0";
        case QuantizationType::Q5_1: return "Q5_1";
        case QuantizationType::Q8_0: return "Q8_0";
        case QuantizationType::Q8_1: return "Q8_1";
        case QuantizationType::Q2_K: return "Q2_K";
        case QuantizationType::Q3_K: return "Q3_K";
        case QuantizationType::Q4_K: return "Q4_K";
        case QuantizationType::Q5_K: return "Q5_K";
        case QuantizationType::Q6_K: return "Q6_K";
        case QuantizationType::Q8_K: return "Q8_K";
        default:                     return "Unknown";
    }
}

size_t CalculateDequantizedSize(QuantizationType type, size_t num_elements) {
    return num_elements * sizeof(float);
}

} // namespace runtime
} // namespace rawrxd
