/**
 * @file gguf_tensor_loader.cpp
 * @brief RawrXD GGUF Tensor Loader Implementation
 *
 * Memory-mapped GGUF file access with tensor dequantization.
 *
 * @copyright RawrXD 2026
 */

#include "gguf_tensor_loader.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cmath>

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
// GGUF Constants
// ============================================================================

static constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF" in little-endian
static constexpr uint32_t GGUF_VERSION = 3;

// GGML types
enum class GGMLType : uint32_t {
    F32  = 0,
    F16  = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q8_1 = 9,
    Q2_K = 10,
    Q3_K = 11,
    Q4_K = 12,
    Q5_K = 13,
    Q6_K = 14,
    Q8_K = 15,
};

// GGUF value types
enum class GGUFValueType : uint32_t {
    UINT8   = 0,
    INT8    = 1,
    UINT16  = 2,
    INT16   = 3,
    UINT32  = 4,
    INT32   = 5,
    FLOAT32 = 6,
    BOOL    = 7,
    STRING  = 8,
    ARRAY   = 9,
    UINT64  = 10,
    INT64   = 11,
    FLOAT64 = 12,
};

// ============================================================================
// TensorView Implementation
// ============================================================================

uint64_t TensorView::GetElementCount() const {
    uint64_t count = 1;
    for (auto dim : shape) {
        count *= dim;
    }
    return count;
}

size_t TensorView::GetElementSize() const {
    switch (static_cast<GGMLType>(type)) {
        case GGMLType::F32:  return 4;
        case GGMLType::F16:  return 2;
        case GGMLType::Q4_0: return 0.5f;  // 4 bits
        case GGMLType::Q4_1: return 0.5f;
        case GGMLType::Q5_0: return 0.625f;
        case GGMLType::Q5_1: return 0.625f;
        case GGMLType::Q8_0: return 1;
        case GGMLType::Q8_1: return 1;
        default:             return 1;
    }
}

std::string TensorView::GetTypeName() const {
    switch (static_cast<GGMLType>(type)) {
        case GGMLType::F32:  return "F32";
        case GGMLType::F16:  return "F16";
        case GGMLType::Q4_0: return "Q4_0";
        case GGMLType::Q4_1: return "Q4_1";
        case GGMLType::Q5_0: return "Q5_0";
        case GGMLType::Q5_1: return "Q5_1";
        case GGMLType::Q8_0: return "Q8_0";
        case GGMLType::Q8_1: return "Q8_1";
        case GGMLType::Q2_K: return "Q2_K";
        case GGMLType::Q3_K: return "Q3_K";
        case GGMLType::Q4_K: return "Q4_K";
        case GGMLType::Q5_K: return "Q5_K";
        case GGMLType::Q6_K: return "Q6_K";
        case GGMLType::Q8_K: return "Q8_K";
        default:             return "UNKNOWN(" + std::to_string(type) + ")";
    }
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

GGUFTensorLoader::GGUFTensorLoader() = default;

GGUFTensorLoader::~GGUFTensorLoader() {
    Close();
}

GGUFTensorLoader::GGUFTensorLoader(GGUFTensorLoader&& other) noexcept {
    *this = std::move(other);
}

GGUFTensorLoader& GGUFTensorLoader::operator=(GGUFTensorLoader&& other) noexcept {
    if (this != &other) {
        Close();
        file_data_ = other.file_data_;
        file_size_ = other.file_size_;
        gguf_version_ = other.gguf_version_;
        tensors_ = std::move(other.tensors_);
#ifdef _WIN32
        file_handle_ = other.file_handle_;
        map_handle_ = other.map_handle_;
        other.file_handle_ = nullptr;
        other.map_handle_ = nullptr;
#else
        file_fd_ = other.file_fd_;
        other.file_fd_ = -1;
#endif
        other.file_data_ = nullptr;
        other.file_size_ = 0;
    }
    return *this;
}

// ============================================================================
// File Operations
// ============================================================================

bool GGUFTensorLoader::Open(const std::string& path) {
    Close();
    
    if (!MapFile(path)) {
        return false;
    }
    
    if (!ParseHeader()) {
        Close();
        return false;
    }
    
    return true;
}

void GGUFTensorLoader::Close() {
    UnmapFile();
    tensors_.clear();
    gguf_version_ = 0;
}

// ============================================================================
// Platform-Specific File Mapping
// ============================================================================

#ifdef _WIN32

bool GGUFTensorLoader::MapFile(const std::string& path) {
    file_handle_ = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (file_handle_ == INVALID_HANDLE_VALUE) {
        last_error_ = "Failed to open file: " + path;
        return false;
    }
    
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file_handle_, &size)) {
        last_error_ = "Failed to get file size";
        CloseHandle(file_handle_);
        file_handle_ = nullptr;
        return false;
    }
    
    file_size_ = static_cast<size_t>(size.QuadPart);
    
    map_handle_ = CreateFileMapping(
        file_handle_,
        nullptr,
        PAGE_READONLY,
        0,
        0,
        nullptr
    );
    
    if (!map_handle_) {
        last_error_ = "Failed to create file mapping";
        CloseHandle(file_handle_);
        file_handle_ = nullptr;
        return false;
    }
    
    file_data_ = MapViewOfFile(map_handle_, FILE_MAP_READ, 0, 0, 0);
    
    if (!file_data_) {
        last_error_ = "Failed to map view of file";
        CloseHandle(map_handle_);
        CloseHandle(file_handle_);
        map_handle_ = nullptr;
        file_handle_ = nullptr;
        return false;
    }
    
    return true;
}

void GGUFTensorLoader::UnmapFile() {
    if (file_data_) {
        UnmapViewOfFile(file_data_);
        file_data_ = nullptr;
    }
    if (map_handle_) {
        CloseHandle(map_handle_);
        map_handle_ = nullptr;
    }
    if (file_handle_) {
        CloseHandle(file_handle_);
        file_handle_ = nullptr;
    }
    file_size_ = 0;
}

#else  // POSIX

bool GGUFTensorLoader::MapFile(const std::string& path) {
    file_fd_ = open(path.c_str(), O_RDONLY);
    if (file_fd_ < 0) {
        last_error_ = "Failed to open file: " + path;
        return false;
    }
    
    struct stat st;
    if (fstat(file_fd_, &st) < 0) {
        last_error_ = "Failed to get file size";
        close(file_fd_);
        file_fd_ = -1;
        return false;
    }
    
    file_size_ = st.st_size;
    
    file_data_ = mmap(nullptr, file_size_, PROT_READ, MAP_PRIVATE, file_fd_, 0);
    if (file_data_ == MAP_FAILED) {
        last_error_ = "Failed to mmap file";
        close(file_fd_);
        file_fd_ = -1;
        file_data_ = nullptr;
        return false;
    }
    
    return true;
}

void GGUFTensorLoader::UnmapFile() {
    if (file_data_) {
        munmap(file_data_, file_size_);
        file_data_ = nullptr;
    }
    if (file_fd_ >= 0) {
        close(file_fd_);
        file_fd_ = -1;
    }
    file_size_ = 0;
}

#endif

// ============================================================================
// GGUF Parsing
// ============================================================================

bool GGUFTensorLoader::ParseHeader() {
    if (!file_data_ || file_size_ < 64) {
        last_error_ = "File too small";
        return false;
    }
    
    const uint8_t* ptr = static_cast<const uint8_t*>(file_data_);
    const uint8_t* end = ptr + file_size_;
    
    // Magic
    uint32_t magic;
    std::memcpy(&magic, ptr, sizeof(magic));
    ptr += sizeof(magic);
    
    if (magic != GGUF_MAGIC) {
        last_error_ = "Invalid GGUF magic";
        return false;
    }
    
    // Version
    std::memcpy(&gguf_version_, ptr, sizeof(gguf_version_));
    ptr += sizeof(gguf_version_);
    
    if (gguf_version_ != 3) {
        last_error_ = "Unsupported GGUF version: " + std::to_string(gguf_version_);
        return false;
    }
    
    // Tensor count
    uint64_t tensor_count;
    std::memcpy(&tensor_count, ptr, sizeof(tensor_count));
    ptr += sizeof(tensor_count);
    
    // Metadata count (skip for now)
    uint64_t metadata_count;
    std::memcpy(&metadata_count, ptr, sizeof(metadata_count));
    ptr += sizeof(metadata_count);
    
    // Skip metadata (simplified - would parse in full implementation)
    for (uint64_t i = 0; i < metadata_count && ptr < end; ++i) {
        // Read key length and key
        uint64_t key_len;
        std::memcpy(&key_len, ptr, sizeof(key_len));
        ptr += sizeof(key_len) + key_len;
        
        // Read value type
        uint32_t value_type;
        std::memcpy(&value_type, ptr, sizeof(value_type));
        ptr += sizeof(value_type);
        
        // Skip value based on type
        // (simplified - just skip for now)
        ptr += 8;  // Rough skip
    }
    
    // Parse tensor info
    tensors_.reserve(tensor_count);
    
    for (uint64_t i = 0; i < tensor_count && ptr < end; ++i) {
        TensorMetadata meta;
        
        // Name
        uint64_t name_len;
        std::memcpy(&name_len, ptr, sizeof(name_len));
        ptr += sizeof(name_len);
        meta.name = std::string(reinterpret_cast<const char*>(ptr), name_len);
        ptr += name_len;
        
        // Dimensions
        uint32_t n_dims;
        std::memcpy(&n_dims, ptr, sizeof(n_dims));
        ptr += sizeof(n_dims);
        
        meta.shape.resize(n_dims);
        for (uint32_t d = 0; d < n_dims; ++d) {
            std::memcpy(&meta.shape[d], ptr, sizeof(uint64_t));
            ptr += sizeof(uint64_t);
        }
        
        // Type
        std::memcpy(&meta.type, ptr, sizeof(meta.type));
        ptr += sizeof(meta.type);
        
        // Offset
        std::memcpy(&meta.offset, ptr, sizeof(meta.offset));
        ptr += sizeof(meta.offset);
        
        // Calculate size
        meta.size = GetTensorSize(meta.type, meta.shape);
        
        tensors_.push_back(std::move(meta));
    }
    
    return true;
}

size_t GetTensorSize(uint32_t type, const std::vector<uint64_t>& shape) {
    uint64_t num_elements = 1;
    for (auto dim : shape) {
        num_elements *= dim;
    }
    
    switch (static_cast<GGMLType>(type)) {
        case GGMLType::F32:  return num_elements * 4;
        case GGMLType::F16:  return num_elements * 2;
        case GGMLType::Q4_0: return ((num_elements + 31) / 32) * (2 + 16);  // 32 elements per block
        case GGMLType::Q4_1: return ((num_elements + 31) / 32) * (2 + 2 + 16);
        case GGMLType::Q5_0: return ((num_elements + 31) / 32) * (2 + 20);
        case GGMLType::Q5_1: return ((num_elements + 31) / 32) * (2 + 2 + 20);
        case GGMLType::Q8_0: return ((num_elements + 31) / 32) * (2 + 32);
        case GGMLType::Q8_1: return ((num_elements + 31) / 32) * (2 + 2 + 32);
        default:             return num_elements * 4;  // Assume F32
    }
}

// ============================================================================
// Tensor Access
// ============================================================================

TensorView GGUFTensorLoader::GetTensor(const std::string& name) const {
    for (const auto& meta : tensors_) {
        if (meta.name == name) {
            TensorView view;
            view.data = static_cast<const uint8_t*>(file_data_) + meta.offset;
            view.size = meta.size;
            view.type = meta.type;
            view.shape = meta.shape;
            return view;
        }
    }
    return TensorView{};
}

bool GGUFTensorLoader::HasTensor(const std::string& name) const {
    for (const auto& meta : tensors_) {
        if (meta.name == name) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> GGUFTensorLoader::ListTensors() const {
    std::vector<std::string> names;
    names.reserve(tensors_.size());
    for (const auto& meta : tensors_) {
        names.push_back(meta.name);
    }
    return names;
}

std::vector<float> GGUFTensorLoader::GetTensorF32(const std::string& name, bool* success) const {
    auto view = GetTensor(name);
    if (!view.IsValid()) {
        if (success) *success = false;
        return {};
    }
    
    auto result = Dequantize(view.data, view.size, view.type, view.GetElementCount());
    if (success) *success = !result.empty();
    return result;
}

std::vector<uint8_t> GGUFTensorLoader::GetTensorRaw(const std::string& name, bool* success) const {
    auto view = GetTensor(name);
    if (!view.IsValid()) {
        if (success) *success = false;
        return {};
    }
    
    const uint8_t* data = static_cast<const uint8_t*>(view.data);
    if (success) *success = true;
    return std::vector<uint8_t>(data, data + view.size);
}

// ============================================================================
// Dequantization
// ============================================================================

QuantizationInfo GGUFTensorLoader::GetQuantizationInfo(uint32_t type) {
    QuantizationInfo info;
    info.type = type;
    
    switch (static_cast<GGMLType>(type)) {
        case GGMLType::F32:
            info.block_size = 1;
            info.scale_size = 0;
            info.block_bytes = 4;
            break;
        case GGMLType::F16:
            info.block_size = 1;
            info.scale_size = 0;
            info.block_bytes = 2;
            break;
        case GGMLType::Q4_0:
            info.block_size = 32;
            info.scale_size = 2;  // F16 scale
            info.block_bytes = 2 + 16;  // scale + 32 nibbles
            break;
        case GGMLType::Q4_1:
            info.block_size = 32;
            info.scale_size = 2;
            info.block_bytes = 2 + 2 + 16;  // scale + min + 32 nibbles
            break;
        case GGMLType::Q8_0:
            info.block_size = 32;
            info.scale_size = 2;  // F16 scale
            info.block_bytes = 2 + 32;  // scale + 32 int8 values
            break;
        default:
            info.block_size = 1;
            info.scale_size = 0;
            info.block_bytes = 4;
            break;
    }
    
    return info;
}

std::vector<float> GGUFTensorLoader::Dequantize(
    const void* data,
    size_t size,
    uint32_t type,
    uint64_t num_elements) {
    
    std::vector<float> result;
    result.reserve(num_elements);
    
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    
    switch (static_cast<GGMLType>(type)) {
        case GGMLType::F32: {
            const float* f32_data = static_cast<const float*>(data);
            result.assign(f32_data, f32_data + num_elements);
            break;
        }
        
        case GGMLType::F16: {
            const uint16_t* f16_data = static_cast<const uint16_t*>(data);
            for (uint64_t i = 0; i < num_elements; ++i) {
                uint16_t h = f16_data[i];
                // F16 to F32 conversion
                uint32_t sign = (h & 0x8000) << 16;
                uint32_t exponent = ((h & 0x7C00) + 0x1C000) << 13;
                uint32_t mantissa = (h & 0x03FF) << 13;
                uint32_t f32 = sign | exponent | mantissa;
                float val;
                std::memcpy(&val, &f32, sizeof(float));
                result.push_back(val);
            }
            break;
        }
        
        case GGMLType::Q4_0: {
            uint64_t num_blocks = (num_elements + 31) / 32;
            for (uint64_t b = 0; b < num_blocks; ++b) {
                // Read F16 scale
                uint16_t scale_h;
                std::memcpy(&scale_h, ptr + b * 18, sizeof(scale_h));
                float scale = F16ToF32(scale_h);
                
                // Read 32 nibbles
                for (int i = 0; i < 32 && result.size() < num_elements; ++i) {
                    uint8_t byte = ptr[b * 18 + 2 + i / 2];
                    int8_t nibble = (i % 2 == 0) ? (byte & 0x0F) : ((byte >> 4) & 0x0F);
                    if (nibble & 0x08) nibble |= 0xF0;  // Sign extend
                    result.push_back(scale * static_cast<float>(nibble));
                }
            }
            break;
        }
        
        case GGMLType::Q8_0: {
            uint64_t num_blocks = (num_elements + 31) / 32;
            for (uint64_t b = 0; b < num_blocks; ++b) {
                // Read F16 scale
                uint16_t scale_h;
                std::memcpy(&scale_h, ptr + b * 34, sizeof(scale_h));
                float scale = F16ToF32(scale_h);
                
                // Read 32 int8 values
                for (int i = 0; i < 32 && result.size() < num_elements; ++i) {
                    int8_t val = static_cast<int8_t>(ptr[b * 34 + 2 + i]);
                    result.push_back(scale * static_cast<float>(val));
                }
            }
            break;
        }
        
        default:
            // Return zeros for unsupported types
            result.resize(num_elements, 0.0f);
            break;
    }
    
    return result;
}

// Forward declaration
static float F16ToF32(uint16_t h);

size_t GetTensorSize(uint32_t type, const std::vector<uint64_t>& shape) {
    uint64_t num_elements = 1;
    for (auto dim : shape) {
        num_elements *= dim;
    }
    
    switch (static_cast<GGMLType>(type)) {
        case GGMLType::F32:  return num_elements * 4;
        case GGMLType::F16:  return num_elements * 2;
        case GGMLType::Q4_0: return ((num_elements + 31) / 32) * (2 + 16);  // 32 elements per block
        case GGMLType::Q4_1: return ((num_elements + 31) / 32) * (2 + 2 + 16);
        case GGMLType::Q5_0: return ((num_elements + 31) / 32) * (2 + 20);
        case GGMLType::Q5_1: return ((num_elements + 31) / 32) * (2 + 2 + 20);
        case GGMLType::Q8_0: return ((num_elements + 31) / 32) * (2 + 32);
        case GGMLType::Q8_1: return ((num_elements + 31) / 32) * (2 + 2 + 32);
        default:             return num_elements * 4;  // Assume F32
    }
}

// Helper: F16 to F32 conversion
static float F16ToF32(uint16_t h) {
    uint32_t sign = (h & 0x8000) << 16;
    uint32_t exponent = ((h & 0x7C00) + 0x1C000) << 13;
    uint32_t mantissa = (h & 0x03FF) << 13;
    uint32_t f32 = sign | exponent | mantissa;
    float val;
    std::memcpy(&val, &f32, sizeof(float));
    return val;
}

// ============================================================================
// Convenience Functions
// ============================================================================

std::vector<float> LoadTensorF32(
    const std::string& gguf_path,
    const std::string& tensor_name,
    std::string* error) {
    
    GGUFTensorLoader loader;
    if (!loader.Open(gguf_path)) {
        if (error) *error = loader.GetLastError();
        return {};
    }
    
    bool success;
    auto result = loader.GetTensorF32(tensor_name, &success);
    if (!success && error) {
        *error = "Tensor not found: " + tensor_name;
    }
    
    return result;
}

std::map<std::string, std::vector<float>> LoadTensorsF32(
    const std::string& gguf_path,
    const std::vector<std::string>& tensor_names,
    std::string* error) {
    
    GGUFTensorLoader loader;
    if (!loader.Open(gguf_path)) {
        if (error) *error = loader.GetLastError();
        return {};
    }
    
    std::map<std::string, std::vector<float>> result;
    
    for (const auto& name : tensor_names) {
        bool success;
        auto tensor = loader.GetTensorF32(name, &success);
        if (success) {
            result[name] = std::move(tensor);
        }
    }
    
    return result;
}

std::vector<std::string> GetTransformerWeightNames(uint32_t layer_idx) {
    std::vector<std::string> names;
    std::string prefix = "blk." + std::to_string(layer_idx) + ".";
    
    // Attention weights
    names.push_back(prefix + "attn_q.weight");
    names.push_back(prefix + "attn_k.weight");
    names.push_back(prefix + "attn_v.weight");
    names.push_back(prefix + "attn_output.weight");
    
    // FFN weights
    names.push_back(prefix + "ffn_gate.weight");
    names.push_back(prefix + "ffn_up.weight");
    names.push_back(prefix + "ffn_down.weight");
    
    // Normalization
    names.push_back(prefix + "attn_norm.weight");
    names.push_back(prefix + "ffn_norm.weight");
    
    return names;
}

std::vector<std::string> GetAllTransformerWeightNames(uint32_t num_layers) {
    std::vector<std::string> all_names;
    
    for (uint32_t i = 0; i < num_layers; ++i) {
        auto layer_names = GetTransformerWeightNames(i);
        all_names.insert(all_names.end(), layer_names.begin(), layer_names.end());
    }
    
    // Output weights
    all_names.push_back("output.weight");
    all_names.push_back("token_embd.weight");
    
    return all_names;
}

} // namespace runtime
} // namespace rawrxd
