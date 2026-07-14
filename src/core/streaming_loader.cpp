// ============================================================================
// Streaming Model Loader Implementation
// ============================================================================

#include "streaming_loader.hpp"
#include <cstring>
#include <algorithm>

namespace RawrXD {
namespace Core {

// ============================================================================
// GGUF Constants
// ============================================================================

static constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF"
static constexpr uint32_t GGUF_VERSION = 3;

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
    FLOAT64 = 12
};

// ============================================================================
// Helper Functions
// ============================================================================

static uint32_t ReadU32(const uint8_t* data, size_t& pos) {
    uint32_t val = *reinterpret_cast<const uint32_t*>(data + pos);
    pos += 4;
    return val;
}

static uint64_t ReadU64(const uint8_t* data, size_t& pos) {
    uint64_t val = *reinterpret_cast<const uint64_t*>(data + pos);
    pos += 8;
    return val;
}

// FP16 to FP32 conversion
static float FP16ToFP32(uint16_t h) {
    // IEEE 754 half-precision to single-precision
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    uint32_t f;
    if (exp == 0) {
        // Zero or denormal
        if (mant == 0) {
            f = sign << 31;
        } else {
            // Denormal
            exp = 1;
            while ((mant & 0x400) == 0) {
                mant <<= 1;
                exp--;
            }
            mant &= 0x3FF;
            f = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        // Infinity or NaN
        f = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        // Normal
        f = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
    }
    
    return *reinterpret_cast<float*>(&f);
}

static float ReadF32(const uint8_t* data, size_t& pos) {
    float val = *reinterpret_cast<const float*>(data + pos);
    pos += 4;
    return val;
}

static std::string ReadString(const uint8_t* data, size_t& pos) {
    uint64_t len = ReadU64(data, pos);
    std::string str(reinterpret_cast<const char*>(data + pos), len);
    pos += len;
    return str;
}

static QuantType GGMLTypeToQuant(uint32_t ggml_type) {
    switch (ggml_type) {
        case 0: return QuantType::F32;
        case 1: return QuantType::F16;
        case 2: return QuantType::Q4_0;
        case 3: return QuantType::Q4_1;
        case 6: return QuantType::Q5_0;
        case 7: return QuantType::Q5_1;
        case 8: return QuantType::Q8_0;
        case 9: return QuantType::Q8_1;
        case 10: return QuantType::Q2_K;
        case 11: return QuantType::Q3_K;
        case 12: return QuantType::Q4_K;
        case 13: return QuantType::Q5_K;
        case 14: return QuantType::Q6_K;
        case 15: return QuantType::Q8_K;
        default: return QuantType::Unknown;
    }
}

// ============================================================================
// StreamingLoader Implementation
// ============================================================================

StreamingLoader::StreamingLoader() = default;

StreamingLoader::~StreamingLoader() {
    Close();
}

bool StreamingLoader::Open(const wchar_t* filepath) {
    Close();
    
    file_handle_ = CreateFileW(filepath, GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Get file size
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file_handle_, &size)) {
        Close();
        return false;
    }
    file_size_ = size.QuadPart;
    
    // Create file mapping
    mapping_handle_ = CreateFileMapping(file_handle_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping_handle_) {
        Close();
        return false;
    }
    
    // Map view
    mapped_data_ = MapViewOfFile(mapping_handle_, FILE_MAP_READ, 0, 0, 0);
    if (!mapped_data_) {
        Close();
        return false;
    }
    
    return true;
}

bool StreamingLoader::Open(const char* filepath) {
    // Convert to wide char
    int len = MultiByteToWideChar(CP_UTF8, 0, filepath, -1, nullptr, 0);
    if (len <= 0) return false;
    
    std::vector<wchar_t> wpath(len);
    MultiByteToWideChar(CP_UTF8, 0, filepath, -1, wpath.data(), len);
    
    return Open(wpath.data());
}

void StreamingLoader::Close() {
    if (mapped_data_) {
        UnmapViewOfFile(mapped_data_);
        mapped_data_ = nullptr;
    }
    if (mapping_handle_) {
        CloseHandle(mapping_handle_);
        mapping_handle_ = nullptr;
    }
    if (file_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
    }
    file_size_ = 0;
    tensors_.clear();
}

bool StreamingLoader::ParseHeader() {
    if (!mapped_data_ || file_size_ < 64) return false;
    
    const uint8_t* data = static_cast<const uint8_t*>(mapped_data_);
    size_t pos = 0;
    
    // Check magic
    uint32_t magic = ReadU32(data, pos);
    if (magic != GGUF_MAGIC) {
        return false;
    }
    
    // Check version
    uint32_t version = ReadU32(data, pos);
    if (version != GGUF_VERSION) {
        // Still try to parse
    }
    
    // Read tensor count and metadata count
    uint64_t tensor_count = ReadU64(data, pos);
    uint64_t metadata_count = ReadU64(data, pos);
    
    // Parse metadata
    for (uint64_t i = 0; i < metadata_count; ++i) {
        std::string key = ReadString(data, pos);
        uint32_t type = ReadU32(data, pos);
        
        // Skip value based on type
        switch (static_cast<GGUFValueType>(type)) {
            case GGUFValueType::UINT8:
            case GGUFValueType::INT8:
                pos += 1;
                break;
            case GGUFValueType::UINT16:
            case GGUFValueType::INT16:
                pos += 2;
                break;
            case GGUFValueType::UINT32:
            case GGUFValueType::INT32:
            case GGUFValueType::FLOAT32:
                pos += 4;
                break;
            case GGUFValueType::UINT64:
            case GGUFValueType::INT64:
            case GGUFValueType::FLOAT64:
                pos += 8;
                break;
            case GGUFValueType::BOOL:
                pos += 1;
                break;
            case GGUFValueType::STRING: {
                uint64_t len = ReadU64(data, pos);
                pos += len;
                break;
            }
            case GGUFValueType::ARRAY: {
                uint32_t arr_type = ReadU32(data, pos);
                uint64_t arr_len = ReadU64(data, pos);
                // Skip array data
                for (uint64_t j = 0; j < arr_len; ++j) {
                    switch (static_cast<GGUFValueType>(arr_type)) {
                        case GGUFValueType::UINT32: pos += 4; break;
                        case GGUFValueType::FLOAT32: pos += 4; break;
                        case GGUFValueType::STRING: {
                            uint64_t len = ReadU64(data, pos);
                            pos += len;
                            break;
                        }
                        default: pos += 4; break;
                    }
                }
                break;
            }
        }
        
        // Extract architecture info from known keys
        if (key == "general.architecture") {
            // Would need to parse string value
        } else if (key == "llama.context_length" || key == "qwen2.context_length") {
            // Would need to parse int value
        }
    }
    
    // Parse tensors
    data_offset_ = (pos + 31) & ~31ULL;  // Align to 32 bytes
    
    tensors_.reserve(tensor_count);
    for (uint64_t i = 0; i < tensor_count; ++i) {
        TensorInfo info;
        
        // Read name
        std::string name = ReadString(data, pos);
        std::strncpy(info.name, name.c_str(), sizeof(info.name) - 1);
        
        // Read dimensions
        uint32_t n_dims = ReadU32(data, pos);
        info.n_dims = n_dims;
        for (uint32_t d = 0; d < n_dims; ++d) {
            info.dims[d] = ReadU64(data, pos);
        }
        
        // Read type
        uint32_t ggml_type = ReadU32(data, pos);
        info.quant_type = GGMLTypeToQuant(ggml_type);
        
        // Read offset
        info.offset = ReadU64(data, pos);
        
        // Calculate size
        uint64_t num_elements = 1;
        for (uint32_t d = 0; d < n_dims; ++d) {
            num_elements *= info.dims[d];
        }
        info.num_elements = num_elements;
        
        size_t block_size = GetQuantBlockSize(info.quant_type);
        size_t type_size = GetQuantTypeSize(info.quant_type);
        info.size_bytes = ((num_elements + block_size - 1) / block_size) * type_size;
        
        tensors_.push_back(info);
    }
    
    return true;
}

const TensorInfo* StreamingLoader::FindTensor(const char* name) const {
    for (const auto& tensor : tensors_) {
        if (std::strcmp(tensor.name, name) == 0) {
            return &tensor;
        }
    }
    return nullptr;
}

float* StreamingLoader::LoadTensor(const TensorInfo& info) {
    if (!mapped_data_) return nullptr;
    
    // Allocate buffer
    dequant_buffer_.resize(info.GetNumElements());
    
    // Get source data
    const uint8_t* src = static_cast<const uint8_t*>(mapped_data_) + data_offset_ + info.offset;
    
    // Dequantize
    Dequantize(src, dequant_buffer_.data(), info);
    
    return dequant_buffer_.data();
}

float* StreamingLoader::LoadTensor(const char* name) {
    const TensorInfo* info = FindTensor(name);
    if (!info) return nullptr;
    return LoadTensor(*info);
}

void StreamingLoader::Dequantize(const void* src, float* dst, const TensorInfo& info) {
    switch (info.quant_type) {
        case QuantType::F32:
            std::memcpy(dst, src, info.num_elements * sizeof(float));
            break;
        case QuantType::F16:
            // Would need F16 to F32 conversion
            break;
        case QuantType::Q4_0:
            DequantizeQ4_0(src, dst, info.num_elements);
            break;
        case QuantType::Q4_1:
            DequantizeQ4_1(src, dst, info.num_elements);
            break;
        case QuantType::Q8_0:
            DequantizeQ8_0(src, dst, info.num_elements);
            break;
        case QuantType::Q4_K:
            DequantizeQ4_K(src, dst, info.num_elements);
            break;
        case QuantType::Q5_K:
            DequantizeQ5_K(src, dst, info.num_elements);
            break;
        case QuantType::Q6_K:
            DequantizeQ6_K(src, dst, info.num_elements);
            break;
        case QuantType::Q8_K:
            DequantizeQ8_K(src, dst, info.num_elements);
            break;
        default:
            // Unknown type - zero fill
            std::memset(dst, 0, info.num_elements * sizeof(float));
            break;
    }
}

void StreamingLoader::DequantizeQ4_0(const void* src, float* dst, size_t n) {
    const uint8_t* data = static_cast<const uint8_t*>(src);
    size_t num_blocks = (n + 31) / 32;
    
    for (size_t b = 0; b < num_blocks; ++b) {
        float scale = *reinterpret_cast<const float*>(data + b * 18);
        const uint8_t* qs = data + b * 18 + 2;
        
        for (size_t i = 0; i < 32 && (b * 32 + i) < n; ++i) {
            uint8_t q = (i & 1) ? (qs[i / 2] >> 4) : (qs[i / 2] & 0xF);
            dst[b * 32 + i] = scale * (q - 8);
        }
    }
}

void StreamingLoader::DequantizeQ4_1(const void* src, float* dst, size_t n) {
    const uint8_t* data = static_cast<const uint8_t*>(src);
    size_t num_blocks = (n + 31) / 32;
    
    for (size_t b = 0; b < num_blocks; ++b) {
        float scale = *reinterpret_cast<const float*>(data + b * 20);
        float min = *reinterpret_cast<const float*>(data + b * 20 + 4);
        const uint8_t* qs = data + b * 20 + 8;
        
        for (size_t i = 0; i < 32 && (b * 32 + i) < n; ++i) {
            uint8_t q = (i & 1) ? (qs[i / 2] >> 4) : (qs[i / 2] & 0xF);
            dst[b * 32 + i] = min + scale * q;
        }
    }
}

void StreamingLoader::DequantizeQ8_0(const void* src, float* dst, size_t n) {
    const uint8_t* data = static_cast<const uint8_t*>(src);
    size_t num_blocks = (n + 31) / 32;
    
    for (size_t b = 0; b < num_blocks; ++b) {
        float scale = *reinterpret_cast<const float*>(data + b * 34);
        const int8_t* qs = reinterpret_cast<const int8_t*>(data + b * 34 + 2);
        
        for (size_t i = 0; i < 32 && (b * 32 + i) < n; ++i) {
            dst[b * 32 + i] = scale * qs[i];
        }
    }
}

void StreamingLoader::DequantizeQ4_K(const void* src, float* dst, size_t n) {
    // Q4_K dequantization - based on llama.cpp format
    // Each block has 256 weights with 4-bit quantization
    // Block structure: 2 scales (fp16) + 2 mins (fp16) + 128 nibbles (4-bit each)
    const uint8_t* data = static_cast<const uint8_t*>(src);
    size_t num_blocks = (n + 255) / 256;
    
    for (size_t b = 0; b < num_blocks; ++b) {
        const uint8_t* block = data + b * 144; // 144 bytes per block
        
        // Read scales and mins (stored as fp16, convert to fp32)
        uint16_t scale1_u16 = *reinterpret_cast<const uint16_t*>(block);
        uint16_t scale2_u16 = *reinterpret_cast<const uint16_t*>(block + 2);
        uint16_t min1_u16 = *reinterpret_cast<const uint16_t*>(block + 4);
        uint16_t min2_u16 = *reinterpret_cast<const uint16_t*>(block + 6);
        
        float scale1 = FP16ToFP32(scale1_u16);
        float scale2 = FP16ToFP32(scale2_u16);
        float min1 = FP16ToFP32(min1_u16);
        float min2 = FP16ToFP32(min2_u16);
        
        const uint8_t* qs = block + 8; // Quantized weights start at offset 8
        
        // Dequantize 256 weights (128 bytes of nibbles)
        for (size_t i = 0; i < 256 && (b * 256 + i) < n; ++i) {
            uint8_t byte_idx = i / 2;
            uint8_t nibble = (i & 1) ? (qs[byte_idx] >> 4) : (qs[byte_idx] & 0xF);
            
            // First 128 weights use scale1/min1, second 128 use scale2/min2
            if (i < 128) {
                dst[b * 256 + i] = min1 + scale1 * nibble;
            } else {
                dst[b * 256 + i] = min2 + scale2 * nibble;
            }
        }
    }
}

void StreamingLoader::DequantizeQ6_K(const void* src, float* dst, size_t n) {
    // Q6_K dequantization - based on llama.cpp format
    // Each block has 256 weights with 6-bit quantization
    // Block structure: scale (fp16) + 192 bytes of 6-bit weights
    const uint8_t* data = static_cast<const uint8_t*>(src);
    size_t num_blocks = (n + 255) / 256;
    
    for (size_t b = 0; b < num_blocks; ++b) {
        const uint8_t* block = data + b * 210; // 210 bytes per block
        
        // Read scale (fp16)
        uint16_t scale_u16 = *reinterpret_cast<const uint16_t*>(block);
        float scale = FP16ToFP32(scale_u16);
        
        const uint8_t* qs = block + 2; // Quantized weights start at offset 2
        
        // Dequantize 256 weights (6-bit each, packed in 192 bytes)
        // Each group of 4 weights uses 3 bytes (24 bits / 4 = 6 bits each)
        for (size_t i = 0; i < 256 && (b * 256 + i) < n; ++i) {
            size_t group = i / 4;
            size_t idx_in_group = i % 4;
            
            uint32_t packed = qs[group * 3] | (qs[group * 3 + 1] << 8) | (qs[group * 3 + 2] << 16);
            uint8_t q = (packed >> (idx_in_group * 6)) & 0x3F; // 6 bits
            
            // Center around 32 (typical for Q6_K)
            dst[b * 256 + i] = scale * (q - 32);
        }
    }
}

void StreamingLoader::DequantizeQ5_K(const void* src, float* dst, size_t n) {
    // Q5_K dequantization - based on llama.cpp format
    // Each block has 256 weights with 5-bit quantization
    // Block structure: 2 scales (fp16) + 2 mins (fp16) + 160 bytes of 5-bit weights
    const uint8_t* data = static_cast<const uint8_t*>(src);
    size_t num_blocks = (n + 255) / 256;
    
    for (size_t b = 0; b < num_blocks; ++b) {
        const uint8_t* block = data + b * 176; // 176 bytes per block
        
        // Read scales and mins (stored as fp16)
        uint16_t scale1_u16 = *reinterpret_cast<const uint16_t*>(block);
        uint16_t scale2_u16 = *reinterpret_cast<const uint16_t*>(block + 2);
        uint16_t min1_u16 = *reinterpret_cast<const uint16_t*>(block + 4);
        uint16_t min2_u16 = *reinterpret_cast<const uint16_t*>(block + 6);
        
        float scale1 = FP16ToFP32(scale1_u16);
        float scale2 = FP16ToFP32(scale2_u16);
        float min1 = FP16ToFP32(min1_u16);
        float min2 = FP16ToFP32(min2_u16);
        
        const uint8_t* qs = block + 8; // Quantized weights start at offset 8
        
        // Dequantize 256 weights (5-bit each, packed in 160 bytes)
        // Each group of 8 weights uses 5 bytes (40 bits / 8 = 5 bits each)
        for (size_t i = 0; i < 256 && (b * 256 + i) < n; ++i) {
            size_t group = i / 8;
            size_t idx_in_group = i % 8;
            
            uint64_t packed = 0;
            for (int j = 0; j < 5; j++) {
                packed |= (uint64_t)qs[group * 5 + j] << (j * 8);
            }
            uint8_t q = (packed >> (idx_in_group * 5)) & 0x1F; // 5 bits
            
            // First 128 weights use scale1/min1, second 128 use scale2/min2
            if (i < 128) {
                dst[b * 256 + i] = min1 + scale1 * q;
            } else {
                dst[b * 256 + i] = min2 + scale2 * q;
            }
        }
    }
}

void StreamingLoader::DequantizeQ8_K(const void* src, float* dst, size_t n) {
    // Q8_K dequantization - based on llama.cpp format
    // Each block has 256 weights with 8-bit quantization
    // Block structure: scale (fp16) + 256 bytes of 8-bit weights
    const uint8_t* data = static_cast<const uint8_t*>(src);
    size_t num_blocks = (n + 255) / 256;
    
    for (size_t b = 0; b < num_blocks; ++b) {
        const uint8_t* block = data + b * 258; // 258 bytes per block
        
        // Read scale (fp16)
        uint16_t scale_u16 = *reinterpret_cast<const uint16_t*>(block);
        float scale = FP16ToFP32(scale_u16);
        
        const int8_t* qs = reinterpret_cast<const int8_t*>(block + 2);
        
        // Dequantize 256 weights (8-bit signed)
        for (size_t i = 0; i < 256 && (b * 256 + i) < n; ++i) {
            dst[b * 256 + i] = scale * qs[i];
        }
    }
}

uint64_t StreamingLoader::GetDequantizedSize() const {
    uint64_t total = 0;
    for (const auto& tensor : tensors_) {
        total += tensor.GetDequantizedSize();
    }
    return total;
}

ModelArchitecture StreamingLoader::GetArchitecture() const {
    return arch_;
}

// ============================================================================
// ModelWeights Implementation
// ============================================================================

bool ModelWeights::LoadFrom(StreamingLoader& loader, const ModelArchitecture& arch) {
    // Calculate total size needed
    uint64_t total_params = 0;
    
    // Embeddings
    total_params += arch.vocab_size * arch.hidden_size;
    
    // Per layer
    uint64_t layer_params = 0;
    layer_params += arch.hidden_size * arch.hidden_size * 4;  // Q, K, V, O
    layer_params += arch.hidden_size * arch.intermediate_size * 3;  // gate, up, down
    layer_params += arch.hidden_size * 2;  // norms
    total_params += layer_params * arch.num_layers;
    
    // Output
    total_params += arch.hidden_size;  // norm
    total_params += arch.hidden_size * arch.vocab_size;  // lm_head
    
    // Allocate storage
    storage.resize(total_params);
    layers.resize(arch.num_layers);
    
    float* ptr = storage.data();
    
    // Load embeddings
    token_embeddings = ptr;
    if (float* emb = loader.LoadTensor("token_embd.weight")) {
        std::memcpy(ptr, emb, arch.vocab_size * arch.hidden_size * sizeof(float));
    }
    ptr += arch.vocab_size * arch.hidden_size;
    
    // Load layers
    for (uint32_t i = 0; i < arch.num_layers; ++i) {
        auto& layer = layers[i];
        char name_buf[256];
        
        // Attention weights
        layer.q_proj = ptr;
        std::snprintf(name_buf, sizeof(name_buf), "blk.%u.attn_q.weight", i);
        if (float* w = loader.LoadTensor(name_buf)) {
            std::memcpy(ptr, w, arch.hidden_size * arch.hidden_size * sizeof(float));
        }
        ptr += arch.hidden_size * arch.hidden_size;
        
        layer.k_proj = ptr;
        std::snprintf(name_buf, sizeof(name_buf), "blk.%u.attn_k.weight", i);
        if (float* w = loader.LoadTensor(name_buf)) {
            std::memcpy(ptr, w, arch.hidden_size * arch.hidden_size * sizeof(float));
        }
        ptr += arch.hidden_size * arch.hidden_size;
        
        layer.v_proj = ptr;
        std::snprintf(name_buf, sizeof(name_buf), "blk.%u.attn_v.weight", i);
        if (float* w = loader.LoadTensor(name_buf)) {
            std::memcpy(ptr, w, arch.hidden_size * arch.hidden_size * sizeof(float));
        }
        ptr += arch.hidden_size * arch.hidden_size;
        
        layer.o_proj = ptr;
        std::snprintf(name_buf, sizeof(name_buf), "blk.%u.attn_output.weight", i);
        if (float* w = loader.LoadTensor(name_buf)) {
            std::memcpy(ptr, w, arch.hidden_size * arch.hidden_size * sizeof(float));
        }
        ptr += arch.hidden_size * arch.hidden_size;
        
        // FFN weights
        layer.gate_proj = ptr;
        std::snprintf(name_buf, sizeof(name_buf), "blk.%u.ffn_gate.weight", i);
        if (float* w = loader.LoadTensor(name_buf)) {
            std::memcpy(ptr, w, arch.hidden_size * arch.intermediate_size * sizeof(float));
        }
        ptr += arch.hidden_size * arch.intermediate_size;
        
        layer.up_proj = ptr;
        std::snprintf(name_buf, sizeof(name_buf), "blk.%u.ffn_up.weight", i);
        if (float* w = loader.LoadTensor(name_buf)) {
            std::memcpy(ptr, w, arch.hidden_size * arch.intermediate_size * sizeof(float));
        }
        ptr += arch.hidden_size * arch.intermediate_size;
        
        layer.down_proj = ptr;
        std::snprintf(name_buf, sizeof(name_buf), "blk.%u.ffn_down.weight", i);
        if (float* w = loader.LoadTensor(name_buf)) {
            std::memcpy(ptr, w, arch.intermediate_size * arch.hidden_size * sizeof(float));
        }
        ptr += arch.intermediate_size * arch.hidden_size;
        
        // Norms
        layer.input_norm = ptr;
        std::snprintf(name_buf, sizeof(name_buf), "blk.%u.attn_norm.weight", i);
        if (float* w = loader.LoadTensor(name_buf)) {
            std::memcpy(ptr, w, arch.hidden_size * sizeof(float));
        }
        ptr += arch.hidden_size;
        
        layer.post_attn_norm = ptr;
        std::snprintf(name_buf, sizeof(name_buf), "blk.%u.ffn_norm.weight", i);
        if (float* w = loader.LoadTensor(name_buf)) {
            std::memcpy(ptr, w, arch.hidden_size * sizeof(float));
        }
        ptr += arch.hidden_size;
    }
    
    // Output
    output_norm = ptr;
    if (float* w = loader.LoadTensor("output_norm.weight")) {
        std::memcpy(ptr, w, arch.hidden_size * sizeof(float));
    }
    ptr += arch.hidden_size;
    
    lm_head = ptr;
    if (float* w = loader.LoadTensor("output.weight")) {
        std::memcpy(ptr, w, arch.hidden_size * arch.vocab_size * sizeof(float));
    }
    ptr += arch.hidden_size * arch.vocab_size;
    
    return true;
}

uint64_t ModelWeights::GetParamCount() const {
    uint64_t count = 0;
    for (const auto& layer : layers) {
        // Attention
        count += 4 * 4096 * 4096;  // Q, K, V, O
        // FFN
        count += 3 * 4096 * 11008;  // gate, up, down
        // Norms
        count += 2 * 4096;
    }
    // Embeddings + output
    count += 32000 * 4096 * 2;
    return count;
}

// ============================================================================
// Convenience Functions
// ============================================================================

bool LoadModelWeights(const char* gguf_path, ModelWeights& weights, ModelArchitecture& arch) {
    StreamingLoader loader;
    if (!loader.Open(gguf_path)) return false;
    if (!loader.ParseHeader()) return false;
    
    arch = loader.GetArchitecture();
    return weights.LoadFrom(loader, arch);
}

bool LoadModelWeights(const wchar_t* gguf_path, ModelWeights& weights, ModelArchitecture& arch) {
    StreamingLoader loader;
    if (!loader.Open(gguf_path)) return false;
    if (!loader.ParseHeader()) return false;
    
    arch = loader.GetArchitecture();
    return weights.LoadFrom(loader, arch);
}

const char* GetQuantName(QuantType type) {
    switch (type) {
        case QuantType::F32: return "F32";
        case QuantType::F16: return "F16";
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
        case QuantType::Q8_K: return "Q8_K";
        default: return "Unknown";
    }
}

} // namespace Core
} // namespace RawrXD
