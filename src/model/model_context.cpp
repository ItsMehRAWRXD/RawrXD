/**
 * @file model_context.cpp
 * @brief RawrXD ModelContext Implementation
 *
 * Step C1: GGUF ingestion only.
 *
 * @copyright RawrXD 2026
 */

#include "model_context.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

namespace rawrxd {
namespace model {

// ============================================================================
// GGUF Constants
// ============================================================================

static constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF" in little-endian
static constexpr uint32_t GGUF_VERSION = 3;

// GGML types (subset needed for inspection)
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

// GGUF metadata value types
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
// TensorInfo Implementation
// ============================================================================

std::string TensorInfo::GetTypeName() const {
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

uint64_t TensorInfo::GetElementCount() const {
    uint64_t count = 1;
    for (auto dim : shape) {
        count *= dim;
    }
    return count;
}

// ============================================================================
// Helper Functions
// ============================================================================

static std::string ReadString(std::ifstream& file) {
    uint64_t len;
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    std::string str(len, '\0');
    file.read(str.data(), len);
    return str;
}

template<typename T>
static T ReadValue(std::ifstream& file) {
    T value;
    file.read(reinterpret_cast<char*>(&value), sizeof(T));
    return value;
}

static std::string GetArchitectureName(const std::string& arch_str) {
    // Normalize architecture string
    std::string lower = arch_str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower.find("llama") != std::string::npos) return "llama";
    if (lower.find("qwen") != std::string::npos) return "qwen2";
    if (lower.find("phi") != std::string::npos) return "phi3";
    if (lower.find("gemma") != std::string::npos) return "gemma";
    if (lower.find("mistral") != std::string::npos) return "mistral";
    if (lower.find("mixtral") != std::string::npos) return "mixtral";
    
    return lower.empty() ? "unknown" : lower;
}

static std::string DetectQuantizationType(const std::vector<TensorInfo>& tensors) {
    // Count types
    std::map<uint32_t, int> type_counts;
    for (const auto& t : tensors) {
        type_counts[t.type]++;
    }
    
    // Find most common quantized type
    if (type_counts.empty()) return "unknown";
    
    // Prefer quantized types over F16/F32 for the label
    for (const auto& [type, count] : type_counts) {
        auto gt = static_cast<GGMLType>(type);
        if (gt == GGMLType::Q4_0 || gt == GGMLType::Q4_1 || gt == GGMLType::Q4_K) {
            TensorInfo dummy; dummy.type = type;
            return dummy.GetTypeName();
        }
    }
    
    for (const auto& [type, count] : type_counts) {
        auto gt = static_cast<GGMLType>(type);
        if (gt == GGMLType::Q5_0 || gt == GGMLType::Q5_1 || gt == GGMLType::Q5_K) {
            TensorInfo dummy; dummy.type = type;
            return dummy.GetTypeName();
        }
    }
    
    for (const auto& [type, count] : type_counts) {
        auto gt = static_cast<GGMLType>(type);
        if (gt == GGMLType::Q8_0 || gt == GGMLType::Q8_1 || gt == GGMLType::Q8_K) {
            TensorInfo dummy; dummy.type = type;
            return dummy.GetTypeName();
        }
    }
    
    // Fall back to most common
    auto it = std::max_element(type_counts.begin(), type_counts.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    
    TensorInfo dummy; dummy.type = it->first;
    return dummy.GetTypeName();
}

// ============================================================================
// ModelContext Implementation
// ============================================================================

bool ModelContext::LoadFromFile(const std::string& path) {
    Unload();
    
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    // Read header
    uint32_t magic = ReadValue<uint32_t>(file);
    if (magic != GGUF_MAGIC) {
        return false;
    }
    
    gguf_version_ = ReadValue<uint32_t>(file);
    tensor_count_ = ReadValue<uint64_t>(file);
    metadata_count_ = ReadValue<uint64_t>(file);
    
    // Read metadata
    for (uint64_t i = 0; i < metadata_count_; ++i) {
        std::string key = ReadString(file);
        uint32_t type_val = ReadValue<uint32_t>(file);
        auto value_type = static_cast<GGUFValueType>(type_val);
        
        // Store raw metadata
        std::string value_str;
        
        switch (value_type) {
            case GGUFValueType::UINT8:
            case GGUFValueType::INT8:
            case GGUFValueType::UINT16:
            case GGUFValueType::INT16:
            case GGUFValueType::UINT32:
            case GGUFValueType::INT32:
            case GGUFValueType::UINT64:
            case GGUFValueType::INT64: {
                uint64_t val = 0;
                if (value_type <= GGUFValueType::UINT32) {
                    val = ReadValue<uint32_t>(file);
                } else {
                    val = ReadValue<uint64_t>(file);
                }
                value_str = std::to_string(val);
                
                // Extract architecture info
                if (key == "general.architecture") {
                    // String type, handled below
                } else if (key == "llama.context_length" || key == "qwen2.context_length" ||
                           key == "phi3.context_length" || key == "gemma.context_length") {
                    arch_.context_length = static_cast<uint32_t>(val);
                } else if (key == "llama.block_count" || key == "qwen2.block_count" ||
                           key == "phi3.block_count" || key == "gemma.block_count") {
                    arch_.layer_count = static_cast<uint32_t>(val);
                } else if (key == "llama.embedding_length" || key == "qwen2.embedding_length" ||
                           key == "phi3.embedding_length" || key == "gemma.embedding_length") {
                    arch_.embedding_dim = static_cast<uint32_t>(val);
                } else if (key == "llama.attention.head_count" || key == "qwen2.attention.head_count") {
                    arch_.head_count = static_cast<uint32_t>(val);
                } else if (key == "llama.attention.head_count_kv" || key == "qwen2.attention.head_count_kv") {
                    arch_.kv_head_count = static_cast<uint32_t>(val);
                } else if (key == "llama.vocab_size" || key == "qwen2.vocab_size" ||
                           key == "phi3.vocab_size" || key == "gemma.vocab_size") {
                    arch_.vocab_size = static_cast<uint32_t>(val);
                }
                break;
            }
            case GGUFValueType::FLOAT32:
            case GGUFValueType::FLOAT64: {
                double val = (value_type == GGUFValueType::FLOAT32) ? 
                    ReadValue<float>(file) : ReadValue<double>(file);
                value_str = std::to_string(val);
                break;
            }
            case GGUFValueType::BOOL: {
                uint8_t val = ReadValue<uint8_t>(file);
                value_str = val ? "true" : "false";
                break;
            }
            case GGUFValueType::STRING: {
                value_str = ReadString(file);
                if (key == "general.architecture") {
                    arch_.type = GetArchitectureName(value_str);
                } else if (key == "general.name") {
                    // Model name
                }
                break;
            }
            case GGUFValueType::ARRAY: {
                // Read array type and length
                uint32_t arr_type = ReadValue<uint32_t>(file);
                uint64_t arr_len = ReadValue<uint64_t>(file);
                
                // Handle vocabulary array (tokenizer.ggml.tokens)
                if (key == "tokenizer.ggml.tokens" && arr_type == static_cast<uint32_t>(GGUFValueType::STRING)) {
                    vocabulary_.reserve(arr_len);
                    for (uint64_t j = 0; j < arr_len; ++j) {
                        vocabulary_.push_back(ReadString(file));
                    }
                    value_str = "[vocabulary:" + std::to_string(arr_len) + "]";
                    break;
                }
                
                // Handle merges array (tokenizer.ggml.merges)
                if (key == "tokenizer.ggml.merges" && arr_type == static_cast<uint32_t>(GGUFValueType::STRING)) {
                    merges_.reserve(arr_len);
                    for (uint64_t j = 0; j < arr_len; ++j) {
                        merges_.push_back(ReadString(file));
                    }
                    value_str = "[merges:" + std::to_string(arr_len) + "]";
                    break;
                }
                
                // Skip other arrays
                size_t elem_size = 1;
                switch (static_cast<GGUFValueType>(arr_type)) {
                    case GGUFValueType::UINT8:
                    case GGUFValueType::INT8:
                    case GGUFValueType::BOOL: elem_size = 1; break;
                    case GGUFValueType::UINT16:
                    case GGUFValueType::INT16: elem_size = 2; break;
                    case GGUFValueType::UINT32:
                    case GGUFValueType::INT32:
                    case GGUFValueType::FLOAT32: elem_size = 4; break;
                    case GGUFValueType::UINT64:
                    case GGUFValueType::INT64:
                    case GGUFValueType::FLOAT64: elem_size = 8; break;
                    case GGUFValueType::STRING: {
                        // Strings are variable length, need to skip each
                        for (uint64_t j = 0; j < arr_len; ++j) {
                            ReadString(file);
                        }
                        elem_size = 0; // Already skipped
                        break;
                    }
                    default: elem_size = 1; break;
                }
                
                if (elem_size > 0) {
                    file.seekg(static_cast<std::streamoff>(elem_size * arr_len), std::ios::cur);
                }
                value_str = "[array:" + std::to_string(arr_len) + "]";
                break;
            }
            default:
                // Unknown type, skip
                break;
        }
        
        metadata_[key] = value_str;
    }
    
    // Read tensor info
    tensors_.reserve(tensor_count_);
    for (uint64_t i = 0; i < tensor_count_; ++i) {
        TensorInfo info;
        info.name = ReadString(file);
        
        uint32_t ndims = ReadValue<uint32_t>(file);
        info.shape.resize(ndims);
        for (uint32_t d = 0; d < ndims; ++d) {
            info.shape[d] = ReadValue<uint64_t>(file);
        }
        
        info.type = ReadValue<uint32_t>(file);
        info.offset = ReadValue<uint64_t>(file);
        
        // Calculate size (simplified - doesn't account for quantization blocks)
        uint64_t elem_count = 1;
        for (auto dim : info.shape) {
            elem_count *= dim;
        }
        
        // Rough size calculation
        switch (static_cast<GGMLType>(info.type)) {
            case GGMLType::F32:  info.size = elem_count * 4; break;
            case GGMLType::F16:  info.size = elem_count * 2; break;
            case GGMLType::Q4_0: info.size = elem_count / 2 + (elem_count / 32) * 2; break; // 4.5 bits per element + scales
            case GGMLType::Q4_1: info.size = elem_count / 2 + (elem_count / 32) * 4; break;
            case GGMLType::Q5_0: info.size = elem_count * 5 / 8 + (elem_count / 32) * 2; break;
            case GGMLType::Q5_1: info.size = elem_count * 5 / 8 + (elem_count / 32) * 4; break;
            case GGMLType::Q8_0: info.size = elem_count + (elem_count / 32) * 2; break;
            case GGMLType::Q8_1: info.size = elem_count + (elem_count / 32) * 4; break;
            default:             info.size = elem_count * 4; break; // Conservative
        }
        
        tensors_.push_back(std::move(info));
    }
    
    // Detect quantization type from tensors
    arch_.quantization_type = DetectQuantizationType(tensors_);
    
    path_ = path;
    loaded_ = true;
    
    return true;
}

void ModelContext::Unload() {
    loaded_ = false;
    path_.clear();
    arch_ = ArchitectureInfo{};
    tensors_.clear();
    metadata_.clear();
    gguf_version_ = 0;
    tensor_count_ = 0;
    metadata_count_ = 0;
}

const TensorInfo* ModelContext::FindTensor(const std::string& name) const {
    for (const auto& t : tensors_) {
        if (t.name == name) {
            return &t;
        }
    }
    return nullptr;
}

std::vector<const TensorInfo*> ModelContext::FindTensorsByPattern(const std::string& pattern) const {
    std::vector<const TensorInfo*> result;
    for (const auto& t : tensors_) {
        if (t.name.find(pattern) != std::string::npos) {
            result.push_back(&t);
        }
    }
    return result;
}

uint64_t ModelContext::GetTotalTensorBytes() const {
    uint64_t total = 0;
    for (const auto& t : tensors_) {
        total += t.size;
    }
    return total;
}

std::string ModelContext::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"loaded\":" << (loaded_ ? "true" : "false") << ",";
    oss << "\"path\":\"" << path_ << "\",";
    oss << "\"gguf_version\":" << gguf_version_ << ",";
    oss << "\"tensor_count\":" << tensor_count_ << ",";
    oss << "\"metadata_count\":" << metadata_count_ << ",";
    
    // Architecture
    oss << "\"architecture\":{";
    oss << "\"type\":\"" << arch_.type << "\",";
    oss << "\"context_length\":" << arch_.context_length << ",";
    oss << "\"layer_count\":" << arch_.layer_count << ",";
    oss << "\"embedding_dim\":" << arch_.embedding_dim << ",";
    oss << "\"head_count\":" << arch_.head_count << ",";
    oss << "\"kv_head_count\":" << arch_.kv_head_count << ",";
    oss << "\"vocab_size\":" << arch_.vocab_size << ",";
    oss << "\"quantization_type\":\"" << arch_.quantization_type << "\"";
    oss << "},";
    
    // Tensors summary
    oss << "\"tensors\":{";
    oss << "\"count\":" << tensors_.size() << ",";
    oss << "\"total_bytes\":" << GetTotalTensorBytes() << ",";
    oss << "\"list\":[";
    for (size_t i = 0; i < tensors_.size() && i < 100; ++i) {  // Limit to 100
        if (i > 0) oss << ",";
        const auto& t = tensors_[i];
        oss << "{";
        oss << "\"name\":\"" << t.name << "\",";
        oss << "\"type\":\"" << t.GetTypeName() << "\",";
        oss << "\"shape\":[";
        for (size_t j = 0; j < t.shape.size(); ++j) {
            if (j > 0) oss << ",";
            oss << t.shape[j];
        }
        oss << "],";
        oss << "\"size\":" << t.size;
        oss << "}";
    }
    if (tensors_.size() > 100) {
        oss << ",{\"name\":\"...\",\"note\":\"" << (tensors_.size() - 100) << " more tensors\"}";
    }
    oss << "]}";
    
    oss << "}";
    return oss.str();
}

std::string ModelContext::ToHumanReadable() const {
    std::ostringstream oss;
    
    oss << "Model: " << path_ << "\n";
    oss << "Format: GGUF v" << gguf_version_ << "\n\n";
    
    // Architecture
    oss << "Architecture:\n";
    oss << "  Type: " << (arch_.type.empty() ? "unknown" : arch_.type) << "\n";
    oss << "  Context Length: " << arch_.context_length << "\n";
    oss << "  Layers: " << arch_.layer_count << "\n";
    oss << "  Embedding Dim: " << arch_.embedding_dim << "\n";
    oss << "  Attention Heads: " << arch_.head_count << "\n";
    oss << "  KV Heads: " << arch_.kv_head_count << "\n";
    oss << "  Vocab Size: " << arch_.vocab_size << "\n";
    oss << "  Quantization: " << arch_.quantization_type << "\n\n";
    
    // Tensors
    oss << "Tensors: " << tensors_.size() << " total\n";
    
    // Group by type
    std::map<std::string, int> type_counts;
    std::map<std::string, uint64_t> type_bytes;
    for (const auto& t : tensors_) {
        std::string type_name = t.GetTypeName();
        type_counts[type_name]++;
        type_bytes[type_name] += t.size;
    }
    
    oss << "  By Type:\n";
    for (const auto& [type, count] : type_counts) {
        double mb = type_bytes[type] / (1024.0 * 1024.0);
        oss << "    " << type << ": " << count << " tensors (" << std::fixed << std::setprecision(2) << mb << " MB)\n";
    }
    
    double total_mb = GetTotalTensorBytes() / (1024.0 * 1024.0);
    oss << "  Total Size: " << std::fixed << std::setprecision(2) << total_mb << " MB\n\n";
    
    // Sample tensors
    oss << "Sample Tensors:\n";
    for (size_t i = 0; i < std::min(size_t(10), tensors_.size()); ++i) {
        const auto& t = tensors_[i];
        oss << "  " << t.name << " [" << t.GetTypeName() << "] ";
        oss << "(";
        for (size_t j = 0; j < t.shape.size(); ++j) {
            if (j > 0) oss << "x";
            oss << t.shape[j];
        }
        oss << ")\n";
    }
    if (tensors_.size() > 10) {
        oss << "  ... and " << (tensors_.size() - 10) << " more\n";
    }
    
    return oss.str();
}

// ============================================================================
// ModelContextFactory
// ============================================================================

std::unique_ptr<ModelContext> ModelContextFactory::FromGGUF(const std::string& path) {
    auto ctx = std::make_unique<ModelContext>();
    if (!ctx->LoadFromFile(path)) {
        return nullptr;
    }
    return ctx;
}

std::unique_ptr<ModelContext> ModelContextFactory::Empty() {
    return std::make_unique<ModelContext>();
}

} // namespace model
} // namespace rawrxd
