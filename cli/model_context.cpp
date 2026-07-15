// ============================================================================
// ModelContext Implementation — GGUF Loader + Tensor Registry + TensorView
// ============================================================================

#include "model_context.hpp"
#include "tensor_view.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace RawrXD {
namespace CLI {

// GGUF Magic and version
constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF"
constexpr uint32_t GGUF_VERSION = 3;

// GGUF value types
enum GGUFValueType {
    GGUF_TYPE_UINT8 = 0,
    GGUF_TYPE_INT8 = 1,
    GGUF_TYPE_UINT16 = 2,
    GGUF_TYPE_INT16 = 3,
    GGUF_TYPE_UINT32 = 4,
    GGUF_TYPE_INT32 = 5,
    GGUF_TYPE_FLOAT32 = 6,
    GGUF_TYPE_BOOL = 7,
    GGUF_TYPE_STRING = 8,
    GGUF_TYPE_ARRAY = 9,
    GGUF_TYPE_UINT64 = 10,
    GGUF_TYPE_INT64 = 11,
    GGUF_TYPE_FLOAT64 = 12
};

// GGML tensor types (from llama.cpp)
enum GGMLType {
    GGML_TYPE_F32 = 0,
    GGML_TYPE_F16 = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q5_0 = 6,
    GGML_TYPE_Q5_1 = 7,
    GGML_TYPE_Q8_0 = 8,
    GGML_TYPE_Q8_1 = 9,
    GGML_TYPE_Q2_K = 10,
    GGML_TYPE_Q3_K = 11,
    GGML_TYPE_Q4_K = 12,
    GGML_TYPE_Q5_K = 13,
    GGML_TYPE_Q6_K = 14,
    GGML_TYPE_Q8_K = 15,
    GGML_TYPE_I8 = 16,
    GGML_TYPE_I16 = 17,
    GGML_TYPE_I32 = 18,
    GGML_TYPE_COUNT
};

// Convert GGML type to TensorType
static TensorType ConvertGGMLType(uint32_t ggmlType) {
    switch (ggmlType) {
        case GGML_TYPE_F32: return TensorType::F32;
        case GGML_TYPE_F16: return TensorType::F16;
        case GGML_TYPE_Q4_0: return TensorType::Q4_0;
        case GGML_TYPE_Q4_1: return TensorType::Q4_1;
        case GGML_TYPE_Q5_0: return TensorType::Q5_0;
        case GGML_TYPE_Q5_1: return TensorType::Q5_1;
        case GGML_TYPE_Q8_0: return TensorType::Q8_0;
        case GGML_TYPE_Q8_1: return TensorType::Q8_1;
        case GGML_TYPE_Q2_K: return TensorType::Q2_K;
        case GGML_TYPE_Q3_K: return TensorType::Q3_K;
        case GGML_TYPE_Q4_K: return TensorType::Q4_K;
        case GGML_TYPE_Q5_K: return TensorType::Q5_K;
        case GGML_TYPE_Q6_K: return TensorType::Q6_K;
        case GGML_TYPE_Q8_K: return TensorType::Q8_K;
        case GGML_TYPE_I8: return TensorType::I8;
        case GGML_TYPE_I16: return TensorType::I16;
        case GGML_TYPE_I32: return TensorType::I32;
        default: return TensorType::F32;
    }
}

// Calculate element size for tensor type
size_t TensorEntry::ElementSize() const {
    switch (type) {
        case TensorType::F32: return 4;
        case TensorType::F16: return 2;
        case TensorType::Q4_0: return 18;  // 32 elements per 18-byte block
        case TensorType::Q4_1: return 20;
        case TensorType::Q5_0: return 22;
        case TensorType::Q5_1: return 24;
        case TensorType::Q8_0: return 34;  // 32 elements per 34-byte block
        case TensorType::Q8_1: return 36;
        case TensorType::Q2_K: return 84;  // 256 elements
        case TensorType::Q3_K: return 110;
        case TensorType::Q4_K: return 144;
        case TensorType::Q5_K: return 176;
        case TensorType::Q6_K: return 210;
        case TensorType::Q8_K: return 292;
        case TensorType::I8: return 1;
        case TensorType::I16: return 2;
        case TensorType::I32: return 4;
        default: return 4;
    }
}

// ============================================================================
// ModelContext Implementation
// ============================================================================

ModelContext::ModelContext() = default;
ModelContext::~ModelContext() = default;

bool ModelContext::LoadFromGGUF(const std::string& path) {
    // Clear previous state
    m_loaded = false;
    m_modelPath.clear();
    m_metadata.clear();
    m_tensors.clear();
    m_fileData.clear();
    
    // Open and read file
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "[ModelContext] Failed to open: " << path << std::endl;
        return false;
    }
    
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    if (fileSize < 24) {
        std::cerr << "[ModelContext] File too small: " << fileSize << " bytes" << std::endl;
        return false;
    }
    
    // Read entire file into memory
    m_fileData.resize(fileSize);
    if (!file.read(reinterpret_cast<char*>(m_fileData.data()), fileSize)) {
        std::cerr << "[ModelContext] Failed to read file" << std::endl;
        return false;
    }
    
    // Parse GGUF
    if (!ParseGGUF(m_fileData.data(), fileSize)) {
        return false;
    }
    
    m_modelPath = path;
    m_loaded = true;
    
    // Extract architecture
    ExtractArchitecture();
    
    std::cout << "[ModelContext] Loaded: " << path << std::endl;
    std::cout << "  Architecture: " << m_arch.architecture << std::endl;
    std::cout << "  Vocab size: " << m_arch.vocabSize << std::endl;
    std::cout << "  Hidden size: " << m_arch.hiddenSize << std::endl;
    std::cout << "  Layers: " << m_arch.numLayers << std::endl;
    std::cout << "  Tensors: " << m_tensors.size() << std::endl;
    
    return true;
}

bool ModelContext::ParseGGUF(const uint8_t* data, size_t size) {
    size_t offset = 0;
    
    // Helper lambdas for reading
    auto readU32 = [&]() -> uint32_t {
        uint32_t val;
        memcpy(&val, data + offset, 4);
        offset += 4;
        return val;
    };
    
    auto readU64 = [&]() -> uint64_t {
        uint64_t val;
        memcpy(&val, data + offset, 8);
        offset += 8;
        return val;
    };
    
    auto readString = [&]() -> std::string {
        uint64_t len = readU64();
        std::string str(reinterpret_cast<const char*>(data + offset), len);
        offset += len;
        return str;
    };
    
    // Read header
    uint32_t magic = readU32();
    if (magic != GGUF_MAGIC) {
        std::cerr << "[ModelContext] Invalid GGUF magic: 0x" << std::hex << magic << std::dec << std::endl;
        return false;
    }
    
    uint32_t version = readU32();
    if (version > GGUF_VERSION) {
        std::cerr << "[ModelContext] Unsupported version: " << version << std::endl;
        return false;
    }
    
    uint64_t tensorCount = readU64();
    uint64_t metadataCount = readU64();
    
    // Parse metadata
    for (uint64_t i = 0; i < metadataCount; ++i) {
        std::string key = readString();
        uint32_t type = readU32();
        
        MetadataValue value;
        value.type = static_cast<MetadataValue::Type>(type);
        
        switch (type) {
            case GGUF_TYPE_UINT32:
                value.value.u32 = readU32();
                break;
            case GGUF_TYPE_INT32: {
                int32_t val;
                memcpy(&val, data + offset, 4);
                offset += 4;
                value.value.i32 = val;
                break;
            }
            case GGUF_TYPE_FLOAT32: {
                float val;
                memcpy(&val, data + offset, 4);
                offset += 4;
                value.value.f32 = val;
                break;
            }
            case GGUF_TYPE_STRING:
                value.str = readString();
                break;
            case GGUF_TYPE_UINT64:
                value.value.u64 = readU64();
                break;
            case GGUF_TYPE_INT64: {
                int64_t val;
                memcpy(&val, data + offset, 8);
                offset += 8;
                value.value.i64 = val;
                break;
            }
            case GGUF_TYPE_FLOAT64: {
                double val;
                memcpy(&val, data + offset, 8);
                offset += 8;
                value.value.f64 = val;
                break;
            }
            case GGUF_TYPE_BOOL: {
                uint8_t val;
                memcpy(&val, data + offset, 1);
                offset += 1;
                value.value.b = (val != 0);
                break;
            }
            case GGUF_TYPE_ARRAY: {
                uint32_t arrType = readU32();
                uint64_t arrLen = readU64();
                // Skip array data for now
                for (uint64_t j = 0; j < arrLen; ++j) {
                    switch (arrType) {
                        case GGUF_TYPE_UINT32: offset += 4; break;
                        case GGUF_TYPE_INT32: offset += 4; break;
                        case GGUF_TYPE_FLOAT32: offset += 4; break;
                        case GGUF_TYPE_STRING: {
                            uint64_t strLen = readU64();
                            offset += strLen;
                            break;
                        }
                        case GGUF_TYPE_UINT64: offset += 8; break;
                        case GGUF_TYPE_INT64: offset += 8; break;
                        default: offset += 4; break;
                    }
                }
                break;
            }
            default:
                std::cerr << "[ModelContext] Unknown metadata type: " << type << std::endl;
                return false;
        }
        
        m_metadata[key] = value;
    }
    
    // Parse tensor info
    for (uint64_t i = 0; i < tensorCount; ++i) {
        TensorEntry entry;
        entry.name = readString();
        entry.type = ConvertGGMLType(readU32());
        
        uint32_t numDims = readU32();
        for (uint32_t d = 0; d < numDims; ++d) {
            entry.shape.dimensions.push_back(readU64());
        }
        
        entry.offset = readU64();
        
        // Calculate size
        entry.size = entry.NumElements() * entry.ElementSize();
        
        m_tensors[entry.name] = entry;
    }
    
    return true;
}

void ModelContext::ExtractArchitecture() {
    // Extract common architecture parameters from metadata
    m_arch.name = GetMetadataString("general.name", "unknown");
    m_arch.architecture = GetMetadataString("general.architecture", "unknown");
    
    // Try different naming conventions
    m_arch.vocabSize = GetMetadataInt("llama.vocab_size", 
        GetMetadataInt("phi3.vocab_size", 32000));
    m_arch.hiddenSize = GetMetadataInt("llama.embedding_length",
        GetMetadataInt("phi3.embedding_length", 4096));
    m_arch.numLayers = GetMetadataInt("llama.block_count",
        GetMetadataInt("phi3.block_count", 32));
    m_arch.numHeads = GetMetadataInt("llama.attention.head_count",
        GetMetadataInt("phi3.attention.head_count", 32));
    m_arch.numKVHeads = GetMetadataInt("llama.attention.head_count_kv",
        GetMetadataInt("phi3.attention.head_count_kv", m_arch.numHeads));
    m_arch.contextLength = GetMetadataInt("llama.context_length",
        GetMetadataInt("phi3.context_length", 4096));
    m_arch.intermediateSize = GetMetadataInt("llama.feed_forward_length",
        GetMetadataInt("phi3.feed_forward_length", 11008));
    m_arch.rmsNormEps = GetMetadataFloat("llama.attention.layer_norm_rms_epsilon",
        GetMetadataFloat("phi3.attention.layer_norm_rms_epsilon", 1e-6f));
}

// Metadata access
bool ModelContext::HasMetadata(const std::string& key) const {
    return m_metadata.find(key) != m_metadata.end();
}

const MetadataValue* ModelContext::GetMetadata(const std::string& key) const {
    auto it = m_metadata.find(key);
    return (it != m_metadata.end()) ? &it->second : nullptr;
}

std::string ModelContext::GetMetadataString(const std::string& key, const std::string& defaultVal) const {
    auto it = m_metadata.find(key);
    if (it != m_metadata.end() && it->second.type == MetadataValue::Type::STRING) {
        return it->second.str;
    }
    return defaultVal;
}

int32_t ModelContext::GetMetadataInt(const std::string& key, int32_t defaultVal) const {
    auto it = m_metadata.find(key);
    if (it != m_metadata.end()) {
        switch (it->second.type) {
            case MetadataValue::Type::UINT32: return static_cast<int32_t>(it->second.value.u32);
            case MetadataValue::Type::INT32: return it->second.value.i32;
            case MetadataValue::Type::UINT64: return static_cast<int32_t>(it->second.value.u64);
            case MetadataValue::Type::INT64: return static_cast<int32_t>(it->second.value.i64);
            default: break;
        }
    }
    return defaultVal;
}

float ModelContext::GetMetadataFloat(const std::string& key, float defaultVal) const {
    auto it = m_metadata.find(key);
    if (it != m_metadata.end() && it->second.type == MetadataValue::Type::FLOAT32) {
        return it->second.value.f32;
    }
    return defaultVal;
}

// Tensor access
bool ModelContext::HasTensor(const std::string& name) const {
    return m_tensors.find(name) != m_tensors.end();
}

const TensorEntry* ModelContext::GetTensor(const std::string& name) const {
    auto it = m_tensors.find(name);
    return (it != m_tensors.end()) ? &it->second : nullptr;
}

const TensorEntry* ModelContext::GetTensorByPattern(const std::string& pattern) const {
    for (const auto& [name, entry] : m_tensors) {
        if (name.find(pattern) != std::string::npos) {
            return &entry;
        }
    }
    return nullptr;
}

std::vector<std::string> ModelContext::GetTensorNames() const {
    std::vector<std::string> names;
    for (const auto& [name, _] : m_tensors) {
        names.push_back(name);
    }
    return names;
}

const void* ModelContext::GetTensorData(const std::string& name) const {
    auto it = m_tensors.find(name);
    if (it != m_tensors.end() && it->second.offset + it->second.size <= m_fileData.size()) {
        return m_fileData.data() + it->second.offset;
    }
    return nullptr;
}

// Get TensorView for runtime kernel access
TensorView ModelContext::GetTensorView(const std::string& name) const {
    TensorView view;
    
    auto it = m_tensors.find(name);
    if (it == m_tensors.end()) {
        view.source_name = m_modelPath;
        return view;  // Invalid view - tensor not found
    }
    
    const TensorEntry& entry = it->second;
    view.data = GetTensorData(name);
    view.type = entry.type;
    view.shape = entry.shape.dimensions;
    view.byte_size = entry.size;
    view.source_name = m_modelPath;
    view.is_synthetic = false;
    
    return view;
}

// Specific tensor accessors
const TensorEntry* ModelContext::GetTokenEmbeddings() const {
    return GetTensor("token_embd.weight");
}

const TensorEntry* ModelContext::GetOutputWeight() const {
    return GetTensor("output.weight");
}

const TensorEntry* ModelContext::GetNormWeight() const {
    return GetTensor("norm.weight");
}

const TensorEntry* ModelContext::GetLayerNormWeight(uint32_t layer) const {
    std::ostringstream oss;
    oss << "blk." << layer << ".attn_norm.weight";
    return GetTensor(oss.str());
}

const TensorEntry* ModelContext::GetAttentionQWeight(uint32_t layer) const {
    std::ostringstream oss;
    oss << "blk." << layer << ".attn_q.weight";
    return GetTensor(oss.str());
}

const TensorEntry* ModelContext::GetAttentionKWeight(uint32_t layer) const {
    std::ostringstream oss;
    oss << "blk." << layer << ".attn_k.weight";
    return GetTensor(oss.str());
}

const TensorEntry* ModelContext::GetAttentionVWeight(uint32_t layer) const {
    std::ostringstream oss;
    oss << "blk." << layer << ".attn_v.weight";
    return GetTensor(oss.str());
}

const TensorEntry* ModelContext::GetAttentionOutputWeight(uint32_t layer) const {
    std::ostringstream oss;
    oss << "blk." << layer << ".attn_output.weight";
    return GetTensor(oss.str());
}

const TensorEntry* ModelContext::GetFFNUpWeight(uint32_t layer) const {
    std::ostringstream oss;
    oss << "blk." << layer << ".ffn_up.weight";
    return GetTensor(oss.str());
}

const TensorEntry* ModelContext::GetFFNGateWeight(uint32_t layer) const {
    std::ostringstream oss;
    oss << "blk." << layer << ".ffn_gate.weight";
    return GetTensor(oss.str());
}

const TensorEntry* ModelContext::GetFFNDownWeight(uint32_t layer) const {
    std::ostringstream oss;
    oss << "blk." << layer << ".ffn_down.weight";
    return GetTensor(oss.str());
}

// Validation gates
bool ModelContext::ValidateGate1_Metadata() const {
    return HasMetadata("general.architecture") &&
           HasMetadata("llama.embedding_length") &&
           m_arch.IsValid();
}

bool ModelContext::ValidateGate2_TensorLookup() const {
    return GetTokenEmbeddings() != nullptr &&
           GetOutputWeight() != nullptr &&
           GetNormWeight() != nullptr;
}

bool ModelContext::ValidateGate3_SingleToken() const {
    // Check we have enough tensors for a single token forward pass
    if (!ValidateGate2_TensorLookup()) return false;
    
    // Check first layer exists
    if (m_arch.numLayers > 0) {
        if (!GetLayerNormWeight(0)) return false;
        if (!GetAttentionQWeight(0) && !GetAttentionKWeight(0)) return false;
    }
    
    return true;
}

std::string ModelContext::GetValidationReport() const {
    std::ostringstream oss;
    oss << "=== ModelContext Validation Report ===\n";
    oss << "Model: " << m_arch.name << "\n";
    oss << "Architecture: " << m_arch.architecture << "\n\n";
    
    // Gate 1
    oss << "Gate 1 - Metadata: " << (ValidateGate1_Metadata() ? "PASS" : "FAIL") << "\n";
    oss << "  Required metadata present\n\n";
    
    // Gate 2
    oss << "Gate 2 - Tensor Lookup: " << (ValidateGate2_TensorLookup() ? "PASS" : "FAIL") << "\n";
    oss << "  token_embd.weight: " << (GetTokenEmbeddings() ? "FOUND" : "MISSING") << "\n";
    oss << "  output.weight: " << (GetOutputWeight() ? "FOUND" : "MISSING") << "\n";
    oss << "  norm.weight: " << (GetNormWeight() ? "FOUND" : "MISSING") << "\n\n";
    
    // Gate 3
    oss << "Gate 3 - Single Token Forward: " << (ValidateGate3_SingleToken() ? "PASS" : "FAIL") << "\n";
    oss << "  First layer tensors present\n\n";
    
    // Summary
    int passed = 0;
    if (ValidateGate1_Metadata()) passed++;
    if (ValidateGate2_TensorLookup()) passed++;
    if (ValidateGate3_SingleToken()) passed++;
    
    oss << "Summary: " << passed << "/3 gates passed\n";
    
    return oss.str();
}

} // namespace CLI
} // namespace RawrXD
