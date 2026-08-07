// ============================================================================
// UniversalModelLoader.cpp
// ============================================================================
// Implementation of format-agnostic model loader
// ============================================================================

#include "UniversalModelLoader.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <cstdint>
#include <zlib.h>  // For ZIP decompression

#ifdef _MSC_VER
    #include <intrin.h>
#else
    #include <x86intrin.h>
#endif

namespace RawrXD {

// ============================================================================
// UniversalModelLoader Implementation
// ============================================================================

UniversalModelLoader::UniversalModelLoader() : activeReader_(nullptr) {
    // Register built-in format readers
    RegisterFormatReader(std::make_unique<GGUFFormatReader>());
    RegisterFormatReader(std::make_unique<SafetensorsFormatReader>());
    RegisterFormatReader(std::make_unique<HFPyTorchFormatReader>());
}

UniversalModelLoader::~UniversalModelLoader() = default;

void UniversalModelLoader::RegisterFormatReader(std::unique_ptr<IFormatReader> reader) {
    readers_.push_back(std::move(reader));
}

bool UniversalModelLoader::LoadModel(const std::string& filePath) {
    filePath_ = filePath;
    return DetectAndLoad();
}

bool UniversalModelLoader::DetectAndLoad() {
    // Find a reader that can handle this file
    for (auto& reader : readers_) {
        if (reader->CanRead(filePath_)) {
            activeReader_ = reader.get();
            formatName_ = reader->GetFormatName();
            break;
        }
    }

    if (!activeReader_) {
        return false;
    }

    // Read metadata
    if (!activeReader_->ReadMetadata(filePath_, metadata_)) {
        return false;
    }

    // Read tensor catalog
    tensors_.clear();
    if (!activeReader_->ReadTensorCatalog(filePath_, tensors_)) {
        return false;
    }

    // Resolve kernels ONCE (cached for entire model lifetime)
    kernels_ = ResolvedKernelTable::Resolve(metadata_.weightQuant, metadata_.kvQuant);

    return true;
}

const TensorEntry* UniversalModelLoader::FindTensor(const std::string& name) const {
    for (const auto& t : tensors_) {
        if (t.name == name) return &t;
    }
    return nullptr;
}

bool UniversalModelLoader::LoadTensorData(const std::string& tensorName, void* destBuffer) {
    const TensorEntry* entry = FindTensor(tensorName);
    if (!entry || !activeReader_) return false;
    return activeReader_->LoadTensor(filePath_, *entry, destBuffer);
}

// ============================================================================
// GGUF Format Reader Implementation
// ============================================================================

// GGUF magic: "GGUF" in little-endian
constexpr uint32_t GGUF_MAGIC = 0x46554747;

// GGUF tensor types
enum GGUFType : uint32_t {
    GGUF_F32      = 0,
    GGUF_F16      = 1,
    GGUF_Q4_0     = 2,
    GGUF_Q4_1     = 3,
    GGUF_Q5_0     = 6,
    GGUF_Q5_1     = 7,
    GGUF_Q8_0     = 8,
    GGUF_Q8_1     = 9,
    GGUF_Q2_K     = 10,
    GGUF_Q3_K     = 11,
    GGUF_Q4_K     = 12,
    GGUF_Q5_K     = 13,
    GGUF_Q6_K     = 14,
    GGUF_Q8_K     = 15,
    GGUF_IQ2_XXS  = 16,
    GGUF_IQ2_XS   = 17,
    GGUF_IQ3_XXS  = 18,
    GGUF_IQ4_NL   = 19,
    GGUF_IQ4_XS   = 20,
    GGUF_BF16     = 24,
    GGUF_I8       = 25,
    GGUF_I16      = 26,
    GGUF_I32      = 27,
    GGUF_I64      = 28,
    GGUF_F64      = 29,
};

QuantType GGUFFormatReader::MapGGUFType(uint32_t ggufType) {
    switch (ggufType) {
        case GGUF_F32:     return QuantType::F32;
        case GGUF_F16:     return QuantType::F16;
        case GGUF_BF16:    return QuantType::BF16;
        case GGUF_Q4_0:    return QuantType::Q4_0;
        case GGUF_Q4_1:    return QuantType::Q4_1;
        case GGUF_Q5_0:    return QuantType::Q5_0;
        case GGUF_Q5_1:    return QuantType::Q5_1;
        case GGUF_Q8_0:    return QuantType::Q8_0;
        case GGUF_Q8_1:    return QuantType::Q8_1;
        case GGUF_Q2_K:    return QuantType::Q2_K;
        case GGUF_Q3_K:    return QuantType::Q3_K;
        case GGUF_Q4_K:    return QuantType::Q4_K;
        case GGUF_Q5_K:    return QuantType::Q5_K;
        case GGUF_Q6_K:    return QuantType::Q6_K;
        case GGUF_IQ2_XXS: return QuantType::IQ2_XXS;
        case GGUF_IQ2_XS:  return QuantType::IQ2_XS;
        case GGUF_IQ3_XXS: return QuantType::IQ3_XXS;
        case GGUF_IQ4_NL:  return QuantType::IQ4_NL;
        case GGUF_IQ4_XS:  return QuantType::IQ4_XS;
        default:           return QuantType::UNKNOWN;
    }
}

bool GGUFFormatReader::CanRead(const std::string& filePath) {
    // Check for .gguf extension
    if (filePath.size() < 5) return false;
    auto ext = filePath.substr(filePath.size() - 5);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext == ".gguf";
}

// Block sizes for quantized types (elements per block, bytes per block)
struct BlockInfo {
    uint32_t elements;
    uint32_t bytes;
};

static BlockInfo GetBlockInfo(QuantType q) {
    switch (q) {
        case QuantType::Q4_0:    return {32, 18};
        case QuantType::Q4_1:    return {32, 20};
        case QuantType::Q5_0:    return {32, 22};
        case QuantType::Q5_1:    return {32, 24};
        case QuantType::Q8_0:    return {32, 34};
        case QuantType::Q8_1:    return {32, 36};
        case QuantType::Q2_K:    return {256, 84};
        case QuantType::Q3_K:    return {256, 110};
        case QuantType::Q4_K:    return {256, 144};
        case QuantType::Q5_K:    return {256, 176};
        case QuantType::Q6_K:    return {256, 210};
        case QuantType::IQ2_XXS: return {256, 66};
        case QuantType::IQ2_XS:  return {256, 74};
        case QuantType::IQ3_XXS: return {256, 98};
        case QuantType::IQ4_NL:  return {32, 18};
        case QuantType::IQ4_XS:  return {256, 136};
        default:                 return {0, 0};  // Dense
    }
}

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

static size_t GetGGUFValueTypeSize(GGUFValueType type) {
    switch (type) {
        case GGUFValueType::UINT8:   return 1;
        case GGUFValueType::INT8:    return 1;
        case GGUFValueType::UINT16:  return 2;
        case GGUFValueType::INT16:   return 2;
        case GGUFValueType::UINT32:  return 4;
        case GGUFValueType::INT32:   return 4;
        case GGUFValueType::FLOAT32: return 4;
        case GGUFValueType::BOOL:    return 1;
        case GGUFValueType::UINT64:  return 8;
        case GGUFValueType::INT64:   return 8;
        case GGUFValueType::FLOAT64: return 8;
        default: return 0;
    }
}

static std::string ReadGGUFString(std::ifstream& file) {
    uint64_t len;
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    std::string str(len, '\0');
    if (len > 0) {
        file.read(&str[0], len);
    }
    return str;
}

static void SkipGGUFValue(std::ifstream& file, GGUFValueType type) {
    if (type == GGUFValueType::STRING) {
        ReadGGUFString(file);
    } else if (type == GGUFValueType::ARRAY) {
        uint32_t arrType;
        uint64_t arrCount;
        file.read(reinterpret_cast<char*>(&arrType), sizeof(arrType));
        file.read(reinterpret_cast<char*>(&arrCount), sizeof(arrCount));
        GGUFValueType elemType = static_cast<GGUFValueType>(arrType);
        size_t elemSize = GetGGUFValueTypeSize(elemType);
        if (elemSize > 0) {
            file.seekg(elemSize * arrCount, std::ios::cur);
        } else if (elemType == GGUFValueType::STRING) {
            for (uint64_t i = 0; i < arrCount; i++) {
                ReadGGUFString(file);
            }
        }
    } else {
        size_t size = GetGGUFValueTypeSize(type);
        if (size > 0) {
            file.seekg(size, std::ios::cur);
        }
    }
}

bool GGUFFormatReader::ReadMetadata(const std::string& filePath, ModelMetadata& metadata) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;

    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (magic != GGUF_MAGIC) return false;

    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 3) return false;

    uint64_t tensorCount;
    file.read(reinterpret_cast<char*>(&tensorCount), sizeof(tensorCount));

    uint64_t kvCount;
    file.read(reinterpret_cast<char*>(&kvCount), sizeof(kvCount));

    metadata.architecture = "unknown";
    metadata.weightQuant = QuantType::F32;
    metadata.kvQuant = QuantType::F16;
    metadata.hiddenDim = 0;
    metadata.numLayers = 0;
    metadata.numHeads = 0;
    metadata.numKVHeads = 0;
    metadata.contextLength = 0;
    metadata.vocabSize = 0;

    for (uint64_t i = 0; i < kvCount; i++) {
        std::string key = ReadGGUFString(file);
        
        uint32_t valueTypeRaw;
        file.read(reinterpret_cast<char*>(&valueTypeRaw), sizeof(valueTypeRaw));
        GGUFValueType valueType = static_cast<GGUFValueType>(valueTypeRaw);

        if (key == "general.architecture") {
            if (valueType == GGUFValueType::STRING) {
                metadata.architecture = ReadGGUFString(file);
            } else {
                SkipGGUFValue(file, valueType);
            }
        } else if (key == "llama.hidden_size" || key == "qwen2.hidden_size") {
            if (valueType == GGUFValueType::UINT32) {
                uint32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                metadata.hiddenDim = val;
            } else if (valueType == GGUFValueType::INT32) {
                int32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                metadata.hiddenDim = static_cast<uint32_t>(val);
            } else {
                SkipGGUFValue(file, valueType);
            }
        } else if (key == "llama.block_count" || key == "qwen2.block_count") {
            if (valueType == GGUFValueType::UINT32) {
                uint32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                metadata.numLayers = val;
            } else if (valueType == GGUFValueType::INT32) {
                int32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                metadata.numLayers = static_cast<uint32_t>(val);
            } else {
                SkipGGUFValue(file, valueType);
            }
        } else if (key == "llama.attention.head_count" || key == "qwen2.attention.head_count") {
            if (valueType == GGUFValueType::UINT32) {
                uint32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                metadata.numHeads = val;
            } else if (valueType == GGUFValueType::INT32) {
                int32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                metadata.numHeads = static_cast<uint32_t>(val);
            } else {
                SkipGGUFValue(file, valueType);
            }
        } else if (key == "llama.attention.head_count_kv" || key == "qwen2.attention.head_count_kv") {
            if (valueType == GGUFValueType::UINT32) {
                uint32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                metadata.numKVHeads = val;
            } else if (valueType == GGUFValueType::INT32) {
                int32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                metadata.numKVHeads = static_cast<uint32_t>(val);
            } else {
                SkipGGUFValue(file, valueType);
            }
        } else if (key == "llama.context_length" || key == "qwen2.context_length") {
            if (valueType == GGUFValueType::UINT32) {
                uint32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                metadata.contextLength = val;
            } else if (valueType == GGUFValueType::INT32) {
                int32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                metadata.contextLength = static_cast<uint32_t>(val);
            } else {
                SkipGGUFValue(file, valueType);
            }
        } else if (key == "llama.vocab_size" || key == "qwen2.vocab_size") {
            if (valueType == GGUFValueType::UINT32) {
                uint32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                metadata.vocabSize = val;
            } else if (valueType == GGUFValueType::INT32) {
                int32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                metadata.vocabSize = static_cast<uint32_t>(val);
            } else {
                SkipGGUFValue(file, valueType);
            }
        } else {
            SkipGGUFValue(file, valueType);
        }
    }

    file.close();
    return true;
}

bool GGUFFormatReader::ReadTensorCatalog(const std::string& filePath,
                                           std::vector<TensorEntry>& tensors) {
    // Full GGUF tensor catalog reader
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;

    // Read header
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (magic != GGUF_MAGIC) return false;

    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 3) return false;

    uint64_t tensorCount;
    file.read(reinterpret_cast<char*>(&tensorCount), sizeof(tensorCount));

    uint64_t kvCount;
    file.read(reinterpret_cast<char*>(&kvCount), sizeof(kvCount));

    // Skip metadata KV pairs
    for (uint64_t i = 0; i < kvCount; i++) {
        std::string key = ReadGGUFString(file);
        uint32_t valueTypeRaw;
        file.read(reinterpret_cast<char*>(&valueTypeRaw), sizeof(valueTypeRaw));
        SkipGGUFValue(file, static_cast<GGUFValueType>(valueTypeRaw));
    }

    // Read tensor info
    tensors.clear();
    tensors.reserve(tensorCount);

    for (uint64_t i = 0; i < tensorCount; i++) {
        TensorEntry entry;
        entry.name = ReadGGUFString(file);

        // Read dimensions
        uint32_t nDims;
        file.read(reinterpret_cast<char*>(&nDims), sizeof(nDims));
        entry.shape.dims = nDims;
        entry.shape.elements = 1;

        for (uint32_t d = 0; d < nDims && d < 4; d++) {
            uint64_t dimSize;
            file.read(reinterpret_cast<char*>(&dimSize), sizeof(dimSize));
            entry.shape.dim[d] = static_cast<uint32_t>(dimSize);
            entry.shape.elements *= dimSize;
        }

        // Read tensor type
        uint32_t tensorType;
        file.read(reinterpret_cast<char*>(&tensorType), sizeof(tensorType));
        entry.quantType = MapGGUFType(tensorType);

        // Read file offset
        uint64_t offset;
        file.read(reinterpret_cast<char*>(&offset), sizeof(offset));
        entry.fileOffset = static_cast<size_t>(offset);

        // Calculate byte size
        BlockInfo blockInfo = GetBlockInfo(entry.quantType);
        if (blockInfo.elements > 0) {
            uint64_t numBlocks = (entry.shape.elements + blockInfo.elements - 1) / blockInfo.elements;
            entry.byteSize = static_cast<size_t>(numBlocks * blockInfo.bytes);
        } else {
            // Dense types
            size_t elemSize = (entry.quantType == QuantType::F16 || entry.quantType == QuantType::BF16) ? 2 : 4;
            entry.byteSize = static_cast<size_t>(entry.shape.elements * elemSize);
        }

        tensors.push_back(entry);
    }

    file.close();
    return true;
}

bool GGUFFormatReader::LoadTensor(const std::string& filePath,
                                    const TensorEntry& entry,
                                    void* destBuffer) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;

    file.seekg(entry.fileOffset, std::ios::beg);
    file.read(static_cast<char*>(destBuffer), entry.byteSize);

    return file.good();
}

// ============================================================================
// Safetensors Format Reader - Full Implementation
// ============================================================================

// Safetensors magic: 8-byte little-endian header length
constexpr uint64_t SAFETENSORS_MAX_HEADER_SIZE = 100000000; // 100MB max header

bool SafetensorsFormatReader::CanRead(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    // Read header size (first 8 bytes, little-endian uint64)
    uint64_t headerLen;
    file.read(reinterpret_cast<char*>(&headerLen), sizeof(headerLen));
    
    // Check if header size is reasonable
    if (headerLen == 0 || headerLen > SAFETENSORS_MAX_HEADER_SIZE) {
        return false;
    }
    
    // Try to read and validate JSON header starts with '{'
    std::string header(headerLen, '\0');
    file.read(&header[0], headerLen);
    
    // Valid safetensors header starts with '{' and contains __metadata__
    return header.length() > 2 && header[0] == '{';
}

const char* SafetensorsFormatReader::GetFormatName() const {
    return "safetensors";
}

// Simple JSON parser for safetensors header
static std::string ExtractJsonString(const std::string& json, size_t& pos) {
    // Skip whitespace and opening quote
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || 
                                   json[pos] == '\n' || json[pos] == '\r')) pos++;
    if (pos >= json.length() || json[pos] != '"') return "";
    pos++; // skip opening quote
    
    std::string result;
    while (pos < json.length() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.length()) {
            pos++;
            switch (json[pos]) {
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                case '/': result += '/'; break;
                case 'b': result += '\b'; break;
                case 'f': result += '\f'; break;
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                default: result += json[pos]; break;
            }
        } else {
            result += json[pos];
        }
        pos++;
    }
    if (pos < json.length()) pos++; // skip closing quote
    return result;
}

static int64_t ExtractJsonInt(const std::string& json, size_t& pos) {
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    bool negative = false;
    if (pos < json.length() && json[pos] == '-') {
        negative = true;
        pos++;
    }
    int64_t value = 0;
    while (pos < json.length() && json[pos] >= '0' && json[pos] <= '9') {
        value = value * 10 + (json[pos] - '0');
        pos++;
    }
    return negative ? -value : value;
}

static void SkipJsonValue(const std::string& json, size_t& pos);

static void SkipJsonArray(const std::string& json, size_t& pos) {
    if (pos >= json.length() || json[pos] != '[') return;
    pos++; // skip '['
    while (pos < json.length() && json[pos] != ']') {
        SkipJsonValue(json, pos);
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || 
                                      json[pos] == '\n' || json[pos] == '\r')) pos++;
        if (pos < json.length() && json[pos] == ',') pos++;
    }
    if (pos < json.length()) pos++; // skip ']'
}

static void SkipJsonObject(const std::string& json, size_t& pos) {
    if (pos >= json.length() || json[pos] != '{') return;
    pos++; // skip '{'
    while (pos < json.length() && json[pos] != '}') {
        // Skip key
        ExtractJsonString(json, pos);
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == ':' || 
                                      json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r')) pos++;
        // Skip value
        SkipJsonValue(json, pos);
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || 
                                      json[pos] == '\n' || json[pos] == '\r')) pos++;
        if (pos < json.length() && json[pos] == ',') pos++;
    }
    if (pos < json.length()) pos++; // skip '}'
}

static void SkipJsonValue(const std::string& json, size_t& pos) {
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || 
                                   json[pos] == '\n' || json[pos] == '\r')) pos++;
    if (pos >= json.length()) return;
    
    if (json[pos] == '{') {
        SkipJsonObject(json, pos);
    } else if (json[pos] == '[') {
        SkipJsonArray(json, pos);
    } else if (json[pos] == '"') {
        ExtractJsonString(json, pos);
    } else {
        // Number or literal - skip until delimiter
        while (pos < json.length() && json[pos] != ',' && json[pos] != '}' && 
               json[pos] != ']' && json[pos] != ' ') pos++;
    }
}

// Map safetensors dtype to QuantType
static QuantType MapSafetensorsDtype(const std::string& dtype) {
    if (dtype == "F32" || dtype == "float32") return QuantType::F32;
    if (dtype == "F16" || dtype == "float16") return QuantType::F16;
    if (dtype == "BF16" || dtype == "bfloat16") return QuantType::BF16;
    if (dtype == "I32" || dtype == "int32") return QuantType::I32;
    if (dtype == "I16" || dtype == "int16") return QuantType::I16;
    if (dtype == "I8" || dtype == "int8") return QuantType::I8;
    if (dtype == "U8" || dtype == "uint8") return QuantType::U8;
    // Default to F32 for unknown types
    return QuantType::F32;
}

bool SafetensorsFormatReader::ReadMetadata(const std::string& filePath, ModelMetadata& metadata) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    // Read header size
    uint64_t headerLen;
    file.read(reinterpret_cast<char*>(&headerLen), sizeof(headerLen));
    if (headerLen == 0 || headerLen > SAFETENSORS_MAX_HEADER_SIZE) return false;
    
    // Read header
    std::string header(headerLen, '\0');
    file.read(&header[0], headerLen);
    file.close();
    
    // Parse __metadata__ section if present
    size_t metaPos = header.find("\"__metadata__\"");
    if (metaPos != std::string::npos) {
        size_t pos = metaPos + 15; // skip "__metadata__"
        while (pos < header.length() && header[pos] != '{') pos++;
        if (pos < header.length()) {
            SkipJsonObject(header, pos);
        }
    }
    
    // Try to infer architecture from tensor names
    if (header.find("model.layers.") != std::string::npos) {
        metadata.architecture = "llama";
    } else if (header.find("transformer.h.") != std::string::npos) {
        metadata.architecture = "gpt2";
    } else if (header.find("encoder.layer.") != std::string::npos) {
        metadata.architecture = "bert";
    } else {
        metadata.architecture = "safetensors";
    }
    
    // Extract model name from file path
    size_t lastSlash = filePath.find_last_of("/\\");
    size_t lastDot = filePath.find_last_of('.');
    if (lastDot > lastSlash) {
        metadata.modelName = filePath.substr(lastSlash + 1, lastDot - lastSlash - 1);
    }
    
    // Default values - will be refined when reading tensors
    metadata.weightQuant = QuantType::F16;
    metadata.kvQuant = QuantType::F16;
    
    return true;
}

bool SafetensorsFormatReader::ReadTensorCatalog(const std::string& filePath,
                                                  std::vector<TensorEntry>& tensors) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    // Read header size
    uint64_t headerLen;
    file.read(reinterpret_cast<char*>(&headerLen), sizeof(headerLen));
    if (headerLen == 0 || headerLen > SAFETENSORS_MAX_HEADER_SIZE) return false;
    
    // Read header
    std::string header(headerLen, '\0');
    file.read(&header[0], headerLen);
    
    // Data starts after header
    uint64_t dataStart = 8 + headerLen; // 8 bytes for header length + header
    
    // Parse JSON to extract tensor info
    tensors.clear();
    
    size_t pos = 0;
    while (pos < header.length()) {
        // Skip whitespace
        while (pos < header.length() && (header[pos] == ' ' || header[pos] == '\t' || 
                                          header[pos] == '\n' || header[pos] == '\r')) pos++;
        if (pos >= header.length()) break;
        
        // Expect opening brace or skip __metadata__
        if (header[pos] == '{') {
            pos++;
            continue;
        }
        
        // Read tensor name (key)
        std::string tensorName = ExtractJsonString(header, pos);
        if (tensorName.empty() || tensorName == "__metadata__") {
            // Skip metadata section
            while (pos < header.length() && header[pos] != '}') {
                if (header[pos] == '{') SkipJsonObject(header, pos);
                else pos++;
            }
            if (pos < header.length()) pos++;
            continue;
        }
        
        // Expect colon
        while (pos < header.length() && (header[pos] == ' ' || header[pos] == ':' || 
                                          header[pos] == '\t')) pos++;
        
        // Expect opening brace for tensor info
        if (pos >= header.length() || header[pos] != '{') {
            SkipJsonValue(header, pos);
            continue;
        }
        pos++; // skip '{'
        
        TensorEntry entry;
        entry.name = tensorName;
        entry.fileOffset = 0; // Will be calculated
        
        // Parse tensor info object
        while (pos < header.length() && header[pos] != '}') {
            std::string key = ExtractJsonString(header, pos);
            while (pos < header.length() && (header[pos] == ' ' || header[pos] == ':' || 
                                              header[pos] == '\t')) pos++;
            
            if (key == "dtype") {
                std::string dtype = ExtractJsonString(header, pos);
                entry.quantType = MapSafetensorsDtype(dtype);
            } else if (key == "shape") {
                // Parse array of dimensions
                while (pos < header.length() && header[pos] != '[') pos++;
                if (pos < header.length()) pos++; // skip '['
                
                entry.shape.dims = 0;
                entry.shape.elements = 1;
                
                while (pos < header.length() && header[pos] != ']') {
                    int64_t dim = ExtractJsonInt(header, pos);
                    if (entry.shape.dims < 4) {
                        entry.shape.dim[entry.shape.dims] = static_cast<uint32_t>(dim);
                        entry.shape.elements *= dim;
                    }
                    entry.shape.dims++;
                    while (pos < header.length() && (header[pos] == ' ' || header[pos] == ',' || 
                                                      header[pos] == '\t')) pos++;
                }
                if (pos < header.length()) pos++; // skip ']'
            } else if (key == "data_offsets") {
                // Parse [start, end] array
                while (pos < header.length() && header[pos] != '[') pos++;
                if (pos < header.length()) pos++; // skip '['
                
                int64_t startOffset = ExtractJsonInt(header, pos);
                while (pos < header.length() && (header[pos] == ' ' || header[pos] == ',')) pos++;
                int64_t endOffset = ExtractJsonInt(header, pos);
                
                entry.fileOffset = dataStart + startOffset;
                entry.byteSize = endOffset - startOffset;
                
                while (pos < header.length() && header[pos] != ']') pos++;
                if (pos < header.length()) pos++; // skip ']'
            } else {
                SkipJsonValue(header, pos);
            }
            
            while (pos < header.length() && (header[pos] == ' ' || header[pos] == ',' || 
                                              header[pos] == '\t')) pos++;
        }
        
        if (pos < header.length()) pos++; // skip '}'
        
        tensors.push_back(entry);
        
        while (pos < header.length() && (header[pos] == ' ' || header[pos] == ',' || 
                                          header[pos] == '\t' || header[pos] == '\n' || 
                                          header[pos] == '\r')) pos++;
    }
    
    file.close();
    return !tensors.empty();
}

bool SafetensorsFormatReader::LoadTensor(const std::string& filePath,
                                           const TensorEntry& entry,
                                           void* destBuffer) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    file.seekg(entry.fileOffset, std::ios::beg);
    file.read(static_cast<char*>(destBuffer), entry.byteSize);
    
    return file.good();
}

// ============================================================================
// HFPyTorch Format Reader - Full Implementation
// ============================================================================

// PyTorch pickle format constants
constexpr uint8_t PT_OPCODE_PROTO = 0x80;
constexpr uint8_t PT_OPCODE_PERSISTENT = 0x81;
constexpr uint8_t PT_OPCODE_GLOBAL = 0x95;
constexpr uint8_t PT_OPCODE_TUPLE = 0x86;
constexpr uint8_t PT_OPCODE_BININT = 0x84;
constexpr uint8_t PT_OPCODE_BININT1 = 0x8A;
constexpr uint8_t PT_OPCODE_BININT2 = 0x8B;
constexpr uint8_t PT_OPCODE_BININT4 = 0x8C;
constexpr uint8_t PT_OPCODE_BINSTRING = 0x8E;
constexpr uint8_t PT_OPCODE_SHORT_BINSTRING = 0x8D;
constexpr uint8_t PT_OPCODE_BINUNICODE = 0x96;
constexpr uint8_t PT_OPCODE_EMPTY_DICT = 0x83;
constexpr uint8_t PT_OPCODE_EMPTY_LIST = 0x90;
constexpr uint8_t PT_OPCODE_APPENDS = 0x91;
constexpr uint8_t PT_OPCODE_BUILD = 0x94;
constexpr uint8_t PT_OPCODE_STOP = 0x2E;
constexpr uint8_t PT_OPCODE_MARK = 0x28;
constexpr uint8_t PT_OPCODE_POP = 0x30;
constexpr uint8_t PT_OPCODE_DUP = 0x32;
constexpr uint8_t PT_OPCODE_FLOAT = 0x47;
constexpr uint8_t PT_OPCODE_INT = 0x49;
constexpr uint8_t PT_OPCODE_LONG = 0x4C;
constexpr uint8_t PT_OPCODE_NONE = 0x4E;
constexpr uint8_t PT_OPCODE_REDUCE = 0x52;
constexpr uint8_t PT_OPCODE_STRING = 0x53;
constexpr uint8_t PT_OPCODE_UNICODE = 0x56;
constexpr uint8_t PT_OPCODE_LIST = 0x5B;
constexpr uint8_t PT_OPCODE_DICT = 0x75;
constexpr uint8_t PT_OPCODE_SETITEM = 0x73;
constexpr uint8_t PT_OPCODE_SETITEMS = 0x74;
constexpr uint8_t PT_OPCODE_BINFLOAT = 0x8F;

// ZIP local file header signature
constexpr uint32_t ZIP_LOCAL_FILE_HEADER = 0x04034b50;
constexpr uint32_t ZIP_CENTRAL_DIR_HEADER = 0x02014b50;
constexpr uint32_t ZIP_END_OF_CENTRAL_DIR = 0x06054b50;

bool HFPyTorchFormatReader::CanRead(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    // Check for ZIP signature (PyTorch files are ZIP archives)
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    
    // PyTorch files start with ZIP local file header
    return magic == ZIP_LOCAL_FILE_HEADER;
}

const char* HFPyTorchFormatReader::GetFormatName() const {
    return "pytorch";
}

// Simple ZIP file reader for PyTorch files
struct ZipEntry {
    std::string name;
    uint64_t offset;
    uint64_t compressedSize;
    uint64_t uncompressedSize;
    uint16_t compressionMethod;
    uint32_t crc32;
};

static bool ReadZipCentralDirectory(std::ifstream& file, std::vector<ZipEntry>& entries) {
    // Find end of central directory
    file.seekg(0, std::ios::end);
    auto fileSize = file.tellg();
    
    // Search backwards for end of central directory signature
    auto searchStart = std::max(static_cast<std::streamoff>(0), fileSize - 65536);
    file.seekg(searchStart, std::ios::beg);
    
    std::vector<uint8_t> buffer(fileSize - searchStart);
    file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    
    size_t eocdPos = 0;
    for (size_t i = buffer.size() - 22; i > 0; i--) {
        uint32_t sig = *reinterpret_cast<uint32_t*>(&buffer[i]);
        if (sig == ZIP_END_OF_CENTRAL_DIR) {
            eocdPos = i;
            break;
        }
    }
    
    if (eocdPos == 0) return false;
    
    // Parse end of central directory
    uint16_t numEntries = *reinterpret_cast<uint16_t*>(&buffer[eocdPos + 8]);
    uint32_t centralDirSize = *reinterpret_cast<uint32_t*>(&buffer[eocdPos + 12]);
    uint32_t centralDirOffset = *reinterpret_cast<uint32_t*>(&buffer[eocdPos + 16]);
    
    // Read central directory
    file.seekg(centralDirOffset, std::ios::beg);
    std::vector<uint8_t> centralDir(centralDirSize);
    file.read(reinterpret_cast<char*>(centralDir.data()), centralDirSize);
    
    // Parse central directory entries
    size_t pos = 0;
    for (uint16_t i = 0; i < numEntries && pos < centralDir.size(); i++) {
        uint32_t sig = *reinterpret_cast<uint32_t*>(&centralDir[pos]);
        if (sig != ZIP_CENTRAL_DIR_HEADER) break;
        
        uint16_t nameLen = *reinterpret_cast<uint16_t*>(&centralDir[pos + 28]);
        uint16_t extraLen = *reinterpret_cast<uint16_t*>(&centralDir[pos + 30]);
        uint16_t commentLen = *reinterpret_cast<uint16_t*>(&centralDir[pos + 32]);
        
        ZipEntry entry;
        entry.compressionMethod = *reinterpret_cast<uint16_t*>(&centralDir[pos + 10]);
        entry.crc32 = *reinterpret_cast<uint32_t*>(&centralDir[pos + 16]);
        entry.compressedSize = *reinterpret_cast<uint32_t*>(&centralDir[pos + 20]);
        entry.uncompressedSize = *reinterpret_cast<uint32_t*>(&centralDir[pos + 24]);
        entry.offset = *reinterpret_cast<uint32_t*>(&centralDir[pos + 42]);
        
        entry.name.assign(reinterpret_cast<char*>(&centralDir[pos + 46]), nameLen);
        entries.push_back(entry);
        
        pos += 46 + nameLen + extraLen + commentLen;
    }
    
    return true;
}

static bool ReadZipEntryData(std::ifstream& file, const ZipEntry& entry, std::vector<uint8_t>& data) {
    file.seekg(entry.offset, std::ios::beg);
    
    // Skip local file header
    uint32_t sig;
    file.read(reinterpret_cast<char*>(&sig), sizeof(sig));
    if (sig != ZIP_LOCAL_FILE_HEADER) return false;
    
    uint16_t nameLen, extraLen;
    file.seekg(22, std::ios::cur); // skip to name length
    file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
    file.read(reinterpret_cast<char*>(&extraLen), sizeof(extraLen));
    file.seekg(nameLen + extraLen, std::ios::cur);
    
    // Read data
    data.resize(entry.compressedSize);
    file.read(reinterpret_cast<char*>(data.data()), entry.compressedSize);
    
    // Handle compressed entries
    if (entry.compressionMethod != 0) {
        // Compression method 8 = DEFLATE (zlib)
        if (entry.compressionMethod == 8) {
            // Decompress using zlib
            uLongf uncompressedLen = entry.uncompressedSize;
            std::vector<uint8_t> uncompressed(uncompressedLen);
            int ret = uncompress(uncompressed.data(), &uncompressedLen,
                                 data.data(), entry.compressedSize);
            if (ret != Z_OK) {
                printf("[UniversalModelLoader] zlib decompression failed: %d\n", ret);
                return false;
            }
            data = std::move(uncompressed);
        } else {
            printf("[UniversalModelLoader] Unsupported compression method: %d\n",
                   entry.compressionMethod);
            return false;
        }
    }
    
    return file.good();
}

// Map PyTorch dtype to QuantType
static QuantType MapPyTorchDtype(int8_t dtype) {
    // PyTorch dtype values
    // 0 = float32, 1 = float64, 2 = float16, 3 = bfloat16, 4 = int8, etc.
    switch (dtype) {
        case 0: return QuantType::F32;
        case 2: return QuantType::F16;
        case 3: return QuantType::BF16;
        case 4: return QuantType::I8;
        case 6: return QuantType::I32;
        case 7: return QuantType::I64;
        default: return QuantType::F32;
    }
}

bool HFPyTorchFormatReader::ReadMetadata(const std::string& filePath, ModelMetadata& metadata) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    // Read ZIP central directory to find pickle file
    std::vector<ZipEntry> entries;
    if (!ReadZipCentralDirectory(file, entries)) {
        return false;
    }
    
    // Look for data.pkl which contains model metadata
    const ZipEntry* pickleEntry = nullptr;
    for (const auto& entry : entries) {
        if (entry.name.find("data.pkl") != std::string::npos ||
            entry.name.find("model.pkl") != std::string::npos) {
            pickleEntry = &entry;
            break;
        }
    }
    
    // Try to infer architecture from tensor file names
    for (const auto& entry : entries) {
        if (entry.name.find("transformer.") != std::string::npos ||
            entry.name.find("model.layers.") != std::string::npos) {
            metadata.architecture = "llama";
            break;
        } else if (entry.name.find("encoder.layer.") != std::string::npos) {
            metadata.architecture = "bert";
            break;
        }
    }
    
    if (metadata.architecture.empty()) {
        metadata.architecture = "pytorch";
    }
    
    // Extract model name from file path
    size_t lastSlash = filePath.find_last_of("/\\");
    size_t lastDot = filePath.find_last_of('.');
    if (lastDot > lastSlash) {
        metadata.modelName = filePath.substr(lastSlash + 1, lastDot - lastSlash - 1);
    }
    
    // Default quantization
    metadata.weightQuant = QuantType::F32;
    metadata.kvQuant = QuantType::F16;
    
    return true;
}

bool HFPyTorchFormatReader::ReadTensorCatalog(const std::string& filePath,
                                                std::vector<TensorEntry>& tensors) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    // Read ZIP central directory
    std::vector<ZipEntry> entries;
    if (!ReadZipCentralDirectory(file, entries)) {
        return false;
    }
    
    // Find data.pkl for tensor metadata
    const ZipEntry* pickleEntry = nullptr;
    for (const auto& entry : entries) {
        if (entry.name == "data.pkl" || entry.name.find(".pkl") != std::string::npos) {
            pickleEntry = &entry;
            break;
        }
    }
    
    // Build tensor catalog from .pkl file entries
    // PyTorch stores tensors as separate files in the ZIP
    tensors.clear();
    
    for (const auto& entry : entries) {
        // Skip non-tensor files
        if (entry.name == "data.pkl" || entry.name == "version" ||
            entry.name.find("/") == std::string::npos) {
            continue;
        }
        
        // Extract tensor name from path (e.g., "archive/data/0" -> "0")
        size_t lastSlash = entry.name.find_last_of('/');
        std::string tensorName = (lastSlash != std::string::npos) ? 
                                  entry.name.substr(lastSlash + 1) : entry.name;
        
        // Skip if not a numeric tensor file
        bool isNumeric = true;
        for (char c : tensorName) {
            if (!std::isdigit(c)) {
                isNumeric = false;
                break;
            }
        }
        if (!isNumeric && tensorName.find("tensor") == std::string::npos) {
            continue;
        }
        
        TensorEntry te;
        te.name = tensorName;
        te.fileOffset = entry.offset;
        te.byteSize = entry.compressedSize;
        
        // Read tensor header to get shape and dtype
        // PyTorch tensor files have a simple header
        file.seekg(entry.offset, std::ios::beg);
        
        // Skip local file header
        uint32_t sig;
        file.read(reinterpret_cast<char*>(&sig), sizeof(sig));
        if (sig != ZIP_LOCAL_FILE_HEADER) continue;
        
        uint16_t nameLen, extraLen;
        file.seekg(22, std::ios::cur);
        file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
        file.read(reinterpret_cast<char*>(&extraLen), sizeof(extraLen));
        file.seekg(nameLen + extraLen, std::ios::cur);
        
        // Read tensor header (version + ndim + dtype + shape)
        // Format: version(1) + ndim(1) + dtype(1) + shape(ndim * 8) + data
        uint8_t version, ndim, dtype;
        file.read(reinterpret_cast<char*>(&version), 1);
        file.read(reinterpret_cast<char*>(&ndim), 1);
        file.read(reinterpret_cast<char*>(&dtype), 1);
        
        te.quantType = MapPyTorchDtype(static_cast<int8_t>(dtype));
        
        te.shape.dims = ndim;
        te.shape.elements = 1;
        for (uint8_t i = 0; i < ndim && i < 4; i++) {
            uint64_t dim;
            file.read(reinterpret_cast<char*>(&dim), sizeof(dim));
            te.shape.dim[i] = static_cast<uint32_t>(dim);
            te.shape.elements *= dim;
        }
        
        // Calculate actual data offset
        te.fileOffset = static_cast<uint64_t>(file.tellg());
        
        // Calculate byte size from shape and dtype
        size_t elemSize = (te.quantType == QuantType::F16 || te.quantType == QuantType::BF16) ? 2 : 
                          (te.quantType == QuantType::F32 || te.quantType == QuantType::I32) ? 4 : 1;
        te.byteSize = te.shape.elements * elemSize;
        
        tensors.push_back(te);
    }
    
    return !tensors.empty();
}

bool HFPyTorchFormatReader::LoadTensor(const std::string& filePath,
                                          const TensorEntry& entry,
                                          void* destBuffer) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    // Read ZIP central directory to find the entry
    std::vector<ZipEntry> entries;
    if (!ReadZipCentralDirectory(file, entries)) {
        return false;
    }
    
    // Find matching entry
    const ZipEntry* zipEntry = nullptr;
    for (const auto& e : entries) {
        size_t lastSlash = e.name.find_last_of('/');
        std::string name = (lastSlash != std::string::npos) ? e.name.substr(lastSlash + 1) : e.name;
        if (name == entry.name) {
            zipEntry = &e;
            break;
        }
    }
    
    if (!zipEntry) return false;
    
    // Read the data
    std::vector<uint8_t> compressedData;
    if (!ReadZipEntryData(file, *zipEntry, compressedData)) {
        return false;
    }
    
    // Skip tensor header to get to actual data
    size_t headerSize = 3; // version + ndim + dtype
    headerSize += entry.shape.dims * 8; // shape dimensions
    
    if (compressedData.size() < headerSize + entry.byteSize) {
        return false;
    }
    
    // Copy data to destination buffer
    std::memcpy(destBuffer, compressedData.data() + headerSize, entry.byteSize);
    
    return true;
}

} // namespace RawrXD
