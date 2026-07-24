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
// Safetensors Format Reader (stub)
// ============================================================================

bool SafetensorsFormatReader::ReadMetadata(const std::string& filePath, ModelMetadata& metadata) {
    // Safetensors stores metadata in JSON header
    // For now, stub - real implementation parses JSON header
    metadata.architecture = "safetensors";
    return true;
}

bool SafetensorsFormatReader::ReadTensorCatalog(const std::string& filePath,
                                                  std::vector<TensorEntry>& tensors) {
    tensors.clear();
    return true;
}

bool SafetensorsFormatReader::LoadTensor(const std::string& filePath,
                                           const TensorEntry& entry,
                                           void* destBuffer) {
    return false;
}

// ============================================================================
// HFPyTorch Format Reader (stub)
// ============================================================================

bool HFPyTorchFormatReader::ReadMetadata(const std::string& filePath, ModelMetadata& metadata) {
    metadata.architecture = "pytorch";
    return true;
}

bool HFPyTorchFormatReader::ReadTensorCatalog(const std::string& filePath,
                                                std::vector<TensorEntry>& tensors) {
    tensors.clear();
    return true;
}

bool HFPyTorchFormatReader::LoadTensor(const std::string& filePath,
                                          const TensorEntry& entry,
                                          void* destBuffer) {
    return false;
}

} // namespace RawrXD