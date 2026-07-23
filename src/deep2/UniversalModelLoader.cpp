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

bool GGUFFormatReader::ReadMetadata(const std::string& filePath, ModelMetadata& metadata) {
    // Simplified GGUF metadata reader
    // In production, this would parse the full GGUF metadata key-value store
    // For now, we read the header and extract architecture from metadata keys

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;

    // Read magic
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (magic != GGUF_MAGIC) {
        return false;
    }

    // Read version
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));

    // Read tensor count
    uint64_t tensorCount;
    file.read(reinterpret_cast<char*>(&tensorCount), sizeof(tensorCount));

    // Read metadata KV count
    uint64_t kvCount;
    file.read(reinterpret_cast<char*>(&kvCount), sizeof(kvCount));

    // Parse metadata key-value pairs
    // This is a simplified parser - production would handle all GGUF value types
    metadata.architecture = "unknown";
    metadata.weightQuant = QuantType::F32;
    metadata.kvQuant = QuantType::F16;

    // In a real implementation, we'd parse all KV pairs here:
    // - general.architecture
    // - llama.hidden_size, llama.num_layers, etc.
    // - quantization info from tensor types

    file.close();
    return true;
}

bool GGUFFormatReader::ReadTensorCatalog(const std::string& filePath,
                                           std::vector<TensorEntry>& tensors) {
    // Simplified - in production this reads the GGUF tensor info section
    // For now, return empty catalog (real implementation parses tensor info)
    tensors.clear();
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