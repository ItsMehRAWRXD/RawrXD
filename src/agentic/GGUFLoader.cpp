/**
 * @file GGUFLoader.cpp
 * @brief Real GGUF model loader implementation
 * 
 * @copyright RawrXD 2026
 */

#include "GGUFLoader.h"
#include "../ggml_rxd_internal.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace RawrXD {
namespace Agentic {

// GGUF magic number: "GGUF" in little-endian
static constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF"
static constexpr uint32_t GGUF_VERSION = 3;

// GGUF value types
enum class GGUFValueType : uint32_t {
    UINT8 = 0,
    INT8 = 1,
    UINT16 = 2,
    INT16 = 3,
    UINT32 = 4,
    INT32 = 5,
    FLOAT32 = 6,
    BOOL = 7,
    STRING = 8,
    ARRAY = 9,
    UINT64 = 10,
    INT64 = 11,
    FLOAT64 = 12
};

GGUFLoader::GGUFLoader() = default;
GGUFLoader::~GGUFLoader() = default;
GGUFLoader::GGUFLoader(GGUFLoader&&) noexcept = default;
GGUFLoader& GGUFLoader::operator=(GGUFLoader&&) noexcept = default;

bool GGUFLoader::IsValidGGUF(const std::string& path) {
    FILE* file = fopen(path.c_str(), "rb");
    if (!file) {
        return false;
    }
    
    uint32_t magic = 0;
    size_t read = fread(&magic, sizeof(magic), 1, file);
    fclose(file);
    
    if (read != 1) {
        return false;
    }
    
    return magic == GGUF_MAGIC;
}

Result<std::unique_ptr<LoadedModel>> GGUFLoader::Load(const std::string& path) {
    // Check file exists and is valid GGUF
    if (!IsValidGGUF(path)) {
        SetError("File is not a valid GGUF: " + path);
        return Result<std::unique_ptr<LoadedModel>>::Err(
            ErrorCode::InvalidArgument, m_lastError);
    }
    
    FILE* file = fopen(path.c_str(), "rb");
    if (!file) {
        SetError("Failed to open file: " + path);
        return Result<std::unique_ptr<LoadedModel>>::Err(
            ErrorCode::NotFound, m_lastError);
    }
    
    auto model = std::make_unique<LoadedModel>();
    model->path = path;
    
    // Parse header
    if (!ParseHeader(file, model->header)) {
        fclose(file);
        return Result<std::unique_ptr<LoadedModel>>::Err(
            ErrorCode::ParseError, m_lastError);
    }
    
    // Parse metadata
    if (!ParseMetadata(file, model->header, *model)) {
        fclose(file);
        return Result<std::unique_ptr<LoadedModel>>::Err(
            ErrorCode::ParseError, m_lastError);
    }
    
    // Parse tensor info
    if (!ParseTensors(file, model->header, *model)) {
        fclose(file);
        return Result<std::unique_ptr<LoadedModel>>::Err(
            ErrorCode::ParseError, m_lastError);
    }
    
    // Load tensors into GGML
    if (!LoadTensorsIntoGGML(*model, file)) {
        fclose(file);
        return Result<std::unique_ptr<LoadedModel>>::Err(
            ErrorCode::InternalError, m_lastError);
    }
    
    fclose(file);
    
    return Result<std::unique_ptr<LoadedModel>>::Ok(std::move(model));
}

bool GGUFLoader::ParseHeader(FILE* file, GGUFHeader& header) {
    // Read magic
    if (fread(&header.magic, sizeof(header.magic), 1, file) != 1) {
        SetError("Failed to read magic");
        return false;
    }
    
    if (header.magic != GGUF_MAGIC) {
        SetError("Invalid magic number");
        return false;
    }
    
    // Read version
    if (fread(&header.version, sizeof(header.version), 1, file) != 1) {
        SetError("Failed to read version");
        return false;
    }
    
    if (header.version != 3) {
        SetError("Unsupported GGUF version: " + std::to_string(header.version));
        return false;
    }
    
    // Read tensor count
    if (fread(&header.tensorCount, sizeof(header.tensorCount), 1, file) != 1) {
        SetError("Failed to read tensor count");
        return false;
    }
    
    // Read metadata count
    if (fread(&header.metadataCount, sizeof(header.metadataCount), 1, file) != 1) {
        SetError("Failed to read metadata count");
        return false;
    }
    
    return true;
}

static std::string ReadString(FILE* file) {
    uint64_t len = 0;
    if (fread(&len, sizeof(len), 1, file) != 1) {
        return "";
    }
    
    std::string str(len, '\0');
    if (len > 0 && fread(&str[0], len, 1, file) != 1) {
        return "";
    }
    
    return str;
}

static bool SkipValue(FILE* file, GGUFValueType type) {
    switch (type) {
        case GGUFValueType::UINT8:
        case GGUFValueType::INT8:
            return fseek(file, 1, SEEK_CUR) == 0;
        case GGUFValueType::UINT16:
        case GGUFValueType::INT16:
            return fseek(file, 2, SEEK_CUR) == 0;
        case GGUFValueType::UINT32:
        case GGUFValueType::INT32:
        case GGUFValueType::FLOAT32:
            return fseek(file, 4, SEEK_CUR) == 0;
        case GGUFValueType::UINT64:
        case GGUFValueType::INT64:
        case GGUFValueType::FLOAT64:
            return fseek(file, 8, SEEK_CUR) == 0;
        case GGUFValueType::BOOL:
            return fseek(file, 1, SEEK_CUR) == 0;
        case GGUFValueType::STRING: {
            std::string str = ReadString(file);
            return !str.empty() || feof(file) == 0;
        }
        case GGUFValueType::ARRAY: {
            uint32_t itemType;
            if (fread(&itemType, sizeof(itemType), 1, file) != 1) return false;
            
            uint64_t count;
            if (fread(&count, sizeof(count), 1, file) != 1) return false;
            
            for (uint64_t i = 0; i < count; i++) {
                if (!SkipValue(file, static_cast<GGUFValueType>(itemType))) return false;
            }
            return true;
        }
        default:
            return false;
    }
}

bool GGUFLoader::ParseMetadata(FILE* file, const GGUFHeader& header, LoadedModel& model) {
    for (uint64_t i = 0; i < header.metadataCount; i++) {
        std::string key = ReadString(file);
        if (key.empty()) {
            SetError("Failed to read metadata key");
            return false;
        }
        
        uint32_t valueType;
        if (fread(&valueType, sizeof(valueType), 1, file) != 1) {
            SetError("Failed to read metadata value type");
            return false;
        }
        
        // For now, just store string representations
        if (static_cast<GGUFValueType>(valueType) == GGUFValueType::STRING) {
            std::string value = ReadString(file);
            model.metadata[key] = value;
        } else if (static_cast<GGUFValueType>(valueType) == GGUFValueType::UINT32) {
            uint32_t value;
            if (fread(&value, sizeof(value), 1, file) != 1) {
                SetError("Failed to read uint32 metadata");
                return false;
            }
            model.metadata[key] = std::to_string(value);
            
            // Extract key architecture info
            if (key == "general.architecture") {
                model.architecture = std::to_string(value);
            } else if (key == "llama.vocab_size" || key == "general.vocab_size") {
                model.vocabSize = static_cast<int>(value);
            } else if (key == "llama.hidden_size" || key == "general.hidden_size") {
                model.hiddenSize = static_cast<int>(value);
            } else if (key == "llama.block_count" || key == "general.block_count") {
                model.numLayers = static_cast<int>(value);
            } else if (key == "llama.attention.head_count") {
                model.numHeads = static_cast<int>(value);
            } else if (key == "llama.context_length" || key == "general.context_length") {
                model.contextLength = static_cast<int>(value);
            }
        } else {
            if (!SkipValue(file, static_cast<GGUFValueType>(valueType))) {
                SetError("Failed to skip metadata value");
                return false;
            }
        }
    }
    
    return true;
}

bool GGUFLoader::ParseTensors(FILE* file, const GGUFHeader& header, LoadedModel& model) {
    model.tensors.reserve(header.tensorCount);
    
    for (uint64_t i = 0; i < header.tensorCount; i++) {
        GGUFTensorInfo info;
        
        // Read name
        info.name = ReadString(file);
        if (info.name.empty()) {
            SetError("Failed to read tensor name");
            return false;
        }
        
        // Read dimensions
        uint32_t n_dims;
        if (fread(&n_dims, sizeof(n_dims), 1, file) != 1) {
            SetError("Failed to read tensor dimensions");
            return false;
        }
        info.n_dims = static_cast<int>(n_dims);
        
        // Read dimension sizes
        info.dims.resize(n_dims);
        for (uint32_t d = 0; d < n_dims; d++) {
            if (fread(&info.dims[d], sizeof(info.dims[d]), 1, file) != 1) {
                SetError("Failed to read tensor dimension");
                return false;
            }
        }
        
        // Read type
        if (fread(&info.type, sizeof(info.type), 1, file) != 1) {
            SetError("Failed to read tensor type");
            return false;
        }
        
        // Read offset
        if (fread(&info.offset, sizeof(info.offset), 1, file) != 1) {
            SetError("Failed to read tensor offset");
            return false;
        }
        
        // Calculate size (simplified - doesn't account for quantization)
        info.size = 1;
        for (auto dim : info.dims) {
            info.size *= dim;
        }
        info.size *= 4;  // Assume float32 for now
        
        model.tensors.push_back(std::move(info));
    }
    
    return true;
}

bool GGUFLoader::LoadTensorsIntoGGML(LoadedModel& model, FILE* file) {
    // For now, just validate that we can read the tensor data section
    // Real GGML integration would initialize context and create tensors here
    
    // Calculate total memory needed
    size_t totalSize = 0;
    for (const auto& tensor : model.tensors) {
        totalSize += tensor.size;
    }
    
    // Get current file position (start of tensor data)
    long tensorDataOffset = ftell(file);
    
    // Align to 32 bytes (GGUF spec)
    tensorDataOffset = (tensorDataOffset + 31) & ~31;
    
    // Seek to tensor data section to validate it exists
    if (fseek(file, tensorDataOffset, SEEK_SET) != 0) {
        SetError("Failed to seek to tensor data");
        return false;
    }
    
    // For Phase 2, we just validate the file structure
    // Full GGML integration will come in Phase 3
    
    // Store the tensor data offset for later use
    // (In real implementation, we'd mmap this and create GGML tensors)
    
    return true;
}

void GGUFLoader::SetError(const std::string& msg) {
    m_lastError = msg;
}

} // namespace Agentic
} // namespace RawrXD
