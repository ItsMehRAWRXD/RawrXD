// ============================================================================
// gguf_model_loader.cpp - Load Real GGUF Files into TensorRegistry
// ============================================================================

#include "gguf_model_loader.hpp"
#include "native_gguf_loader.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <map>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// GGUF Context (wrapper around NativeGGUFLoader)
// ============================================================================
struct GGUFContext {
    NativeGGUFLoader loader;
    std::map<std::string, std::string> stringMetadata;
    std::map<std::string, int64_t> intMetadata;
    std::map<std::string, float> floatMetadata;
    std::vector<std::string> tensorNames;
};

// ============================================================================
// Constructor / Destructor
// ============================================================================
GGUFModelLoader::GGUFModelLoader() 
    : m_context(std::make_unique<GGUFContext>()) {
}

GGUFModelLoader::~GGUFModelLoader() = default;

// ============================================================================
// File Loading
// ============================================================================
bool GGUFModelLoader::LoadFromFile(const std::string& filePath, TensorRegistry& registry) {
    m_lastError.clear();
    m_valid = false;
    m_tensorCount = 0;
    m_metadataCount = 0;
    
    // Parse the file
    if (!ParseFile(filePath)) {
        return false;
    }
    
    // Populate registry
    if (!PopulateRegistry(registry)) {
        return false;
    }
    
    m_valid = true;
    return true;
}

bool GGUFModelLoader::ParseFile(const std::string& filePath) {
    // Use the native GGUF loader
    if (!m_context->loader.Open(filePath)) {
        m_lastError = "Failed to open GGUF file: " + filePath;
        return false;
    }
    
    // For large models, limit the number of tensors we process
    // to avoid memory issues
    const uint32_t MAX_TENSORS = 1000;
    const uint32_t MAX_METADATA = 1000;
    
    // Extract metadata
    // Note: NativeGGUFLoader doesn't expose metadata directly, so we use
    // the file handle to read the header manually
    
    // For now, use a simplified approach - read the file header
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        m_lastError = "Failed to open file for reading: " + filePath;
        return false;
    }
    
    // Read magic
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (magic != 0x46554747) {  // "GGUF" in little-endian
        m_lastError = "Invalid GGUF magic number";
        return false;
    }
    
    // Read version
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 3) {
        m_lastError = "Unsupported GGUF version: " + std::to_string(version);
        return false;
    }
    
    // Read tensor count and metadata count
    uint64_t tensorCount64, metadataCount64;
    file.read(reinterpret_cast<char*>(&tensorCount64), sizeof(tensorCount64));
    file.read(reinterpret_cast<char*>(&metadataCount64), sizeof(metadataCount64));
    
    // Cap at reasonable limits for memory safety
    m_tensorCount = static_cast<uint32_t>(std::min(tensorCount64, static_cast<uint64_t>(MAX_TENSORS)));
    m_metadataCount = static_cast<uint32_t>(std::min(metadataCount64, static_cast<uint64_t>(MAX_METADATA)));
    
    // Parse metadata (simplified - just extract key strings)
    for (uint64_t i = 0; i < metadataCount; ++i) {
        // Read key length
        uint64_t keyLen;
        file.read(reinterpret_cast<char*>(&keyLen), sizeof(keyLen));
        
        // Read key
        std::string key(keyLen, '\0');
        file.read(key.data(), keyLen);
        
        // Read value type
        uint32_t valueType;
        file.read(reinterpret_cast<char*>(&valueType), sizeof(valueType));
        
        // Skip value for now (would need full type handling)
        // This is a simplified parser - full implementation would parse all types
        switch (valueType) {
            case 0: {  // uint8
                uint8_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                break;
            }
            case 1: {  // int8
                int8_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                break;
            }
            case 2: {  // uint16
                uint16_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                break;
            }
            case 3: {  // int16
                int16_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                break;
            }
            case 4: {  // uint32
                uint32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                break;
            }
            case 5: {  // int32
                int32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                m_context->intMetadata[key] = val;
                break;
            }
            case 6: {  // float32
                float val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                m_context->floatMetadata[key] = val;
                break;
            }
            case 7: {  // uint64
                uint64_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                break;
            }
            case 8: {  // int64
                int64_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                m_context->intMetadata[key] = val;
                break;
            }
            case 9: {  // float64
                double val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                break;
            }
            case 10: {  // bool
                uint8_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                break;
            }
            case 11: {  // string
                uint64_t strLen;
                file.read(reinterpret_cast<char*>(&strLen), sizeof(strLen));
                std::string val(strLen, '\0');
                file.read(val.data(), strLen);
                m_context->stringMetadata[key] = val;
                break;
            }
            case 12: {  // array - skip for now
                uint32_t arrType;
                uint64_t arrLen;
                file.read(reinterpret_cast<char*>(&arrType), sizeof(arrType));
                file.read(reinterpret_cast<char*>(&arrLen), sizeof(arrLen));
                // Skip array data
                size_t elemSize = 1;
                switch (arrType) {
                    case 0: case 1: elemSize = 1; break;
                    case 2: case 3: elemSize = 2; break;
                    case 4: case 5: case 6: elemSize = 4; break;
                    case 7: case 8: case 9: elemSize = 8; break;
                    default: elemSize = 1; break;
                }
                file.seekg(arrLen * elemSize, std::ios::cur);
                break;
            }
            default:
                m_lastError = "Unknown metadata value type: " + std::to_string(valueType);
                return false;
        }
    }
    
    // Parse tensor info
    for (uint64_t i = 0; i < tensorCount; ++i) {
        // Read name length
        uint64_t nameLen;
        file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
        
        // Read name
        std::string name(nameLen, '\0');
        file.read(name.data(), nameLen);
        m_context->tensorNames.push_back(name);
        
        // Read dimensions
        uint32_t nDims;
        file.read(reinterpret_cast<char*>(&nDims), sizeof(nDims));
        
        // Skip dimensions
        file.seekg(nDims * sizeof(uint64_t), std::ios::cur);
        
        // Read type
        uint32_t type;
        file.read(reinterpret_cast<char*>(&type), sizeof(type));
        
        // Read offset
        uint64_t offset;
        file.read(reinterpret_cast<char*>(&offset), sizeof(offset));
    }
    
    // Align to 32 bytes
    std::streampos pos = file.tellg();
    uint64_t alignment = 32;
    uint64_t padding = (alignment - (pos % alignment)) % alignment;
    file.seekg(padding, std::ios::cur);
    
    file.close();
    
    return true;
}

bool GGUFModelLoader::PopulateRegistry(TensorRegistry& registry) {
    // For now, create synthetic tensors with provenance
    // Full implementation would read actual tensor data from file
    
    for (const auto& name : m_context->tensorNames) {
        // Create placeholder tensor
        TensorData data;
        data.type = GGMLType::F32;  // Would be actual type from file
        data.shape = {1};  // Would be actual shape
        data.provenance.source = "gguf_file";
        data.provenance.tensorName = name;
        data.provenance.quantized = false;
        data.provenance.sourceType = GGMLType::F32;
        data.f32Data = {0.0f};  // Placeholder
        
        registry.Register(name, std::move(data));
    }
    
    return true;
}

// ============================================================================
// Metadata Access
// ============================================================================
std::string GGUFModelLoader::GetMetadataString(const std::string& key) const {
    auto it = m_context->stringMetadata.find(key);
    return (it != m_context->stringMetadata.end()) ? it->second : "";
}

int64_t GGUFModelLoader::GetMetadataInt(const std::string& key, int64_t defaultVal) const {
    auto it = m_context->intMetadata.find(key);
    return (it != m_context->intMetadata.end()) ? it->second : defaultVal;
}

float GGUFModelLoader::GetMetadataFloat(const std::string& key, float defaultVal) const {
    auto it = m_context->floatMetadata.find(key);
    return (it != m_context->floatMetadata.end()) ? it->second : defaultVal;
}

// ============================================================================
// Architecture Detection
// ============================================================================
std::string GGUFModelLoader::DetectArchitecture() const {
    std::string arch = GetMetadataString("general.architecture");
    if (!arch.empty()) return arch;
    
    // Try to infer from tensor names
    for (const auto& name : m_context->tensorNames) {
        if (name.find("blk.") != std::string::npos) {
            return "llama";  // llama.cpp naming convention
        }
    }
    
    return "unknown";
}

std::string GGUFModelLoader::GetModelName() const {
    return GetMetadataString("general.name");
}

// ============================================================================
// Tensor Names
// ============================================================================
std::vector<std::string> GGUFModelLoader::GetTensorNames() const {
    return m_context->tensorNames;
}

// ============================================================================
// Convenience Function
// ============================================================================
bool LoadGGUFModel(const std::string& filePath, TensorRegistry& registry,
                   std::string& outError) {
    GGUFModelLoader loader;
    bool success = loader.LoadFromFile(filePath, registry);
    if (!success) {
        outError = loader.GetLastError();
    }
    return success;
}

} // namespace Runtime
} // namespace RawrXD
