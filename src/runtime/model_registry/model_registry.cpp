#include "model_registry.hpp"
#include <fstream>
#include <filesystem>
#include <iostream>
#include <cstring>
#include <algorithm>

namespace rawrxd {
namespace runtime {

ModelRegistry::ModelRegistry() : registryPath_("") {}

ModelRegistry::~ModelRegistry() {}

bool ModelRegistry::scanDirectory(const std::string& path) {
    namespace fs = std::filesystem;
    
    try {
        if (!fs::exists(path) || !fs::is_directory(path)) {
            std::cerr << "Model registry path does not exist or is not a directory: " << path << std::endl;
            return false;
        }
        
        registryPath_ = path;
        bool success = true;
        
        for (const auto& entry : fs::directory_iterator(path)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                std::string ext = entry.path().extension().string();
                
                // Check for GGUF files
                if (ext == ".gguf" || ext == ".GGUF") {
                    ModelManifest manifest;
                    manifest.path = entry.path().string();
                    manifest.name = filename.substr(0, filename.find_last_of('.'));
                    
                    if (parseGGUFHeader(entry.path().string(), manifest)) {
                        if (!registerModel(manifest)) {
                            std::cerr << "Failed to register model: " << manifest.name << std::endl;
                            success = false;
                        }
                    } else {
                        std::cerr << "Failed to parse GGUF header for: " << entry.path().string() << std::endl;
                        success = false;
                    }
                }
            }
        }
        
        return success;
    } catch (const std::exception& e) {
        std::cerr << "Error scanning model directory: " << e.what() << std::endl;
        return false;
    }
}

bool ModelRegistry::registerModel(const ModelManifest& manifest) {
    // Check if model already exists
    if (models_.find(manifest.name) != models_.end()) {
        std::cerr << "Model already registered: " << manifest.name << std::endl;
        return false;
    }
    
    models_[manifest.name] = manifest;
    return true;
}

ModelManifest* ModelRegistry::find(const std::string& name) {
    auto it = models_.find(name);
    if (it != models_.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<ModelManifest> ModelRegistry::list() {
    std::vector<ModelManifest> result;
    result.reserve(models_.size());
    
    for (const auto& pair : models_) {
        result.push_back(pair.second);
    }
    
    return result;
}

bool ModelRegistry::remove(const std::string& name) {
    auto it = models_.find(name);
    if (it != models_.end()) {
        models_.erase(it);
        return true;
    }
    return false;
}

bool ModelRegistry::loadRegistry(const std::string& configPath) {
    // For now, we'll implement a simple JSON-based registry
    // In a full implementation, this would load from a config file
    std::cerr << "Registry loading not yet implemented" << std::endl;
    return false;
}

bool ModelRegistry::saveRegistry(const std::string& configPath) {
    // For now, we'll implement a simple JSON-based registry
    // In a full implementation, this would save to a config file
    std::cerr << "Registry saving not yet implemented" << std::endl;
    return false;
}

bool ModelRegistry::parseGGUFHeader(const std::string& filePath, ModelManifest& manifest) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return false;
    }
    
    // Read GGUF magic number
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    
    // GGUF magic number is 0x46554747 (GGUF in little endian)
    const uint32_t GGUF_MAGIC = 0x46554747;
    
    if (magic != GGUF_MAGIC) {
        std::cerr << "Invalid GGUF magic number in file: " << filePath << std::endl;
        return false;
    }
    
    // Read version
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    
    if (version != 3) { // GGUF version 3 is current
        std::cerr << "Unsupported GGUF version: " << version << " in file: " << filePath << std::endl;
        return false;
    }
    
    // Read tensor count
    uint64_t tensorCount;
    file.read(reinterpret_cast<char*>(&tensorCount), sizeof(tensorCount));
    
    // Read metadata key-value count
    uint64_t kvCount;
    file.read(reinterpret_cast<char*>(&kvCount), sizeof(kvCount));
    
    // Skip over KV pairs to get to tensor info
    for (uint64_t i = 0; i < kvCount; ++i) {
        // Read key length
        uint64_t keyLen;
        file.read(reinterpret_cast<char*>(&keyLen), sizeof(keyLen));
        
        // Skip key
        file.seekg(keyLen, std::ios::cur);
        
        // Read value type
        uint32_t valueType;
        file.read(reinterpret_cast<char*>(&valueType), sizeof(valueType));
        
        // Skip value based on type
        switch (valueType) {
            case 0: // UINT8
                file.seekg(1, std::ios::cur);
                break;
            case 1: // INT8
                file.seekg(1, std::ios::cur);
                break;
            case 2: // UINT16
                file.seekg(2, std::ios::cur);
                break;
            case 3: // INT16
                file.seekg(2, std::ios::cur);
                break;
            case 4: // UINT32
                file.seekg(4, std::ios::cur);
                break;
            case 5: // INT32
                file.seekg(4, std::ios::cur);
                break;
            case 6: // FLOAT32
                file.seekg(4, std::ios::cur);
                break;
            case 7: // BOOL
                file.seekg(1, std::ios::cur);
                break;
            case 8: // STRING
            {
                uint64_t strLen;
                file.read(reinterpret_cast<char*>(&strLen), sizeof(strLen));
                file.seekg(strLen, std::ios::cur);
                break;
            }
            case 9: // ARRAY
            {
                uint64_t arrType;
                uint64_t arrSize;
                file.read(reinterpret_cast<char*>(&arrType), sizeof(arrType));
                file.read(reinterpret_cast<char*>(&arrSize), sizeof(arrSize));
                
                // Skip array elements based on type
                size_t elementSize = 0;
                switch (arrType) {
                    case 0: elementSize = 1; break; // UINT8
                    case 1: elementSize = 1; break; // INT8
                    case 2: elementSize = 2; break; // UINT16
                    case 3: elementSize = 2; break; // INT16
                    case 4: elementSize = 4; break; // UINT32
                    case 5: elementSize = 4; break; // INT32
                    case 6: elementSize = 4; break; // FLOAT32
                    case 7: elementSize = 1; break; // BOOL
                    case 8: elementSize = 0; break; // STRING (handled separately)
                    default: elementSize = 0; break;
                }
                
                if (arrType == 8) { // STRING array
                    for (uint64_t j = 0; j < arrSize; ++j) {
                        uint64_t strLen;
                        file.read(reinterpret_cast<char*>(&strLen), sizeof(strLen));
                        file.seekg(strLen, std::ios::cur);
                    }
                } else {
                    file.seekg(arrSize * elementSize, std::ios::cur);
                }
                break;
            }
            default:
                std::cerr << "Unknown GGUF value type: " << valueType << std::endl;
                return false;
        }
    }
    
    // Now we're at the tensor data, but we need to extract metadata from KV pairs
    // For simplicity, we'll re-parse the KV pairs to extract metadata
    file.clear();
    file.seekg(sizeof(magic) + sizeof(version) + sizeof(tensorCount) + sizeof(kvCount), std::ios::beg);
    
    std::string architecture;
    std::string quantization;
    uint64_t parameterCount = 0;
    uint64_t contextLength = 0;
    
    for (uint64_t i = 0; i < kvCount; ++i) {
        // Read key length
        uint64_t keyLen;
        file.read(reinterpret_cast<char*>(&keyLen), sizeof(keyLen));
        
        // Read key
        std::string key(keyLen, '\0');
        file.read(&key[0], keyLen);
        
        // Read value type
        uint32_t valueType;
        file.read(reinterpret_cast<char*>(&valueType), sizeof(valueType));
        
        // Process value based on type and key
        if (key == "general.architecture") {
            if (valueType == 8) { // STRING
                uint64_t strLen;
                file.read(reinterpret_cast<char*>(&strLen), sizeof(strLen));
                architecture.resize(strLen);
                file.read(&architecture[0], strLen);
            }
        } else if (key == "general.quantization_version") {
            // Skip for now
            if (valueType == 4) { // UINT32
                file.seekg(4, std::ios::cur);
            }
        } else if (key == "llama.context_length") {
            if (valueType == 4) { // UINT32
                file.read(reinterpret_cast<char*>(&contextLength), sizeof(contextLength));
            }
        } else if (key == "llama.embedding_length") {
            // Skip for now
            if (valueType == 4) { // UINT32
                file.seekg(4, std::ios::cur);
            }
        } else if (key == "llama.block_count") {
            // Skip for now
            if (valueType == 4) { // UINT32
                file.seekg(4, std::ios::cur);
            }
        } else if (key == "llama.feed_forward_length") {
            // Skip for now
            if (valueType == 4) { // UINT32
                file.seekg(4, std::ios::cur);
            }
        } else if (key == "llama.embedding_length") {
            // Skip for now
            if (valueType == 4) { // UINT32
                file.seekg(4, std::ios::cur);
            }
        } else if (key == "llama.attention.head_count") {
            // Skip for now
            if (valueType == 4) { // UINT32
                file.seekg(4, std::ios::cur);
            }
        } else if (key == "llama.attention.head_count_kv") {
            // Skip for now
            if (valueType == 4) { // UINT32
                file.seekg(4, std::ios::cur);
            }
        } else if (key == "llama.attention.layer_norm_rms_eps") {
            // Skip for now
            if (valueType == 6) { // FLOAT32
                file.seekg(4, std::ios::cur);
            }
        } else if (key == "llama.rope.freq_base") {
            // Skip for now
            if (valueType == 6) { // FLOAT32
                file.seekg(4, std::ios::cur);
            }
        } else if (key == "llama.rope.freq_scale") {
            // Skip for now
            if (valueType == 6) { // FLOAT32
                file.seekg(4, std::ios::cur);
            }
        } else if (key == "llama.attention.layer_norm_rms_eps") {
            // Skip for now
            if (valueType == 6) { // FLOAT32
                file.seekg(4, std::ios::cur);
            }
        } else if (key == "tokenizer.ggml.tokens") {
            // Skip for now - this is a string array
            if (valueType == 8) { // STRING
                uint64_t arrSize;
                file.read(reinterpret_cast<char*>(&arrSize), sizeof(arrSize));
                for (uint64_t j = 0; j < arrSize; ++j) {
                    uint64_t strLen;
                    file.read(reinterpret_cast<char*>(&strLen), sizeof(strLen));
                    file.seekg(strLen, std::ios::cur);
                }
            }
        } else if (key == "tokenizer.ggml.merge_ranks") {
            // Skip for now - this is a uint32 array
            if (valueType == 9) { // ARRAY
                uint64_t arrType;
                uint64_t arrSize;
                file.read(reinterpret_cast<char*>(&arrType), sizeof(arrType));
                file.read(reinterpret_cast<char*>(&arrSize), sizeof(arrSize));
                if (arrType == 4) { // UINT32 array
                    file.seekg(arrSize * 4, std::ios::cur);
                }
            }
        } else if (key == "tokenizer.ggml.token_type") {
            // Skip for now - this is a uint32 array
            if (valueType == 9) { // ARRAY
                uint64_t arrType;
                uint64_t arrSize;
                file.read(reinterpret_cast<char*>(&arrType), sizeof(arrType));
                file.read(reinterpret_cast<char*>(&arrSize), sizeof(arrSize));
                if (arrType == 4) { // UINT32 array
                    file.seekg(arrSize * 4, std::ios::cur);
                }
            }
        } else {
            // Skip unknown key value
            switch (valueType) {
                case 0: // UINT8
                    file.seekg(1, std::ios::cur);
                    break;
                case 1: // INT8
                    file.seekg(1, std::ios::cur);
                    break;
                case 2: // UINT16
                    file.seekg(2, std::ios::cur);
                    break;
                case 3: // INT16
                    file.seekg(2, std::ios::cur);
                    break;
                case 4: // UINT32
                    file.seekg(4, std::ios::cur);
                    break;
                case 5: // INT32
                    file.seekg(4, std::ios::cur);
                    break;
                case 6: // FLOAT32
                    file.seekg(4, std::ios::cur);
                    break;
                case 7: // BOOL
                    file.seekg(1, std::ios::cur);
                    break;
                case 8: // STRING
                {
                    uint64_t strLen;
                    file.read(reinterpret_cast<char*>(&strLen), sizeof(strLen));
                    file.seekg(strLen, std::ios::cur);
                    break;
                }
                case 9: // ARRAY
                {
                    uint64_t arrType;
                    uint64_t arrSize;
                    file.read(reinterpret_cast<char*>(&arrType), sizeof(arrType));
                    file.read(reinterpret_cast<char*>(&arrSize), sizeof(arrSize));
                    
                    // Skip array elements based on type
                    size_t elementSize = 0;
                    switch (arrType) {
                        case 0: elementSize = 1; break; // UINT8
                        case 1: elementSize = 1; break; // INT8
                        case 2: elementSize = 2; break; // UINT16
                        case 3: elementSize = 2; break; // INT16
                        case 4: elementSize = 4; break; // UINT32
                        case 5: elementSize = 4; break; // INT32
                        case 6: elementSize = 4; break; // FLOAT32
                        case 7: elementSize = 1; break; // BOOL
                        case 8: elementSize = 0; break; // STRING (handled separately)
                        default: elementSize = 0; break;
                    }
                    
                    if (arrType == 8) { // STRING array
                        for (uint64_t j = 0; j < arrSize; ++j) {
                            uint64_t strLen;
                            file.read(reinterpret_cast<char*>(&strLen), sizeof(strLen));
                            file.seekg(strLen, std::ios::cur);
                        }
                    } else {
                        file.seekg(arrSize * elementSize, std::ios::cur);
                    }
                    break;
                }
                default:
                    std::cerr << "Unknown GGUF value type: " << valueType << std::endl;
                    return false;
            }
        }
    }
    
    // Set the extracted values
    manifest.architecture = architecture.empty() ? "unknown" : architecture;
    manifest.quantization = quantization.empty() ? "unknown" : quantization;
    manifest.context_length = contextLength;
    
    // Estimate parameter count (simplified)
    // In a real implementation, we would calculate this from tensor shapes
    manifest.parameter_count = tensorCount * 1000000; // Rough estimate
    
    // Get file size
    std::filesystem::path filePathObj(filePath);
    manifest.file_size = std::filesystem::file_size(filePathObj);
    
    #ifdef _WIN32
    // Windows-specific VRAM estimation (simplified)
    // In reality, this would be more complex and consider quantization
    manifest.required_vram = (manifest.parameter_count * 2) / (1024 * 1024 * 1024); // Rough GB estimate
    #else
    // Linux/other OS
    manifest.required_vram = (manifest.parameter_count * 2) / (1024 * 1024 * 1024); // Rough GB estimate
    #endif
    
    // Set capabilities (simplified)
    manifest.supports_gpu = true;
    #ifdef __ANDROID__
    manifest.supports_vulkan = true;
    manifest.supports_hip = false;
    #elif defined(__APPLE__)
    // macOS - Metal support would go here
    manifest.supports_vulkan = false;
    manifest.supports_hip = false;
    #elif defined(_WIN32)
    // Windows - check for HIP/AMD or Vulkan
    // For simplicity, we'll assume Vulkan is available
    manifest.supports_vulkan = true;
    manifest.supports_hip = false;
    #else
    // Linux
    manifest.supports_vulkan = true;
    #ifdef __HIP_PLATFORM_AMD__
    manifest.supports_hip = true;
    #else
    manifest.supports_hip = false;
    #endif
    #endif
    
    file.close();
    return true;
}

} // namespace runtime
} // namespace rawrxd
