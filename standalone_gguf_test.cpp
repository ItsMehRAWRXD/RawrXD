// Standalone GGUF loader test - minimal dependencies
// Compile: cl.exe /EHsc /W3 /O2 standalone_gguf_test.cpp /Fe:gguf_test.exe

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <iostream>
#include <algorithm>

// Minimal GGUF structures
#pragma pack(push, 1)
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};
#pragma pack(pop)

enum class GGMLType : uint32_t {
    F32 = 0, F16 = 1, Q4_0 = 2, Q4_1 = 3,
    Q5_0 = 6, Q5_1 = 7, Q8_0 = 8, Q8_1 = 9,
    Q2_K = 10, Q3_K = 11, Q4_K = 12, Q5_K = 13, Q6_K = 14
};

struct TensorInfo {
    std::string name;
    GGMLType type;
    std::vector<uint64_t> shape;
    uint64_t offset;
};

// Simple GGUF parser
class SimpleGGUFParser {
public:
    std::map<std::string, std::string> metadata;
    std::vector<TensorInfo> tensors;
    
    bool Parse(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            std::cerr << "Failed to open: " << filepath << std::endl;
            return false;
        }
        
        // Read header
        GGUFHeader header;
        file.read(reinterpret_cast<char*>(&header), sizeof(header));
        
        if (header.magic != 0x46554747) { // 'GGUF' in little-endian
            std::cerr << "Invalid GGUF magic: " << std::hex << header.magic << std::dec << std::endl;
            return false;
        }
        
        std::cerr << "[GGUF] Version: " << header.version << std::endl;
        std::cerr << "[GGUF] Tensors: " << header.tensor_count << std::endl;
        std::cerr << "[GGUF] Metadata KV pairs: " << header.metadata_kv_count << std::endl;
        
        // Parse metadata
        for (uint64_t i = 0; i < header.metadata_kv_count; i++) {
            std::string key = ReadString(file);
            uint32_t type;
            file.read(reinterpret_cast<char*>(&type), sizeof(type));
            
            std::string value = ReadMetadataValue(file, type);
            metadata[key] = value;
        }
        
        // Parse tensor info
        for (uint64_t i = 0; i < header.tensor_count; i++) {
            TensorInfo info;
            info.name = ReadString(file);
            
            uint32_t dims;
            file.read(reinterpret_cast<char*>(&dims), sizeof(dims));
            
            info.shape.resize(dims);
            for (uint32_t d = 0; d < dims; d++) {
                file.read(reinterpret_cast<char*>(&info.shape[d]), sizeof(uint64_t));
            }
            
            uint32_t typeVal;
            file.read(reinterpret_cast<char*>(&typeVal), sizeof(typeVal));
            info.type = static_cast<GGMLType>(typeVal);
            
            file.read(reinterpret_cast<char*>(&info.offset), sizeof(info.offset));
            
            tensors.push_back(info);
        }
        
        return true;
    }
    
    // Architecture-aware metadata extraction
    void ExtractArchitectureMetadata() {
        std::cerr << "\n[ARCH] Detecting architecture..." << std::endl;
        
        // Find architecture
        std::string arch = "llama";
        auto archIt = metadata.find("general.architecture");
        if (archIt != metadata.end()) {
            arch = archIt->second;
            std::cerr << "[ARCH] Found: " << arch << std::endl;
            
            // Normalize
            if (arch == "qwen" || arch == "qwen2" || arch == "qwen2_moe") arch = "qwen2";
            else if (arch == "phi" || arch == "phi3") arch = "phi3";
            else if (arch == "gemma" || arch == "gemma2") arch = "gemma";
        } else {
            std::cerr << "[ARCH] No architecture key, defaulting to llama" << std::endl;
        }
        
        // Try architecture-specific keys first, then fall back
        auto findUint = [&](const std::string& key, const std::string& fallback) -> uint64_t {
            auto it = metadata.find(key);
            if (it == metadata.end() && !fallback.empty()) {
                it = metadata.find(fallback);
            }
            if (it == metadata.end()) return 0;
            try {
                return std::stoull(it->second);
            } catch (...) {
                return 0;
            }
        };
        
        std::string layerKey = arch + ".block_count";
        std::string layerFallback = "llama.block_count";
        
        std::cerr << "[ARCH] Looking for: " << layerKey << " (fallback: " << layerFallback << ")" << std::endl;
        
        auto layerIt = metadata.find(layerKey);
        auto layerFbIt = metadata.find(layerFallback);
        
        if (layerIt != metadata.end()) {
            std::cerr << "[ARCH] Found " << layerKey << " = " << layerIt->second << std::endl;
        }
        if (layerFbIt != metadata.end()) {
            std::cerr << "[ARCH] Found " << layerFallback << " = " << layerFbIt->second << std::endl;
        }
        
        uint64_t layers = findUint(layerKey, layerFallback);
        uint64_t context = findUint(arch + ".context_length", "llama.context_length");
        uint64_t embedding = findUint(arch + ".embedding_length", "llama.embedding_length");
        uint64_t vocab = findUint(arch + ".vocab_size", "llama.vocab_size");
        
        std::cerr << "\n[RESULT] Architecture: " << arch << std::endl;
        std::cerr << "[RESULT] Layers: " << layers << std::endl;
        std::cerr << "[RESULT] Context: " << context << std::endl;
        std::cerr << "[RESULT] Embedding: " << embedding << std::endl;
        std::cerr << "[RESULT] Vocab: " << vocab << std::endl;
        
        // Validation
        bool success = (layers > 0) && (context > 0) && (vocab > 0);
        if (success) {
            std::cerr << "\n✓ SUCCESS: Architecture detection working!" << std::endl;
        } else {
            std::cerr << "\n✗ FAIL: Some metadata not found" << std::endl;
        }
    }
    
private:
    std::string ReadString(std::ifstream& file) {
        uint64_t len;
        file.read(reinterpret_cast<char*>(&len), sizeof(len));
        std::string str(len, '\0');
        file.read(&str[0], len);
        return str;
    }
    
    std::string ReadMetadataValue(std::ifstream& file, uint32_t type) {
        switch (type) {
            case 0: { // uint8
                uint8_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                return std::to_string(val);
            }
            case 1: { // int8
                int8_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                return std::to_string(val);
            }
            case 2: { // uint16
                uint16_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                return std::to_string(val);
            }
            case 3: { // int16
                int16_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                return std::to_string(val);
            }
            case 4: { // uint32
                uint32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                return std::to_string(val);
            }
            case 5: { // int32
                int32_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                return std::to_string(val);
            }
            case 6: { // uint64
                uint64_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                return std::to_string(val);
            }
            case 7: { // int64
                int64_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                return std::to_string(val);
            }
            case 8: { // float32
                float val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                return std::to_string(val);
            }
            case 9: { // float64
                double val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                return std::to_string(val);
            }
            case 10: { // bool
                uint8_t val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                return val ? "true" : "false";
            }
            case 11: { // string
                return ReadString(file);
            }
            case 12: { // array - skip for now
                uint32_t type;
                uint64_t count;
                file.read(reinterpret_cast<char*>(&type), sizeof(type));
                file.read(reinterpret_cast<char*>(&count), sizeof(count));
                // Skip array data
                for (uint64_t i = 0; i < count; i++) {
                    ReadMetadataValue(file, type);
                }
                return "<array>";
            }
            default:
                return "<unknown>";
        }
    }
};

int main(int argc, char** argv) {
    std::cerr << "========================================" << std::endl;
    std::cerr << "Standalone GGUF Architecture Detection Test" << std::endl;
    std::cerr << "========================================" << std::endl;
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf>" << std::endl;
        return 1;
    }
    
    SimpleGGUFParser parser;
    if (!parser.Parse(argv[1])) {
        return 1;
    }
    
    parser.ExtractArchitectureMetadata();
    
    return 0;
}
