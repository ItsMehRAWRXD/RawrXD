// ============================================================================
// inspect_gguf_metadata.cpp — Deep GGUF Metadata Inspector
// ============================================================================

#include <iostream>
#include <fstream>
#include <string>
#include <cstdint>
#include <vector>
#include <string>

static constexpr uint32_t GGUF_MAGIC = 0x46554747; // "GGUF"

enum class GGUFType : uint32_t {
    UINT8 = 0, INT8 = 1, UINT16 = 2, INT16 = 3,
    UINT32 = 4, INT32 = 5, FLOAT32 = 6, BOOL = 7,
    STRING = 8, ARRAY = 9, UINT64 = 10, INT64 = 11,
    FLOAT64 = 12
};

const char* TypeName(uint32_t type) {
    switch (static_cast<GGUFType>(type)) {
        case GGUFType::UINT8: return "U8";
        case GGUFType::INT8: return "I8";
        case GGUFType::UINT16: return "U16";
        case GGUFType::INT16: return "I16";
        case GGUFType::UINT32: return "U32";
        case GGUFType::INT32: return "I32";
        case GGUFType::FLOAT32: return "F32";
        case GGUFType::BOOL: return "BOOL";
        case GGUFType::STRING: return "STRING";
        case GGUFType::ARRAY: return "ARRAY";
        case GGUFType::UINT64: return "U64";
        case GGUFType::INT64: return "I64";
        case GGUFType::FLOAT64: return "F64";
        default: return "UNKNOWN";
    }
}

void SkipValue(std::ifstream& f, uint32_t valType) {
    switch (static_cast<GGUFType>(valType)) {
        case GGUFType::UINT8: { uint8_t v; f.read(reinterpret_cast<char*>(&v), 1); break; }
        case GGUFType::INT8: { int8_t v; f.read(reinterpret_cast<char*>(&v), 1); break; }
        case GGUFType::UINT16: { uint16_t v; f.read(reinterpret_cast<char*>(&v), 2); break; }
        case GGUFType::INT16: { int16_t v; f.read(reinterpret_cast<char*>(&v), 2); break; }
        case GGUFType::UINT32: { uint32_t v; f.read(reinterpret_cast<char*>(&v), 4); break; }
        case GGUFType::INT32: { int32_t v; f.read(reinterpret_cast<char*>(&v), 4); break; }
        case GGUFType::FLOAT32: { float v; f.read(reinterpret_cast<char*>(&v), 4); break; }
        case GGUFType::BOOL: { bool v; f.read(reinterpret_cast<char*>(&v), 1); break; }
        case GGUFType::UINT64: { uint64_t v; f.read(reinterpret_cast<char*>(&v), 8); break; }
        case GGUFType::INT64: { int64_t v; f.read(reinterpret_cast<char*>(&v), 8); break; }
        case GGUFType::FLOAT64: { double v; f.read(reinterpret_cast<char*>(&v), 8); break; }
        case GGUFType::STRING: {
            uint64_t len = 0;
            f.read(reinterpret_cast<char*>(&len), 8);
            f.seekg(static_cast<std::streamoff>(len), std::ios::cur);
            break;
        }
        case GGUFType::ARRAY: {
            uint32_t arrType = 0;
            uint64_t arrLen = 0;
            f.read(reinterpret_cast<char*>(&arrType), 4);
            f.read(reinterpret_cast<char*>(&arrLen), 8);
            size_t elemSize = 0;
            switch (static_cast<GGUFType>(arrType)) {
                case GGUFType::UINT8: case GGUFType::INT8: elemSize = 1; break;
                case GGUFType::UINT16: case GGUFType::INT16: elemSize = 2; break;
                case GGUFType::UINT32: case GGUFType::INT32: case GGUFType::FLOAT32: elemSize = 4; break;
                case GGUFType::UINT64: case GGUFType::INT64: case GGUFType::FLOAT64: elemSize = 8; break;
                default: elemSize = 1; break;
            }
            f.seekg(static_cast<std::streamoff>(arrLen * elemSize), std::ios::cur);
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <gguf_file>" << std::endl;
        return 1;
    }

    std::string path = argv[1];
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Cannot open: " << path << std::endl;
        return 1;
    }

    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), 4);
    if (magic != GGUF_MAGIC) {
        std::cerr << "Invalid GGUF magic" << std::endl;
        return 1;
    }

    uint32_t version = 0;
    file.read(reinterpret_cast<char*>(&version), 4);
    
    uint64_t tensorCount = 0, metadataCount = 0;
    file.read(reinterpret_cast<char*>(&tensorCount), 8);
    file.read(reinterpret_cast<char*>(&metadataCount), 8);

    std::cout << "============================================================" << std::endl;
    std::cout << "  GGUF Metadata Inspector" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << "File: " << path << std::endl;
    std::cout << "Version: " << version << std::endl;
    std::cout << "Tensors: " << tensorCount << std::endl;
    std::cout << "Metadata entries: " << metadataCount << std::endl;
    std::cout << std::endl;

    std::cout << "Metadata Keys:" << std::endl;
    std::cout << "------------------------------------------------------------" << std::endl;

    for (uint64_t i = 0; i < metadataCount && i < 100; ++i) {
        uint64_t keyLen = 0;
        file.read(reinterpret_cast<char*>(&keyLen), 8);
        
        if (keyLen == 0 || keyLen > 1024) {
            std::cout << "[Invalid key length: " << keyLen << "]" << std::endl;
            break;
        }
        
        std::string key(keyLen, '\0');
        file.read(key.data(), keyLen);

        uint32_t valType = 0;
        file.read(reinterpret_cast<char*>(&valType), 4);

        // Print key and type
        std::cout << "  [" << TypeName(valType) << "] " << key;
        
        // Try to read and display value for simple types
        switch (static_cast<GGUFType>(valType)) {
            case GGUFType::UINT32: {
                uint32_t v; file.read(reinterpret_cast<char*>(&v), 4);
                std::cout << " = " << v;
                break;
            }
            case GGUFType::INT32: {
                int32_t v; file.read(reinterpret_cast<char*>(&v), 4);
                std::cout << " = " << v;
                break;
            }
            case GGUFType::FLOAT32: {
                float v; file.read(reinterpret_cast<char*>(&v), 4);
                std::cout << " = " << v;
                break;
            }
            case GGUFType::STRING: {
                uint64_t len = 0;
                file.read(reinterpret_cast<char*>(&len), 8);
                if (len < 100) {
                    std::string s(len, '\0');
                    file.read(s.data(), len);
                    std::cout << " = \"" << s << "\"";
                } else {
                    std::cout << " = [string, " << len << " bytes]";
                    file.seekg(static_cast<std::streamoff>(len), std::ios::cur);
                }
                break;
            }
            default:
                SkipValue(file, valType);
                break;
        }
        
        std::cout << std::endl;
    }

    std::cout << "------------------------------------------------------------" << std::endl;
    std::cout << std::endl;
    
    // Look for architecture-related keys
    std::cout << "Architecture-related keys to check:" << std::endl;
    std::cout << "  - general.architecture" << std::endl;
    std::cout << "  - general.name" << std::endl;
    std::cout << "  - llama.expert_count" << std::endl;
    std::cout << "  - llama.expert_used_count" << std::endl;
    std::cout << "  - deepseek.expert_count" << std::endl;
    std::cout << "  - deepseek.expert_used_count" << std::endl;
    std::cout << "  - moe.expert_count" << std::endl;
    std::cout << "  - moe.num_experts" << std::endl;

    return 0;
}
