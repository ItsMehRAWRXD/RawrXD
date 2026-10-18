#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>

std::string ReadGGUFStr(std::ifstream& f) {
    uint64_t len = 0;
    f.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (!f || len > 4096) return "";
    std::vector<char> buf(len);
    f.read(buf.data(), len);
    return std::string(buf.data(), len);
}

void SkipPayload(uint32_t type, std::ifstream& f) {
    if (type <= 7) { uint32_t sz[] = {1,1,2,2,4,4,4,8}; f.seekg(sz[type & 7], std::ios::cur); }
    else if (type == 8) f.seekg(1, std::ios::cur);
    else if (type == 9) ReadGGUFStr(f);
    else {
        uint32_t sub = 0; uint64_t len = 0;
        f.read(reinterpret_cast<char*>(&sub), sizeof(sub));
        f.read(reinterpret_cast<char*>(&len), sizeof(len));
        if (sub == 9) { for(uint64_t i=0; i<len; ++i) ReadGGUFStr(f); }
        else { uint32_t sz[] = {1,1,2,2,4,4,4,8}; f.seekg(len * sz[sub & 7], std::ios::cur); }
    }
}

int main() {
    std::string path = R"(G:\~dev\rawrxd\models\phi3-mini-Q2_K.gguf)";
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        std::cerr << "Cannot open file\n";
        return 1;
    }
    
    uint32_t magic, version;
    f.read(reinterpret_cast<char*>(&magic), 4);
    f.read(reinterpret_cast<char*>(&version), 4);
    std::cout << "Magic: 0x" << std::hex << magic << " (GGUF=" << std::hex << 0x46554747 << ")\n";
    std::cout << "Version: " << std::dec << version << "\n";
    
    uint64_t tensorCount, kvCount;
    f.read(reinterpret_cast<char*>(&tensorCount), 8);
    f.read(reinterpret_cast<char*>(&kvCount), 8);
    std::cout << "Tensor count: " << tensorCount << "\n";
    std::cout << "KV count: " << kvCount << "\n";
    
    std::cout << "\n=== ALL METADATA KEYS ===\n";
    for (uint64_t i = 0; i < kvCount; ++i) {
        std::string key = ReadGGUFStr(f);
        uint32_t type = 0;
        f.read(reinterpret_cast<char*>(&type), sizeof(type));
        
        // Print key and type
        std::cout << "[" << i << "] Key: '" << key << "' Type: " << type;
        
        // For simple types, read and print value
        if (type <= 7) {
            uint32_t sz[] = {1,1,2,2,4,4,4,8};
            if (type == 5 || type == 6) { // uint64 or int64
                uint64_t val = 0;
                f.read(reinterpret_cast<char*>(&val), sz[type & 7]);
                std::cout << " Value: " << val;
            } else if (type == 4) { // uint32
                uint32_t val = 0;
                f.read(reinterpret_cast<char*>(&val), 4);
                std::cout << " Value: " << val;
            } else {
                f.seekg(sz[type & 7], std::ios::cur);
            }
        } else if (type == 9) { // string
            std::string val = ReadGGUFStr(f);
            if (val.size() < 100) std::cout << " Value: '" << val << "'";
            else std::cout << " Value: [long string " << val.size() << " chars]";
        } else {
            SkipPayload(type, f);
            std::cout << " [complex/array]";
        }
        std::cout << "\n";
    }
    
    return 0;
}