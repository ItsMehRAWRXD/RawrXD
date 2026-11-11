#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <filesystem>

int main() {
    std::string gguf_path = "F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    std::ifstream f(gguf_path, std::ios::binary);
    if (!f) {
        std::cerr << "Failed to open GGUF\n";
        return 1;
    }
    
    std::cerr << "File opened, size: " << std::filesystem::file_size(gguf_path) << "\n";
    std::cerr.flush();
    
    // Read header
    uint32_t magic, version;
    uint64_t tensor_count, metadata_kv_count;
    f.read(reinterpret_cast<char*>(&magic), 4);
    if (!f) { std::cerr << "Failed to read magic\n"; return 1; }
    f.read(reinterpret_cast<char*>(&version), 4);
    if (!f) { std::cerr << "Failed to read version\n"; return 1; }
    f.read(reinterpret_cast<char*>(&tensor_count), 8);
    if (!f) { std::cerr << "Failed to read tensor_count\n"; return 1; }
    f.read(reinterpret_cast<char*>(&metadata_kv_count), 8);
    if (!f) { std::cerr << "Failed to read metadata_kv_count\n"; return 1; }
    
    std::cout << "GGUF Header:\n";
    std::cout << "  Magic: 0x" << std::hex << magic << std::dec << "\n";
    std::cout << "  Version: " << version << "\n";
    std::cout << "  Tensor count: " << tensor_count << "\n";
    std::cout << "  Metadata KV count: " << metadata_kv_count << "\n";
    std::cout.flush();
    
    return 0;
}