#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <filesystem>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: dump_file <file>\n";
        return 1;
    }
    
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) {
        std::cerr << "Failed to open file\n";
        return 1;
    }
    
    // Read first 64 bytes
    std::vector<uint8_t> buffer(64);
    f.read(reinterpret_cast<char*>(buffer.data()), 64);
    
    std::cout << "First 64 bytes:\n";
    for (size_t i = 0; i < buffer.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << "\n";
    }
    std::cout << std::dec << "\n";
    
    // Try reading as 36-byte header + data
    f.seekg(0, std::ios::beg);
    uint32_t magic;
    f.read(reinterpret_cast<char*>(&magic), 4);
    std::cout << "Magic: 0x" << std::hex << magic << std::dec << "\n";
    
    // Check file size
    f.seekg(0, std::ios::end);
    size_t file_size = f.tellg();
    std::cout << "File size: " << file_size << " bytes\n";
    
    return 0;
}