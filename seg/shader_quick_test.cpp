// Quick shader test - minimal setup
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>

std::vector<uint32_t> LoadSPIRV(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint32_t> code(size / 4);
    file.read(reinterpret_cast<char*>(code.data()), size);
    return code;
}

int main() {
    std::cout << "Quick Shader Test" << std::endl;
    std::cout << "=================" << std::endl;

    // Load shader
    auto code = LoadSPIRV("d:/rawrxd/src/inference/shaders/matmul_fp16.spv");
    if (code.empty()) {
        std::cout << "Failed to load shader" << std::endl;
        return 1;
    }
    std::cout << "Shader loaded: " << code.size() * 4 << " bytes" << std::endl;

    // Check SPIR-V magic
    if (code[0] == 0x07230203) {
        std::cout << "SPIR-V magic valid" << std::endl;
    } else {
        std::cout << "Invalid SPIR-V magic: 0x" << std::hex << code[0] << std::dec << std::endl;
    }

    // Parse version
    uint32_t versionWord = code[1];
    uint32_t major = (versionWord >> 16) & 0xFF;
    uint32_t minor = (versionWord >> 8) & 0xFF;
    std::cout << "SPIR-V version: " << major << "." << minor << std::endl;

    // Parse generator
    uint32_t genWord = code[2];
    uint32_t genTool = genWord >> 16;
    std::cout << "Generator tool: " << genTool << std::endl;

    // Parse bound
    std::cout << "ID bound: " << code[3] << std::endl;

    // Count instructions
    size_t wordCount = code.size();
    std::cout << "Total words: " << wordCount << std::endl;

    // Try to find OpEntryPoint
    for (size_t i = 5; i < wordCount - 1; i++) {
        uint16_t opcode = code[i] & 0xFFFF;
        if (opcode == 15) { // OpEntryPoint
            std::cout << "Found OpEntryPoint at word " << i << std::endl;
            break;
        }
    }

    std::cout << "Shader validation complete" << std::endl;
    return 0;
}
