// Shader embedding utility
// Converts SPIR-V binary files to C++ header arrays

#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <cstdint>

void embedShader(const char* inputPath, const char* outputPath, const char* arrayName) {
    std::ifstream file(inputPath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open: " << inputPath << std::endl;
        return;
    }
    
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
    
    std::ofstream out(outputPath, std::ios::app);
    if (!out) {
        std::cerr << "Failed to open output: " << outputPath << std::endl;
        return;
    }
    
    out << "// " << inputPath << std::endl;
    out << "const uint32_t " << arrayName << "[] = {" << std::endl;
    
    // Output as uint32_t words
    for (size_t i = 0; i < data.size(); i += 4) {
        uint32_t word = 0;
        for (size_t j = 0; j < 4 && (i + j) < data.size(); j++) {
            word |= static_cast<uint32_t>(data[i + j]) << (j * 8);
        }
        out << "    0x" << std::hex << std::setw(8) << std::setfill('0') << word;
        if (i + 4 < data.size()) out << ",";
        out << std::endl;
    }
    
    out << "};" << std::endl;
    out << "static const size_t " << arrayName << "_size = " 
        << std::dec << ((data.size() + 3) / 4) << ";" << std::endl;
    out << std::endl;
    
    std::cout << "Embedded " << inputPath << " (" << data.size() << " bytes)" << std::endl;
}

int main() {
    std::cout << "=== Embedding Phase 3 Fused Shaders ===" << std::endl;
    
    // Clear output file first
    std::ofstream clear("embedded_shaders.hpp");
    clear << "#pragma once" << std::endl;
    clear << "// Auto-generated embedded SPIR-V shaders" << std::endl;
    clear << "// Phase 3: Kernel Fusion" << std::endl;
    clear << std::endl;
    clear.close();
    
    // Embed fused shaders
    embedShader("fused_qkv_projection.spv", "embedded_shaders.hpp", "kfused_qkv_projection_spv");
    embedShader("fused_attention.spv", "embedded_shaders.hpp", "kfused_attention_spv");
    
    std::cout << "=== Done ===" << std::endl;
    return 0;
}
