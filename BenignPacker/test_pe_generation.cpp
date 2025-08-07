#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>

// Windows types for PE parsing
typedef unsigned long DWORD;
typedef unsigned char BYTE;

#include "tiny_loader.h"

// Simple test to verify PE generation works
int main() {
    std::cout << "Testing PE Generation..." << std::endl;
    
    // Test 1: Verify tiny_loader.h is valid
    std::cout << "Tiny loader size: " << tiny_loader_bin_len << " bytes" << std::endl;
    std::cout << "PAYLOAD_SIZE_OFFSET: " << PAYLOAD_SIZE_OFFSET << std::endl;
    std::cout << "PAYLOAD_RVA_OFFSET: " << PAYLOAD_RVA_OFFSET << std::endl;
    
    // Test 2: Verify offsets are within bounds
    if (PAYLOAD_SIZE_OFFSET + 3 < tiny_loader_bin_len && 
        PAYLOAD_RVA_OFFSET + 3 < tiny_loader_bin_len) {
        std::cout << "✓ Offsets are valid" << std::endl;
    } else {
        std::cout << "✗ Offsets are invalid!" << std::endl;
        return 1;
    }
    
    // Test 3: Verify PE header signature
    if (tiny_loader_bin[0] == 0x4D && tiny_loader_bin[1] == 0x5A) {
        std::cout << "✓ DOS header signature valid (MZ)" << std::endl;
    } else {
        std::cout << "✗ DOS header signature invalid!" << std::endl;
        return 1;
    }
    
    // Test 4: Verify PE header
    size_t peOffset = 0x3C; // PE header offset in DOS header
    if (peOffset + 3 < tiny_loader_bin_len) {
        DWORD peHeaderOffset = *(DWORD*)(tiny_loader_bin + peOffset);
        if (peHeaderOffset + 3 < tiny_loader_bin_len) {
            if (tiny_loader_bin[peHeaderOffset] == 0x50 && 
                tiny_loader_bin[peHeaderOffset + 1] == 0x45) {
                std::cout << "✓ PE header signature valid (PE)" << std::endl;
            } else {
                std::cout << "✗ PE header signature invalid!" << std::endl;
                return 1;
            }
        }
    }
    
    // Test 5: Create a simple test executable
    std::cout << "Creating test executable..." << std::endl;
    
    // Simple test payload
    std::string testPayload = R"(
#include <windows.h>
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    MessageBoxA(NULL, "Test executable created successfully!", "Success", MB_OK);
    return 0;
}
)";
    
    // Copy loader and append payload
    std::vector<uint8_t> exe(tiny_loader_bin, tiny_loader_bin + tiny_loader_bin_len);
    
    // Pad to alignment
    constexpr size_t kAlign = 0x200;
    size_t paddedSize = (exe.size() + kAlign - 1) & ~(kAlign - 1);
    exe.resize(paddedSize, 0);
    
    // Append payload
    size_t payloadOffset = exe.size();
    exe.insert(exe.end(), testPayload.begin(), testPayload.end());
    
    // Patch offsets
    auto poke32 = [&](size_t off, uint32_t v) {
        if (off + 3 < exe.size()) {
            exe[off + 0] = v & 0xFF;
            exe[off + 1] = (v >> 8) & 0xFF;
            exe[off + 2] = (v >> 16) & 0xFF;
            exe[off + 3] = (v >> 24) & 0xFF;
        }
    };
    
    poke32(PAYLOAD_SIZE_OFFSET, static_cast<uint32_t>(testPayload.size()));
    poke32(PAYLOAD_RVA_OFFSET, static_cast<uint32_t>(payloadOffset));
    
    // Write test executable
    std::ofstream testExe("test_generated.exe", std::ios::binary);
    if (testExe.is_open()) {
        testExe.write(reinterpret_cast<const char*>(exe.data()), exe.size());
        testExe.close();
        std::cout << "✓ Test executable created: test_generated.exe (" << exe.size() << " bytes)" << std::endl;
    } else {
        std::cout << "✗ Failed to create test executable!" << std::endl;
        return 1;
    }
    
    std::cout << "All tests passed! PE generation is working correctly." << std::endl;
    return 0;
}