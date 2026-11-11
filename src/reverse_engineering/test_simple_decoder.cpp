/**
 * @file test_simple_decoder.cpp
 * @brief Test for RawrCodex_Multi_Simple.asm
 * @description Tests the simplified multi-arch decoder
 */

#include <iostream>
#include <cstring>

// Architecture type constants (must match RawrCodex_Multi_Simple.asm)
enum ArchType : uint32_t {
    ARCH_X86_64     = 1,
    ARCH_ARM_64     = 3,
    ARCH_MIPS_32    = 6,
    ARCH_RISCV_32   = 8
};

// External assembly functions from RawrCodex_Multi_Simple.asm
extern "C" {
    __declspec(dllimport) uint32_t SimpleDecoder(
        uint32_t archType,
        const uint8_t* bytes,
        char* outputBuffer
    );

    __declspec(dllimport) void GetArchitectureName(
        uint32_t archType,
        char* outputBuffer
    );
}

int main() {
    std::cout << "=== RawrCodex Multi-Architecture Decoder Test ===" << std::endl;
    std::cout << std::endl;

    char nameBuffer[64];
    char outputBuffer[256];

    // Test ARM64
    std::cout << "Testing ARM64:" << std::endl;
    GetArchitectureName(ARCH_ARM_64, nameBuffer);
    std::cout << "  Architecture: " << nameBuffer << std::endl;
    
    // ARM64 NOP: D5 03 20 DF (HINT #0x1E)
    uint8_t arm64_nop[] = { 0xDF, 0x20, 0x03, 0xD5 };
    uint32_t size = SimpleDecoder(ARCH_ARM_64, arm64_nop, outputBuffer);
    std::cout << "  NOP instruction: " << outputBuffer;
    std::cout << "  Size: " << size << " bytes" << std::endl;
    std::cout << std::endl;

    // Test MIPS32
    std::cout << "Testing MIPS32:" << std::endl;
    GetArchitectureName(ARCH_MIPS_32, nameBuffer);
    std::cout << "  Architecture: " << nameBuffer << std::endl;
    
    // MIPS NOP: 00 00 00 00 (sll $zero, $zero, 0)
    uint8_t mips_nop[] = { 0x00, 0x00, 0x00, 0x00 };
    size = SimpleDecoder(ARCH_MIPS_32, mips_nop, outputBuffer);
    std::cout << "  NOP instruction: " << outputBuffer;
    std::cout << "  Size: " << size << " bytes" << std::endl;
    std::cout << std::endl;

    // Test RISC-V
    std::cout << "Testing RISC-V:" << std::endl;
    GetArchitectureName(ARCH_RISCV_32, nameBuffer);
    std::cout << "  Architecture: " << nameBuffer << std::endl;
    
    // RISC-V NOP: addi x0, x0, 0 = 00 00 00 13
    uint8_t riscv_nop[] = { 0x13, 0x00, 0x00, 0x00 };
    size = SimpleDecoder(ARCH_RISCV_32, riscv_nop, outputBuffer);
    std::cout << "  NOP instruction: " << outputBuffer;
    std::cout << "  Size: " << size << " bytes" << std::endl;
    std::cout << std::endl;

    // Test x64
    std::cout << "Testing x86-64:" << std::endl;
    GetArchitectureName(ARCH_X86_64, nameBuffer);
    std::cout << "  Architecture: " << nameBuffer << std::endl;
    
    // x64 NOP: 90
    uint8_t x64_nop[] = { 0x90 };
    size = SimpleDecoder(ARCH_X86_64, x64_nop, outputBuffer);
    std::cout << "  NOP instruction: " << outputBuffer;
    std::cout << "  Size: " << size << " bytes" << std::endl;
    std::cout << std::endl;

    std::cout << "=== All tests completed successfully ===" << std::endl;
    return 0;
}
