/**
 * @file re_framework_test.cpp
 * @brief Multi-Architecture RE Framework Test
 * @description Comprehensive tests for disassembly, assembly, and emulation
 *              across all supported architectures
 * 
 * @version 1.0.0
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

#include "rawr_arch.hpp"
#include "rawr_disasm.hpp"
#include "rawr_asm.hpp"
#include "rawr_emu.hpp"

using namespace RawrXD::RE;

// Test data for various architectures
struct TestData {
    Architecture arch;
    const char* name;
    std::vector<uint8_t> code;
    const char* expectedMnemonic;
};

// x86-64: mov rax, 0x1234; ret
static const std::vector<uint8_t> x86_64_code = {
    0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00,  // mov rax, 0x1234
    0xC3                                        // ret
};

// x86-32: mov eax, 0x1234; ret
static const std::vector<uint8_t> x86_32_code = {
    0xB8, 0x34, 0x12, 0x00, 0x00,  // mov eax, 0x1234
    0xC3                           // ret
};

// ARM64: mov x0, #0x1234; ret
static const std::vector<uint8_t> arm64_code = {
    0x00, 0x02, 0x82, 0xD2,  // mov x0, #0x1234
    0xC0, 0x03, 0x5F, 0xD6   // ret
};

// ARM32: mov r0, #0x1234; bx lr
static const std::vector<uint8_t> arm32_code = {
    0x34, 0x12, 0x00, 0xE3,  // mov r0, #0x1234
    0x1E, 0xFF, 0x2F, 0xE1   // bx lr
};

// RISC-V64: li a0, 0x1234; ret
static const std::vector<uint8_t> riscv64_code = {
    0x13, 0x15, 0x82, 0x01,  // addi a0, gp, 0x1234 (simplified)
    0x67, 0x80, 0x00, 0x00   // ret
};

// MIPS64: li $v0, 0x1234; jr $ra
static const std::vector<uint8_t> mips64_code = {
    0x34, 0x12, 0x02, 0x24,  // li $v0, 0x1234
    0x08, 0x00, 0xE0, 0x03   // jr $ra
};

static const TestData testCases[] = {
    { Architecture::X86_64, "x86-64", x86_64_code, "mov" },
    { Architecture::X86_32, "x86-32", x86_32_code, "mov" },
    { Architecture::ARM_64, "ARM64", arm64_code, "mov" },
    { Architecture::ARM_32, "ARM32", arm32_code, "mov" },
    { Architecture::RISCV_64, "RISC-V64", riscv64_code, "addi" },
    { Architecture::MIPS_64, "MIPS64", mips64_code, "li" },
};

bool TestArchitectureSupport() {
    std::cout << "=== Testing Architecture Support ===" << std::endl;
    
    auto archs = GetSupportedArchitectures();
    std::cout << "Supported architectures: " << archs.size() << std::endl;
    
    for (const auto& arch : archs) {
        const ArchInfo* info = GetArchInfo(arch);
        if (info) {
            std::cout << "  " << info->name << " (" << info->bits << "-bit)" << std::endl;
        }
    }
    
    return !archs.empty();
}

bool TestDisassembly() {
    std::cout << "\n=== Testing Disassembly ===" << std::endl;
    
    bool allPassed = true;
    
    for (const auto& test : testCases) {
        std::cout << "Testing " << test.name << "... ";
        
        DisasmConfig config;
        config.arch = test.arch;
        config.baseAddress = 0x1000;
        
        Disassembler disasm(config);
        if (!disasm.IsValid()) {
            std::cout << "SKIP (not supported)" << std::endl;
            continue;
        }
        
        auto instructions = disasm.Disassemble(test.code.data(), test.code.size());
        
        if (instructions.empty()) {
            std::cout << "FAIL (no instructions)" << std::endl;
            allPassed = false;
            continue;
        }
        
        // Check first instruction mnemonic
        if (instructions[0].mnemonic.find(test.expectedMnemonic) != std::string::npos) {
            std::cout << "PASS" << std::endl;
        } else {
            std::cout << "FAIL (got: " << instructions[0].mnemonic << ")" << std::endl;
            allPassed = false;
        }
    }
    
    return allPassed;
}

bool TestAssembly() {
    std::cout << "\n=== Testing Assembly ===" << std::endl;
    
    bool allPassed = true;
    
    // Test x86-64 assembly
    std::cout << "Testing x86-64 assembly... ";
    AsmConfig config;
    config.arch = Architecture::X86_64;
    
    Assembler asm_(config);
    if (!asm_.IsValid()) {
        std::cout << "SKIP (not supported)" << std::endl;
    } else {
        auto result = asm_.Assemble("mov rax, 0x1234");
        if (result.success && result.machineCode.size() > 0) {
            std::cout << "PASS (" << result.machineCode.size() << " bytes)" << std::endl;
        } else {
            std::cout << "FAIL: " << result.errorMessage << std::endl;
            allPassed = false;
        }
    }
    
    // Test ARM64 assembly
    std::cout << "Testing ARM64 assembly... ";
    config.arch = Architecture::ARM_64;
    Assembler asm2(config);
    if (!asm2.IsValid()) {
        std::cout << "SKIP (not supported)" << std::endl;
    } else {
        auto result = asm2.Assemble("mov x0, #0x1234");
        if (result.success && result.machineCode.size() > 0) {
            std::cout << "PASS (" << result.machineCode.size() << " bytes)" << std::endl;
        } else {
            std::cout << "FAIL: " << result.errorMessage << std::endl;
            allPassed = false;
        }
    }
    
    return allPassed;
}

bool TestEmulation() {
    std::cout << "\n=== Testing Emulation ===" << std::endl;
    
    bool allPassed = true;
    
    // Test x86-64 emulation
    std::cout << "Testing x86-64 emulation... ";
    
    EmuConfig config;
    config.arch = Architecture::X86_64;
    
    Emulator emu(config);
    if (!emu.Initialize()) {
        std::cout << "SKIP (not supported)" << std::endl;
    } else {
        // Map code memory
        if (!emu.MapMemory(0x1000, 0x1000, MemPermission::READ_EXEC)) {
            std::cout << "FAIL (map memory)" << std::endl;
            allPassed = false;
        } else {
            // Write code: mov rax, 0x1234; ret
            uint8_t code[] = {0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00, 0xC3};
            if (!emu.WriteMemory(0x1000, code, sizeof(code))) {
                std::cout << "FAIL (write memory)" << std::endl;
                allPassed = false;
            } else {
                // Set instruction pointer
                if (!emu.SetInstructionPointer(0x1000)) {
                    std::cout << "FAIL (set IP)" << std::endl;
                    allPassed = false;
                } else {
                    // Emulate
                    auto result = emu.Emulate(0x1000, 0, 0, 10);
                    if (result.success) {
                        // Check RAX value
                        uint64_t rax = 0;
                        if (emu.ReadRegister(UC_X86_REG_RAX, rax) && rax == 0x1234) {
                            std::cout << "PASS (RAX=0x" << std::hex << rax << ")" << std::endl;
                        } else {
                            std::cout << "FAIL (wrong RAX value)" << std::endl;
                            allPassed = false;
                        }
                    } else {
                        std::cout << "FAIL: " << result.errorMessage << std::endl;
                        allPassed = false;
                    }
                }
            }
        }
    }
    
    return allPassed;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Multi-Architecture RE Framework" << std::endl;
    std::cout << "Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    
    bool allPassed = true;
    
    allPassed &= TestArchitectureSupport();
    allPassed &= TestDisassembly();
    allPassed &= TestAssembly();
    allPassed &= TestEmulation();
    
    std::cout << "\n========================================" << std::endl;
    if (allPassed) {
        std::cout << "All tests PASSED!" << std::endl;
        return 0;
    } else {
        std::cout << "Some tests FAILED!" << std::endl;
        return 1;
    }
}
