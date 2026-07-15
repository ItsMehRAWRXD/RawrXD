/**
 * @file test_multi_arch_simple.cpp
 * @brief Standalone Multi-Architecture Decoder Test
 * @description Tests decoder functions directly without full RawrCodex context
 * 
 * @version 1.0.0
 */

#include <iostream>
#include <iomanip>
#include <cstring>

// Architecture type constants (must match RawrCodex.asm)
enum ArchType : uint32_t {
    X86_32      = 0,
    X86_64      = 1,
    ARM_32      = 2,
    ARM_64      = 3,
    THUMB       = 4,
    THUMB2      = 5,
    MIPS_32     = 6,
    MIPS_64     = 7,
    RISCV_32    = 8,
    RISCV_64    = 9
};

// Instruction classes
enum InstrClass : uint32_t {
    DP_REG      = 0,
    DP_IMM      = 1,
    BRANCH      = 2,
    LDST        = 3,
    SIMD        = 4,
    UNKNOWN     = 5
};

// Multi-arch instruction structure (must match RawrCodex.asm)
#pragma pack(push, 1)
struct MultiInstruction {
    uint64_t    va;
    uint32_t    instrSize;
    ArchType    archType;
    uint8_t     rawBytes[16];
    uint32_t    opcode;
    uint32_t    subOpcode;
    uint32_t    regRd;
    uint32_t    regRs1;
    uint32_t    regRs2;
    uint32_t    regRs3;
    uint32_t    immValue;
    uint32_t    flags;
    uint32_t    condCode;
    InstrClass  instrClass;
    int         isBranch;
    int         isCall;
    int         isReturn;
    int         isConditional;
    int         isLoad;
    int         isStore;
    char        szMnemonic[32];
    char        szOperands[64];
    char        szComment[64];
};
#pragma pack(pop)

// External assembly functions
extern "C" {
    __declspec(dllimport) uint32_t RawrDisasm_ARM_Decode(
        void* ctx,
        uint32_t archType,
        uint64_t va,
        const uint8_t* bytes,
        MultiInstruction* outInstr
    );

    __declspec(dllimport) uint32_t RawrDisasm_MIPS_Decode(
        void* ctx,
        uint32_t archType,
        uint64_t va,
        const uint8_t* bytes,
        MultiInstruction* outInstr
    );

    __declspec(dllimport) uint32_t RawrDisasm_RISCV_Decode(
        void* ctx,
        uint32_t archType,
        uint64_t va,
        const uint8_t* bytes,
        MultiInstruction* outInstr
    );
}

// Test data for various architectures

// ARM64: mov x0, #0x1234; ret
static const uint8_t arm64_code[] = {
    0x00, 0x02, 0x82, 0xD2,  // mov x0, #0x1234
    0xC0, 0x03, 0x5F, 0xD6   // ret
};

// ARM32: mov r0, #0x1234; bx lr
static const uint8_t arm32_code[] = {
    0x34, 0x12, 0x00, 0xE3,  // mov r0, #0x1234
    0x1E, 0xFF, 0x2F, 0xE1   // bx lr
};

// Thumb: movs r0, #0x34; bx lr
static const uint8_t thumb_code[] = {
    0x34, 0x20,        // movs r0, #0x34
    0x70, 0x47         // bx lr
};

// MIPS: li $v0, 0x1234; jr $ra
static const uint8_t mips_code[] = {
    0x34, 0x12, 0x02, 0x24,  // li $v0, 0x1234
    0x08, 0x00, 0xE0, 0x03   // jr $ra
};

// RISC-V: li a0, 0x1234; ret
static const uint8_t riscv_code[] = {
    0x13, 0x15, 0x82, 0x01,  // addi a0, gp, 0x1234
    0x67, 0x80, 0x00, 0x00   // ret
};

void PrintInstruction(const MultiInstruction& instr) {
    std::cout << "  Address: 0x" << std::hex << instr.va << std::dec << "\n";
    std::cout << "  Size: " << instr.instrSize << " bytes\n";
    std::cout << "  Arch: " << static_cast<int>(instr.archType) << "\n";
    std::cout << "  Opcode: 0x" << std::hex << instr.opcode << std::dec << "\n";
    std::cout << "  Rd: " << instr.regRd << ", Rs1: " << instr.regRs1 
              << ", Rs2: " << instr.regRs2 << "\n";
    std::cout << "  Flags: branch=" << instr.isBranch 
              << " call=" << instr.isCall 
              << " ret=" << instr.isReturn << "\n";
    std::cout << "  Mnemonic: " << instr.szMnemonic << "\n";
    std::cout << "  Operands: " << instr.szOperands << "\n";
}

bool TestARM64() {
    std::cout << "\n=== Testing ARM64 Decoder ===\n";
    
    MultiInstruction instr;
    std::memset(&instr, 0, sizeof(instr));
    
    // Call decoder directly - pass nullptr for ctx (decoder doesn't use it)
    uint32_t result = RawrDisasm_ARM_Decode(nullptr, ARM_64, 0x1000, arm64_code, &instr);
    
    if (result > 0) {
        std::cout << "  [PASS] Decoded " << result << " bytes\n";
        PrintInstruction(instr);
        return true;
    } else {
        std::cout << "  [FAIL] Could not decode instruction (result=" << result << ")\n";
        return false;
    }
}

bool TestARM32() {
    std::cout << "\n=== Testing ARM32 Decoder ===\n";
    
    MultiInstruction instr;
    std::memset(&instr, 0, sizeof(instr));
    
    uint32_t result = RawrDisasm_ARM_Decode(nullptr, ARM_32, 0x1000, arm32_code, &instr);
    
    if (result > 0) {
        std::cout << "  [PASS] Decoded " << result << " bytes\n";
        PrintInstruction(instr);
        return true;
    } else {
        std::cout << "  [FAIL] Could not decode instruction (result=" << result << ")\n";
        return false;
    }
}

bool TestThumb() {
    std::cout << "\n=== Testing Thumb Decoder ===\n";
    
    MultiInstruction instr;
    std::memset(&instr, 0, sizeof(instr));
    
    uint32_t result = RawrDisasm_ARM_Decode(nullptr, THUMB, 0x1000, thumb_code, &instr);
    
    if (result > 0) {
        std::cout << "  [PASS] Decoded " << result << " bytes\n";
        PrintInstruction(instr);
        return true;
    } else {
        std::cout << "  [FAIL] Could not decode instruction (result=" << result << ")\n";
        return false;
    }
}

bool TestMIPS() {
    std::cout << "\n=== Testing MIPS32 Decoder ===\n";
    
    MultiInstruction instr;
    std::memset(&instr, 0, sizeof(instr));
    
    uint32_t result = RawrDisasm_MIPS_Decode(nullptr, MIPS_32, 0x1000, mips_code, &instr);
    
    if (result > 0) {
        std::cout << "  [PASS] Decoded " << result << " bytes\n";
        PrintInstruction(instr);
        return true;
    } else {
        std::cout << "  [FAIL] Could not decode instruction (result=" << result << ")\n";
        return false;
    }
}

bool TestRISCV() {
    std::cout << "\n=== Testing RISC-V32 Decoder ===\n";
    
    MultiInstruction instr;
    std::memset(&instr, 0, sizeof(instr));
    
    uint32_t result = RawrDisasm_RISCV_Decode(nullptr, RISCV_32, 0x1000, riscv_code, &instr);
    
    if (result > 0) {
        std::cout << "  [PASS] Decoded " << result << " bytes\n";
        PrintInstruction(instr);
        return true;
    } else {
        std::cout << "  [FAIL] Could not decode instruction (result=" << result << ")\n";
        return false;
    }
}

int main() {
    std::cout << "========================================\n";
    std::cout << "RawrCodex Multi-Architecture Test\n";
    std::cout << "========================================\n";
    
    bool allPassed = true;
    
    // Test ARM64
    allPassed &= TestARM64();
    
    // Test ARM32
    allPassed &= TestARM32();
    
    // Test Thumb
    allPassed &= TestThumb();
    
    // Test MIPS
    allPassed &= TestMIPS();
    
    // Test RISC-V
    allPassed &= TestRISCV();
    
    std::cout << "\n========================================\n";
    if (allPassed) {
        std::cout << "All tests PASSED!\n";
    } else {
        std::cout << "Some tests FAILED!\n";
    }
    std::cout << "========================================\n";
    
    return allPassed ? 0 : 1;
}
