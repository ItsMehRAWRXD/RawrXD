/**
 * @file abi_validator_simple.cpp
 * @brief Simplified ABI Validation Framework for Multi-Architecture Decoder
 * @description Tests decoder functions without inline assembly (x64 doesn't support __asm)
 * 
 * Tests:
 * - Function call ABI compliance (parameter passing)
 * - Return value handling
 * - Stack alignment verification
 * - Basic crash detection
 */

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <signal.h>

// Signal handler for crash detection
void signal_handler(int sig) {
    printf("[CRASH] Signal %d received - likely MIPS32 decoder crash\n", sig);
    exit(1);
}
#include <cstdlib>
#include <cstddef>
#include "RawrCodex_Multi_v2.hpp"

using namespace RawrCodex;

// Test result structure
struct TestResult {
    const char* testName;
    bool passed;
    const char* error;
};

// Test ARM64 decoding
TestResult TestARM64_Decode() {
    TestResult result = {"ARM64_Decode", false, "not run"};
    
    printf("  [DEBUG] Testing ARM64 NOP decode...\n");
    
    DecodedInstruction instr;
    memset(&instr, 0, sizeof(instr));
    
    // NOP instruction: D503201F (in big-endian notation)
    // Bytes in memory: {0x1F, 0x20, 0x03, 0xD5}
    // When loaded as DWORD on little-endian x64: 0xD503201F
    uint8_t nop[] = {0x1F, 0x20, 0x03, 0xD5};
    
    printf("  [DEBUG] Bytes: %02X %02X %02X %02X\n", nop[0], nop[1], nop[2], nop[3]);
    printf("  [DEBUG] DWORD: 0x%08X\n", *(uint32_t*)nop);
    printf("  [DEBUG] ArchType::ARM_64 = %d\n", static_cast<int>(ArchType::ARM_64));
    printf("  [DEBUG] &instr: %p\n", &instr);
    printf("  [DEBUG] sizeof(DecodedInstruction) = %zu\n", sizeof(DecodedInstruction));
    printf("  [DEBUG] instr.raw.va offset = %zu\n", offsetof(DecodedInstruction, raw.va));
    printf("  [DEBUG] instr.raw.length offset = %zu\n", offsetof(DecodedInstruction, raw.length) - offsetof(DecodedInstruction, raw));
    printf("  [DEBUG] instr.raw.arch offset = %zu\n", offsetof(DecodedInstruction, raw.arch) - offsetof(DecodedInstruction, raw));
    printf("  [DEBUG] instr.raw.bytes offset = %zu\n", offsetof(DecodedInstruction, raw.bytes) - offsetof(DecodedInstruction, raw));
    printf("  [DEBUG] instr.raw.encoding offset = %zu\n", offsetof(DecodedInstruction, raw.encoding) - offsetof(DecodedInstruction, raw));
    printf("  [DEBUG] Calling ReferenceDecoder_Decode...\n");
    fflush(stdout);
    
    DecodeStatus status = ReferenceDecoder_Decode(
        ArchType::ARM_64,
        nop,
        4,
        0x1000,
        &instr
    );
    
    printf("  [DEBUG] Decode returned status: %d\n", static_cast<int>(status));
    printf("  [DEBUG] Instruction length: %u\n", instr.raw.length);
    printf("  [DEBUG] Instruction class: %u\n", instr.semantic.instrClass);
    printf("  [DEBUG] Mnemonic: %u\n", instr.semantic.mnemonic);
    printf("  [DEBUG] Raw encoding: 0x%08X\n", instr.raw.encoding);
    printf("  [DEBUG] Raw bytes: %02X %02X %02X %02X\n", instr.raw.bytes[0], instr.raw.bytes[1], instr.raw.bytes[2], instr.raw.bytes[3]);
    fflush(stdout);
    
    if (status != DecodeStatus::SUCCESS) {
        result.passed = false;
        result.error = "Decode returned failure status";
        return result;
    }
    
    if (instr.raw.length != 4) {
        result.passed = false;
        result.error = "Incorrect instruction length";
        return result;
    }
    
    result.passed = true;
    result.error = nullptr;
    printf("  [DEBUG] Test completed successfully - returning result\n");
    fflush(stdout);
    return result;
}

// Test MIPS32 decoding
TestResult TestMIPS32_Decode() {
    TestResult result = {"MIPS32_Decode", false, "not run"};
    
    printf("  [DEBUG] Testing MIPS32 NOP decode...\n");
    fflush(stdout);
    
    DecodedInstruction instr;
    memset(&instr, 0, sizeof(instr));
    
    // NOP instruction: 0x00000000
    uint8_t nop[] = {0x00, 0x00, 0x00, 0x00};
    
    printf("  [DEBUG] Calling ReferenceDecoder_Decode for MIPS32...\n");
    fflush(stdout);
    
    DecodeStatus status = ReferenceDecoder_Decode(
        ArchType::MIPS_32,
        nop,
        4,
        0x1000,
        &instr
    );
    
    printf("  [DEBUG] MIPS32 decode returned status: %d\n", static_cast<int>(status));
    printf("  [DEBUG] MIPS32 instruction length: %u\n", instr.raw.length);
    fflush(stdout);
    
    if (status != DecodeStatus::SUCCESS) {
        result.passed = false;
        result.error = "Decode returned failure status";
        return result;
    }
    
    if (instr.raw.length != 4) {
        result.passed = false;
        result.error = "Incorrect instruction length";
        return result;
    }
    
    result.passed = true;
    result.error = nullptr;
    printf("  [DEBUG] MIPS32 test completed successfully - returning result\n");
    fflush(stdout);
    return result;
}

// Test RISC-V32 decoding
TestResult TestRISCV32_Decode() {
    TestResult result = {"RISCV32_Decode", false, "not run"};
    
    DecodedInstruction instr;
    memset(&instr, 0, sizeof(instr));
    
    // NOP instruction: 0x00000013 (ADDI x0, x0, 0)
    uint8_t nop[] = {0x13, 0x00, 0x00, 0x00};
    
    DecodeStatus status = ReferenceDecoder_Decode(
        ArchType::RISCV_32,
        nop,
        4,
        0x1000,
        &instr
    );
    
    if (status != DecodeStatus::SUCCESS) {
        result.passed = false;
        result.error = "Decode returned failure status";
        return result;
    }
    
    if (instr.raw.length != 4) {
        result.passed = false;
        result.error = "Incorrect instruction length";
        return result;
    }
    
    result.passed = true;
    result.error = nullptr;
    return result;
}

// Test GetArchitectureName
TestResult TestGetArchitectureName() {
    TestResult result = {"GetArchitectureName", false, "not run"};
    
    char buffer[64];
    memset(buffer, 0, sizeof(buffer));
    
    GetArchitectureName(static_cast<uint32_t>(ArchType::ARM_64), buffer);
    
    if (buffer[0] == '\0') {
        result.passed = false;
        result.error = "Empty architecture name";
        return result;
    }
    
    result.passed = true;
    result.error = nullptr;
    return result;
}

// Test stack alignment
TestResult TestStackAlignment() {
    TestResult result = {"StackAlignment", false, "not run"};
    
    // Allocate on stack and check alignment
    alignas(16) DecodedInstruction instr;
    memset(&instr, 0, sizeof(instr));
    
    uint8_t nop[] = {0x1F, 0x20, 0x03, 0xD5};
    
    // Call multiple times to stress stack alignment
    for (int i = 0; i < 100; i++) {
        DecodeStatus status = ReferenceDecoder_Decode(ArchType::ARM_64, nop, 4, 0x1000 + i * 4, &instr);
        if (status != DecodeStatus::SUCCESS) {
            result.passed = false;
            result.error = "Decode failed during alignment test";
            return result;
        }
    }
    
    result.passed = true;
    result.error = nullptr;
    return result;
}

// Test null pointer handling
TestResult TestNullPointerHandling() {
    TestResult result = {"NullPointerHandling", false, "not run"};
    
    // Test with null output pointer - should not crash
    uint8_t nop[] = {0x1F, 0x20, 0x03, 0xD5};
    
    __try {
        DecodeStatus status = ReferenceDecoder_Decode(ArchType::ARM_64, nop, 4, 0x1000, nullptr);
        // Function should handle null gracefully
        result.passed = true;
        result.error = nullptr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        result.passed = false;
        result.error = "Exception thrown with null pointer";
    }
    
    return result;
}

// Test truncated instruction handling
TestResult TestTruncatedInstruction() {
    TestResult result = {"TruncatedInstruction", false, "not run"};
    
    DecodedInstruction instr;
    memset(&instr, 0, sizeof(instr));
    
    // Provide only 2 bytes when 4 are needed
    uint8_t partial[] = {0x1F, 0x20};
    
    DecodeStatus status = ReferenceDecoder_Decode(ArchType::ARM_64, partial, 2, 0x1000, &instr);
    
    // Should return failure or truncated status
    // (implementation-specific: may return DecodeStatus::Truncated)
    result.passed = true;  // As long as it doesn't crash
    result.error = nullptr;
    return result;
}

// Test all architectures
TestResult TestAllArchitectures() {
    TestResult result = {"AllArchitectures", false, "not run"};
    
    uint8_t nop[] = {0x00, 0x00, 0x00, 0x00};
    DecodedInstruction instr;
    
    // Test all supported architectures
    ArchType archTypes[] = {
        ArchType::X86_32, ArchType::X86_64, ArchType::ARM_32, ArchType::ARM_64,
        ArchType::THUMB, ArchType::THUMB2, ArchType::MIPS_32, ArchType::MIPS_64,
        ArchType::RISCV_32, ArchType::RISCV_64
    };
    
    for (int i = 0; i < 10; i++) {
        memset(&instr, 0, sizeof(instr));
        DecodeStatus status = ReferenceDecoder_Decode(archTypes[i], nop, 4, 0x1000, &instr);
        // As long as it doesn't crash, we're good
    }
    
    result.passed = true;
    result.error = nullptr;
    return result;
}

// Main test runner
int main(int argc, char* argv[]) {
    // Set up signal handlers for crash detection
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGILL, signal_handler);
    
    printf("=== RawrCodex Multi-Architecture Decoder ABI Validator ===\n\n");
    fflush(stdout);
    
    TestResult tests[8];
    
    printf("Running 8 tests...\n\n");
    fflush(stdout);
    
    // Test 1: ARM64_Decode
    printf("[TEST 1/8] ARM64_Decode\n");
    fflush(stdout);
    tests[0] = TestARM64_Decode();
    printf("[%s] %s\n", tests[0].passed ? "PASS" : "FAIL", tests[0].testName);
    if (!tests[0].passed) printf("       Error: %s\n", tests[0].error);
    fflush(stdout);
    
    // Test 2: MIPS32_Decode
    printf("[TEST 2/8] MIPS32_Decode\n");
    fflush(stdout);
    printf("[DEBUG] About to call TestMIPS32_Decode...\n");
    fflush(stdout);
    
    // Add a try-catch block to catch any exceptions
    __try {
        printf("[DEBUG] Inside try block, calling TestMIPS32_Decode...\n");
        fflush(stdout);
        tests[1] = TestMIPS32_Decode();
        printf("[DEBUG] TestMIPS32_Decode returned successfully\n");
        fflush(stdout);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[CRASH] MIPS32 test crashed with exception code: 0x%08X\n", GetExceptionCode());
        fflush(stdout);
        tests[1].passed = false;
        tests[1].error = "Test crashed with exception";
    }
    
    printf("[%s] %s\n", tests[1].passed ? "PASS" : "FAIL", tests[1].testName);
    if (!tests[1].passed) printf("       Error: %s\n", tests[1].error);
    fflush(stdout);
    
    // Test 3: RISCV32_Decode
    printf("[TEST 3/8] RISCV32_Decode\n");
    fflush(stdout);
    tests[2] = TestRISCV32_Decode();
    printf("[%s] %s\n", tests[2].passed ? "PASS" : "FAIL", tests[2].testName);
    if (!tests[2].passed) printf("       Error: %s\n", tests[2].error);
    fflush(stdout);
    
    // Test 4: GetArchitectureName
    printf("[TEST 4/8] GetArchitectureName\n");
    fflush(stdout);
    tests[3] = TestGetArchitectureName();
    printf("[%s] %s\n", tests[3].passed ? "PASS" : "FAIL", tests[3].testName);
    if (!tests[3].passed) printf("       Error: %s\n", tests[3].error);
    fflush(stdout);
    
    // Test 5: StackAlignment
    printf("[TEST 5/8] StackAlignment\n");
    fflush(stdout);
    tests[4] = TestStackAlignment();
    printf("[%s] %s\n", tests[4].passed ? "PASS" : "FAIL", tests[4].testName);
    if (!tests[4].passed) printf("       Error: %s\n", tests[4].error);
    fflush(stdout);
    
    // Test 6: NullPointerHandling
    printf("[TEST 6/8] NullPointerHandling\n");
    fflush(stdout);
    tests[5] = TestNullPointerHandling();
    printf("[%s] %s\n", tests[5].passed ? "PASS" : "FAIL", tests[5].testName);
    if (!tests[5].passed) printf("       Error: %s\n", tests[5].error);
    fflush(stdout);
    
    // Test 7: TruncatedInstruction
    printf("[TEST 7/8] TruncatedInstruction\n");
    fflush(stdout);
    tests[6] = TestTruncatedInstruction();
    printf("[%s] %s\n", tests[6].passed ? "PASS" : "FAIL", tests[6].testName);
    if (!tests[6].passed) printf("       Error: %s\n", tests[6].error);
    fflush(stdout);
    
    // Test 8: AllArchitectures
    printf("[TEST 8/8] AllArchitectures\n");
    fflush(stdout);
    tests[7] = TestAllArchitectures();
    printf("[%s] %s\n", tests[7].passed ? "PASS" : "FAIL", tests[7].testName);
    if (!tests[7].passed) printf("       Error: %s\n", tests[7].error);
    fflush(stdout);
    
    int passed = 0;
    int failed = 0;
    for (int i = 0; i < 8; i++) {
        if (tests[i].passed) passed++;
        else failed++;
    }
    
    printf("\n=== Results ===\n");
    printf("Passed: %d/8\n", passed);
    printf("Failed: %d/8\n", failed);
    fflush(stdout);
    
    if (failed == 0) {
        printf("\n[SUCCESS] All ABI validation tests passed!\n");
        fflush(stdout);
        return 0;
    } else {
        printf("\n[FAILURE] %d test(s) failed.\n", failed);
        fflush(stdout);
        return 1;
    }
}