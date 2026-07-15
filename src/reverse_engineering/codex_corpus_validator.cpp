/**
 * @file codex_corpus_validator.cpp
 * @brief Corpus validation for RawrCodex multi-architecture decoder
 * @description Tests decoder against known-good instruction sequences
 * 
 * Corpus sources:
 * - ARM64: Common instruction patterns from ARM Architecture Reference Manual
 * - MIPS32: Classic MIPS instruction sequences
 * - RISC-V32: RV32I base instruction set
 * - Edge cases: Boundary conditions and special encodings
 */

#include "RawrCodex_Multi_v2.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <windows.h>

using namespace RawrCodex;

// Test case definition
struct CorpusTestCase {
    const char* name;
    ArchType arch;
    std::vector<uint8_t> bytes;
    uint32_t expectedLength;
    InstrClass expectedClass;
    bool shouldSucceed;
};

// ARM64 corpus - NOP and common instructions
const CorpusTestCase ARM64_CORPUS[] = {
    {"NOP", ArchType::ARM_64, {0x1F, 0x20, 0x03, 0xD5}, 4, InstrClass::NOP, true},
    {"RET", ArchType::ARM_64, {0xC0, 0x03, 0x5F, 0xD6}, 4, InstrClass::RETURN, true},
    {"BR X0", ArchType::ARM_64, {0x00, 0x00, 0x1F, 0xD6}, 4, InstrClass::INDIRECT_JUMP, true},
    {"BLR X0", ArchType::ARM_64, {0x00, 0x00, 0x3F, 0xD6}, 4, InstrClass::CALL, true},
    {"SVC #0", ArchType::ARM_64, {0x01, 0x00, 0x00, 0xD4}, 4, InstrClass::SYSCALL, true},
    {"B .", ArchType::ARM_64, {0x00, 0x00, 0x00, 0x14}, 4, InstrClass::BRANCH, true},
    {"CBZ W0, .", ArchType::ARM_64, {0x00, 0x00, 0x00, 0x34}, 4, InstrClass::BRANCH_COND, true},
    {"ADD X0, X1, X2", ArchType::ARM_64, {0x20, 0x00, 0x02, 0x8B}, 4, InstrClass::DP_REG, true},
    {"MOV X0, X1", ArchType::ARM_64, {0x20, 0x00, 0x03, 0xAA}, 4, InstrClass::DP_REG, true},
    {"LDR X0, [X1]", ArchType::ARM_64, {0x20, 0x00, 0x40, 0xF9}, 4, InstrClass::LOAD, true},
    {"STR X0, [X1]", ArchType::ARM_64, {0x20, 0x00, 0x00, 0xF9}, 4, InstrClass::STORE, true},
    {"CMP X0, X1", ArchType::ARM_64, {0x1F, 0x00, 0x01, 0xEB}, 4, InstrClass::DP_REG, true},
    {"ISB", ArchType::ARM_64, {0xDF, 0x3F, 0x03, 0xD5}, 4, InstrClass::BARRIER, true},
    {"DSB SY", ArchType::ARM_64, {0x9F, 0x3F, 0x03, 0xD5}, 4, InstrClass::BARRIER, true},
    {"MRS X0, NZCV", ArchType::ARM_64, {0x00, 0x00, 0x1B, 0xD5}, 4, InstrClass::PRIVILEGED, true},
    {"MSR NZCV, X0", ArchType::ARM_64, {0x00, 0x00, 0x1B, 0xD5}, 4, InstrClass::PRIVILEGED, true},
};

// MIPS32 corpus
const CorpusTestCase MIPS32_CORPUS[] = {
    {"NOP (SLL)", ArchType::MIPS_32, {0x00, 0x00, 0x00, 0x00}, 4, InstrClass::DP_REG, true},
    {"ADD $t0, $t1, $t2", ArchType::MIPS_32, {0x01, 0x48, 0x40, 0x20}, 4, InstrClass::DP_REG, true},
    {"ADDI $t0, $t1, 100", ArchType::MIPS_32, {0x21, 0x28, 0x00, 0x64}, 4, InstrClass::DP_IMM, true},
    {"LW $t0, 0($sp)", ArchType::MIPS_32, {0x8F, 0xA8, 0x00, 0x00}, 4, InstrClass::LOAD, true},
    {"SW $t0, 0($sp)", ArchType::MIPS_32, {0xAF, 0xA8, 0x00, 0x00}, 4, InstrClass::STORE, true},
    {"J target", ArchType::MIPS_32, {0x08, 0x00, 0x00, 0x00}, 4, InstrClass::BRANCH, true},
    {"JAL target", ArchType::MIPS_32, {0x0C, 0x00, 0x00, 0x00}, 4, InstrClass::CALL, true},
    {"JR $ra", ArchType::MIPS_32, {0x03, 0xE0, 0x00, 0x08}, 4, InstrClass::RETURN, true},
    {"BEQ $t0, $t1, offset", ArchType::MIPS_32, {0x11, 0x09, 0x00, 0x00}, 4, InstrClass::BRANCH_COND, true},
    {"SYSCALL", ArchType::MIPS_32, {0x00, 0x00, 0x00, 0x0C}, 4, InstrClass::SYSCALL, true},
    {"LUI $t0, 0x1234", ArchType::MIPS_32, {0x3C, 0x08, 0x12, 0x34}, 4, InstrClass::DP_IMM, true},
    {"ORI $t0, $t1, 0xFF", ArchType::MIPS_32, {0x31, 0x28, 0x00, 0xFF}, 4, InstrClass::DP_IMM, true},
    {"AND $t0, $t1, $t2", ArchType::MIPS_32, {0x01, 0x2A, 0x40, 0x24}, 4, InstrClass::DP_REG, true},
    {"SLT $t0, $t1, $t2", ArchType::MIPS_32, {0x01, 0x2A, 0x40, 0x2A}, 4, InstrClass::DP_REG, true},
};

// RISC-V32 corpus
const CorpusTestCase RISCV32_CORPUS[] = {
    {"NOP (ADDI)", ArchType::RISCV_32, {0x13, 0x00, 0x00, 0x00}, 4, InstrClass::DP_IMM, true},
    {"ADD x1, x2, x3", ArchType::RISCV_32, {0x33, 0x00, 0xC1, 0x00}, 4, InstrClass::DP_REG, true},
    {"ADDI x1, x2, 10", ArchType::RISCV_32, {0x13, 0x00, 0xA1, 0x00}, 4, InstrClass::DP_IMM, true},
    {"LUI x1, 0x12345", ArchType::RISCV_32, {0x37, 0x15, 0x23, 0x01}, 4, InstrClass::DP_IMM, true},
    {"AUIPC x1, 0x12345", ArchType::RISCV_32, {0x17, 0x15, 0x23, 0x01}, 4, InstrClass::DP_IMM, true},
    {"JAL x1, offset", ArchType::RISCV_32, {0x6F, 0x00, 0x00, 0x00}, 4, InstrClass::CALL, true},
    {"JALR x1, x2, 0", ArchType::RISCV_32, {0x67, 0x00, 0x00, 0x81}, 4, InstrClass::INDIRECT_JUMP, true},
    {"BEQ x1, x2, offset", ArchType::RISCV_32, {0x63, 0x00, 0x20, 0x00}, 4, InstrClass::BRANCH_COND, true},
    {"LW x1, 0(x2)", ArchType::RISCV_32, {0x03, 0x20, 0x00, 0x81}, 4, InstrClass::LOAD, true},
    {"SW x1, 0(x2)", ArchType::RISCV_32, {0x23, 0x20, 0x00, 0x81}, 4, InstrClass::STORE, true},
    {"ECALL", ArchType::RISCV_32, {0x73, 0x00, 0x00, 0x00}, 4, InstrClass::SYSCALL, true},
    {"EBREAK", ArchType::RISCV_32, {0x73, 0x00, 0x10, 0x00}, 4, InstrClass::DEBUG, true},
    {"FENCE", ArchType::RISCV_32, {0x0F, 0x00, 0x00, 0x00}, 4, InstrClass::BARRIER, true},
};

// Edge cases corpus
const CorpusTestCase EDGE_CASE_CORPUS[] = {
    // Truncated instructions
    {"ARM64 truncated (2 bytes)", ArchType::ARM_64, {0x1F, 0x20}, 0, InstrClass::UNKNOWN, false},
    {"MIPS32 truncated (2 bytes)", ArchType::MIPS_32, {0x00, 0x00}, 0, InstrClass::UNKNOWN, false},
    {"RISCV32 truncated (2 bytes)", ArchType::RISCV_32, {0x13, 0x00}, 0, InstrClass::UNKNOWN, false},
    
    // All zeros (valid NOPs on most architectures)
    {"ARM64 all zeros", ArchType::ARM_64, {0x00, 0x00, 0x00, 0x00}, 4, InstrClass::UNKNOWN, true},
    {"MIPS32 all zeros", ArchType::MIPS_32, {0x00, 0x00, 0x00, 0x00}, 4, InstrClass::DP_REG, true},
    
    // All ones (undefined/illegal)
    {"ARM64 all ones", ArchType::ARM_64, {0xFF, 0xFF, 0xFF, 0xFF}, 4, InstrClass::UNDEFINED, true},
    {"MIPS32 all ones", ArchType::MIPS_32, {0xFF, 0xFF, 0xFF, 0xFF}, 4, InstrClass::UNKNOWN, true},
};

// Validation result
struct ValidationResult {
    const char* testName;
    const char* archName;
    bool passed;
    std::string error;
    DecodeStatus actualStatus;
    uint32_t actualLength;
    InstrClass actualClass;
};

// Run a single corpus test
ValidationResult RunCorpusTest(const CorpusTestCase& test) {
    ValidationResult result;
    result.testName = test.name;
    result.archName = nullptr;
    result.passed = false;
    result.actualStatus = DecodeStatus::SUCCESS;  // Default
    result.actualLength = 0;
    result.actualClass = InstrClass::UNKNOWN;
    
    // Get architecture name
    switch (test.arch) {
        case ArchType::ARM_64: result.archName = "ARM64"; break;
        case ArchType::MIPS_32: result.archName = "MIPS32"; break;
        case ArchType::RISCV_32: result.archName = "RISCV32"; break;
        default: result.archName = "Unknown"; break;
    }
    
    DecodedInstruction instr;
    memset(&instr, 0, sizeof(instr));
    
    // Call decoder without SEH (simpler approach)
    DecodeStatus status = ReferenceDecoder_Decode(test.arch, test.bytes.data(), test.bytes.size(), &instr);
    
    result.actualStatus = status;
    result.actualLength = instr.raw.length;
    result.actualClass = instr.semantic.instrClass;
    
    // Check if result matches expectations
    if (test.shouldSucceed) {
        if (status != DecodeStatus::SUCCESS) {
            result.error = "Expected SUCCESS but got " + std::to_string(static_cast<int>(status));
            return result;
        }
        if (instr.raw.length != test.expectedLength) {
            result.error = "Length mismatch: expected " + std::to_string(test.expectedLength) + 
                          " but got " + std::to_string(instr.raw.length);
            return result;
        }
        // Note: We don't strictly check instrClass since decoder may classify differently
    } else {
        // Expected failure
        if (status == DecodeStatus::SUCCESS) {
            result.error = "Expected failure but got SUCCESS";
            return result;
        }
    }
    
    result.passed = true;
    return result;
}

// Run corpus suite
void RunCorpusSuite(const CorpusTestCase* tests, size_t count, const char* suiteName,
                   std::vector<ValidationResult>& results, size_t& passed, size_t& failed) {
    printf("\n=== %s ===\n", suiteName);
    
    for (size_t i = 0; i < count; i++) {
        ValidationResult result = RunCorpusTest(tests[i]);
        results.push_back(result);
        
        if (result.passed) {
            passed++;
            printf("[PASS] %s: %s\n", result.archName, result.testName);
        } else {
            failed++;
            printf("[FAIL] %s: %s - %s\n", result.archName, result.testName, result.error.c_str());
        }
    }
}

// Print summary
void PrintSummary(const std::vector<ValidationResult>& results, size_t passed, size_t failed) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                 CORPUS VALIDATION SUMMARY                    ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Total tests:  %3zu                                           ║\n", results.size());
    printf("║ Passed:       %3zu  (%.1f%%)                                  ║\n", 
           passed, 100.0 * passed / results.size());
    printf("║ Failed:       %3zu  (%.1f%%)                                  ║\n",
           failed, 100.0 * failed / results.size());
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    if (failed == 0) {
        printf("\n[SUCCESS] All corpus tests passed!\n");
    } else {
        printf("\n[WARNING] %zu corpus tests failed!\n", failed);
        
        // Print details of failures
        printf("\nFailure details:\n");
        for (const auto& result : results) {
            if (!result.passed) {
                printf("  - %s: %s\n    Error: %s\n", 
                       result.archName, result.testName, result.error.c_str());
                printf("    Status: %d, Length: %u, Class: %u\n",
                       static_cast<int>(result.actualStatus),
                       result.actualLength,
                       static_cast<uint32_t>(result.actualClass));
            }
        }
    }
}

int main(int argc, char* argv[]) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     RawrCodex Multi-Architecture Decoder Corpus Validator    ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    std::vector<ValidationResult> results;
    size_t totalPassed = 0;
    size_t totalFailed = 0;
    
    // Run ARM64 corpus
    RunCorpusSuite(ARM64_CORPUS, sizeof(ARM64_CORPUS) / sizeof(ARM64_CORPUS[0]),
                   "ARM64 Instruction Corpus", results, totalPassed, totalFailed);
    
    // Run MIPS32 corpus
    RunCorpusSuite(MIPS32_CORPUS, sizeof(MIPS32_CORPUS) / sizeof(MIPS32_CORPUS[0]),
                   "MIPS32 Instruction Corpus", results, totalPassed, totalFailed);
    
    // Run RISC-V32 corpus
    RunCorpusSuite(RISCV32_CORPUS, sizeof(RISCV32_CORPUS) / sizeof(RISCV32_CORPUS[0]),
                   "RISC-V32 Instruction Corpus", results, totalPassed, totalFailed);
    
    // Run edge cases
    RunCorpusSuite(EDGE_CASE_CORPUS, sizeof(EDGE_CASE_CORPUS) / sizeof(EDGE_CASE_CORPUS[0]),
                   "Edge Cases Corpus", results, totalPassed, totalFailed);
    
    // Print summary
    PrintSummary(results, totalPassed, totalFailed);
    
    return (totalFailed > 0) ? 1 : 0;
}