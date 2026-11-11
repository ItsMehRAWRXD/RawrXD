/**
 * @file fuzzing_engine.cpp
 * @brief Fuzzing Infrastructure for Multi-Architecture Decoder
 * @description Generates random and malformed instruction streams to test decoder robustness
 * 
 * Fuzzing Strategies:
 * - Random bit patterns (all architectures)
 * - Valid instruction mutations
 * - Malformed encodings
 * - Edge cases (all zeros, all ones, etc.)
 * - Cross-architecture confusion
 */

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <chrono>
#include "RawrCodex_Multi_v2.hpp"

using namespace RawrCodex;

// External decoder function
extern "C" {
    __declspec(dllimport) uint32_t ReferenceDecoder_Decode(
        uint32_t arch,
        const uint8_t* bytes,
        uint32_t byteCount,
        uint64_t va,
        DecodedInstruction* out
    );
}

// Fuzzing statistics
struct FuzzStats {
    uint64_t iterations;
    uint64_t crashes;
    uint64_t hangs;
    uint64_t decodeSuccess;
    uint64_t decodeFailures;
    uint64_t malformedDetected;
    uint64_t reservedOpcodes;
    uint64_t unsupported;
};

// Random number generator
class FuzzRNG {
private:
    std::mt19937_64 m_rng;
    
public:
    FuzzRNG(uint64_t seed) : m_rng(seed) {}
    
    uint64_t Next() {
        return m_rng();
    }
    
    uint32_t Next32() {
        return static_cast<uint32_t>(m_rng());
    }
    
    uint8_t NextByte() {
        return static_cast<uint8_t>(m_rng() & 0xFF);
    }
    
    // Generate random value in range [min, max]
    uint32_t Range(uint32_t min, uint32_t max) {
        std::uniform_int_distribution<uint32_t> dist(min, max);
        return dist(m_rng);
    }
    
    // Coin flip
    bool Bool() {
        return (m_rng() & 1) != 0;
    }
};

// Generate completely random bytes
void GenerateRandomBytes(FuzzRNG& rng, uint8_t* out, uint32_t length) {
    for (uint32_t i = 0; i < length; i++) {
        out[i] = rng.NextByte();
    }
}

// Generate valid ARM64 instruction and mutate it
void GenerateMutatedARM64(FuzzRNG& rng, uint8_t* out, uint32_t* length) {
    // Start with a valid instruction
    uint32_t base;
    switch (rng.Range(0, 10)) {
        case 0: base = 0xD503201F; break;  // NOP
        case 1: base = 0x91000000; break;  // ADD
        case 2: base = 0xD2800000; break;  // MOVZ
        case 3: base = 0xF9400000; break;  // LDR
        case 4: base = 0xB9000000; break;  // STR
        case 5: base = 0x14000000; break;  // B
        case 6: base = 0x94000000; break;  // BL
        case 7: base = 0xD65F03C0; break;  // RET
        case 8: base = 0xEB000000; break;  // SUBS
        case 9: base = 0x8B000000; break;  // ADD (reg)
        default: base = 0xD503201F; break;
    }
    
    // Apply mutations
    uint32_t mutations = rng.Range(0, 5);
    for (uint32_t i = 0; i < mutations; i++) {
        uint32_t bit = rng.Range(0, 32);
        base ^= (1 << bit);
    }
    
    // Write little-endian
    out[0] = base & 0xFF;
    out[1] = (base >> 8) & 0xFF;
    out[2] = (base >> 16) & 0xFF;
    out[3] = (base >> 24) & 0xFF;
    *length = 4;
}

// Generate valid MIPS instruction and mutate it
void GenerateMutatedMIPS(FuzzRNG& rng, uint8_t* out, uint32_t* length) {
    uint32_t base;
    switch (rng.Range(0, 10)) {
        case 0: base = 0x00000000; break;  // NOP (SLL)
        case 1: base = 0x20000000; break;  // ADDI
        case 2: base = 0x3C000000; break;  // LUI
        case 3: base = 0x8C000000; break;  // LW
        case 4: base = 0xAC000000; break;  // SW
        case 5: base = 0x08000000; break;  // J
        case 6: base = 0x0C000000; break;  // JAL
        case 7: base = 0x10000000; break;  // BEQ
        case 8: base = 0x00000020; break;  // ADD
        case 9: base = 0x00000024; break;  // AND
        default: base = 0x00000000; break;
    }
    
    // Apply mutations
    uint32_t mutations = rng.Range(0, 5);
    for (uint32_t i = 0; i < mutations; i++) {
        uint32_t bit = rng.Range(0, 32);
        base ^= (1 << bit);
    }
    
    // Write big-endian
    out[0] = (base >> 24) & 0xFF;
    out[1] = (base >> 16) & 0xFF;
    out[2] = (base >> 8) & 0xFF;
    out[3] = base & 0xFF;
    *length = 4;
}

// Generate valid RISC-V instruction and mutate it
void GenerateMutatedRISCV(FuzzRNG& rng, uint8_t* out, uint32_t* length) {
    uint32_t base;
    switch (rng.Range(0, 10)) {
        case 0: base = 0x00000013; break;  // NOP (ADDI)
        case 1: base = 0x00000033; break;  // ADD
        case 2: base = 0x00000003; break;  // LB
        case 3: base = 0x00000023; break;  // SB
        case 4: base = 0x0000006F; break;  // JAL
        case 5: base = 0x00000067; break;  // JALR
        case 6: base = 0x00000063; break;  // BEQ
        case 7: base = 0x00000037; break;  // LUI
        case 8: base = 0x00000017; break;  // AUIPC
        case 9: base = 0x00000073; break;  // ECALL
        default: base = 0x00000013; break;
    }
    
    // Apply mutations
    uint32_t mutations = rng.Range(0, 5);
    for (uint32_t i = 0; i < mutations; i++) {
        uint32_t bit = rng.Range(0, 32);
        base ^= (1 << bit);
    }
    
    // Write little-endian
    out[0] = base & 0xFF;
    out[1] = (base >> 8) & 0xFF;
    out[2] = (base >> 16) & 0xFF;
    out[3] = (base >> 24) & 0xFF;
    *length = 4;
}

// Generate specific malformed patterns
void GenerateMalformedPattern(FuzzRNG& rng, ArchType arch, uint8_t* out, uint32_t* length) {
    switch (rng.Range(0, 8)) {
        case 0: // All zeros
            memset(out, 0, 16);
            *length = 4;
            break;
            
        case 1: // All ones
            memset(out, 0xFF, 16);
            *length = 4;
            break;
            
        case 2: // Alternating pattern
            for (int i = 0; i < 16; i++) {
                out[i] = (i % 2 == 0) ? 0xAA : 0x55;
            }
            *length = 4;
            break;
            
        case 3: // Truncated (only 1-3 bytes)
            *length = rng.Range(1, 3);
            for (uint32_t i = 0; i < *length; i++) {
                out[i] = rng.NextByte();
            }
            break;
            
        case 4: // Reserved opcode space
            if (arch == ArchType::ARM_64) {
                // ARM64 reserved: 0x00000000 - 0x03FFFFFF
                uint32_t val = rng.Range(0, 0x03FFFFFF);
                out[0] = val & 0xFF;
                out[1] = (val >> 8) & 0xFF;
                out[2] = (val >> 16) & 0xFF;
                out[3] = (val >> 24) & 0xFF;
            } else {
                GenerateRandomBytes(rng, out, 4);
            }
            *length = 4;
            break;
            
        case 5: // Very long encoding (x86-style)
            *length = rng.Range(5, 15);
            for (uint32_t i = 0; i < *length; i++) {
                out[i] = rng.NextByte();
            }
            break;
            
        case 6: // Invalid compressed (RISC-V/Thumb)
            out[0] = 0x03;  // Invalid compressed prefix
            out[1] = rng.NextByte();
            *length = 2;
            break;
            
        case 7: // Privileged instruction in user mode
            if (arch == ArchType::ARM_64) {
                // MRS/MSR
                out[0] = 0x00;
                out[1] = 0x00;
                out[2] = 0x1B;
                out[3] = 0xD5;
            } else {
                GenerateRandomBytes(rng, out, 4);
            }
            *length = 4;
            break;
            
        default:
            GenerateRandomBytes(rng, out, 4);
            *length = 4;
    }
}

// Generate instruction for specific architecture
void GenerateInstruction(FuzzRNG& rng, ArchType arch, uint8_t* out, 
                         uint32_t* length, bool valid) {
    if (!valid) {
        GenerateMalformedPattern(rng, arch, out, length);
        return;
    }
    
    switch (arch) {
        case ArchType::ARM_64:
            GenerateMutatedARM64(rng, out, length);
            break;
            
        case ArchType::MIPS_32:
        case ArchType::MIPS_64:
            GenerateMutatedMIPS(rng, out, length);
            break;
            
        case ArchType::RISCV_32:
        case ArchType::RISCV_64:
            GenerateMutatedRISCV(rng, out, length);
            break;
            
        default:
            GenerateRandomBytes(rng, out, 4);
            *length = 4;
    }
}

// Run single fuzz iteration
bool FuzzIteration(FuzzRNG& rng, ArchType arch, FuzzStats& stats) {
    uint8_t bytes[16];
    uint32_t length;
    
    // 50% chance of valid vs malformed
    bool valid = rng.Bool();
    GenerateInstruction(rng, arch, bytes, &length, valid);
    
    DecodedInstruction result;
    memset(&result, 0, sizeof(result));
    
    // Set up output pointer on stack
    DecodedInstruction* outPtr = &result;
    
    // Call decoder with exception handling
    bool crashed = false;
    uint32_t status = DECODE_UNSUPPORTED;
    
    __try {
        // Use inline assembly to call with proper stack setup
        uint32_t archVal = static_cast<uint32_t>(arch);
        uint64_t va = 0x1000;
        
        // Call through function pointer to avoid inline asm complexity
        status = ReferenceDecoder_Decode(archVal, bytes, length, va, outPtr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        crashed = true;
        DWORD code = GetExceptionCode();
        (void)code; // Could log this
    }
    
    if (crashed) {
        stats.crashes++;
        return false;
    }
    
    stats.iterations++;
    
    // Track decode results
    if (status == 0) { // SUCCESS
        stats.decodeSuccess++;
    } else {
        stats.decodeFailures++;
        
        switch (status) {
            case 4: // DECODE_MALFORMED
                stats.malformedDetected++;
                break;
            case 5: // DECODE_RESERVED
                stats.reservedOpcodes++;
                break;
            case 6: // DECODE_UNSUPPORTED
                stats.unsupported++;
                break;
        }
    }
    
    return true;
}

// Run fuzzing session
bool RunFuzzing(const FuzzingEngine::FuzzConfig& config, FuzzingEngine::FuzzResult* result) {
    printf("=== Fuzzing Session ===\n");
    printf("Seed: %llu\n", config.seed);
    printf("Iterations: %llu\n", config.iterationCount);
    printf("Architecture: %u\n", static_cast<uint32_t>(config.targetArch));
    printf("Test malformed: %s\n", config.testMalformed ? "yes" : "no");
    printf("Test truncated: %s\n", config.testTruncated ? "yes" : "no");
    printf("\n");
    
    FuzzRNG rng(config.seed);
    FuzzStats stats = {};
    
    // Progress reporting
    const uint64_t reportInterval = config.iterationCount / 10;
    uint64_t nextReport = reportInterval;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    for (uint64_t i = 0; i < config.iterationCount; i++) {
        if (!FuzzIteration(rng, config.targetArch, stats)) {
            printf("\n[CRASH] Detected at iteration %llu\n", i);
            // Continue to find more crashes
        }
        
        // Progress report
        if (i >= nextReport) {
            printf("Progress: %llu/%llu (%.1f%%), Crashes: %llu\n",
                   i, config.iterationCount,
                   (100.0 * i) / config.iterationCount,
                   stats.crashes);
            nextReport += reportInterval;
        }
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    // Fill result
    result->iterations = stats.iterations;
    result->crashes = stats.crashes;
    result->hangs = stats.hangs;
    result->decodeFailures = stats.decodeFailures;
    result->validationErrors = 0; // Not tracking in basic fuzzing
    
    // Print summary
    printf("\n=== Fuzzing Results ===\n");
    printf("Duration: %.2f seconds\n", duration.count() / 1000.0);
    printf("Iterations: %llu\n", stats.iterations);
    printf("Crashes: %llu\n", stats.crashes);
    printf("Decode success: %llu\n", stats.decodeSuccess);
    printf("Decode failures: %llu\n", stats.decodeFailures);
    printf("  - Malformed: %llu\n", stats.malformedDetected);
    printf("  - Reserved: %llu\n", stats.reservedOpcodes);
    printf("  - Unsupported: %llu\n", stats.unsupported);
    printf("\n");
    
    if (stats.crashes == 0) {
        printf("[PASS] No crashes detected\n");
        return true;
    } else {
        printf("[FAIL] %llu crashes detected\n", stats.crashes);
        return false;
    }
}

// C++ API implementation
namespace RawrCodex {

bool FuzzingEngine::Run(const FuzzConfig& config, FuzzResult* result) {
    return RunFuzzing(config, result);
}

bool FuzzingEngine::GenerateValid(ArchType arch, uint8_t* outBytes, uint32_t* outLength) {
    // Use random seed based on time
    uint64_t seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    FuzzRNG rng(seed);
    
    GenerateInstruction(rng, arch, outBytes, outLength, true);
    return true;
}

bool FuzzingEngine::GenerateMalformed(ArchType arch, uint8_t* outBytes, uint32_t* outLength) {
    uint64_t seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    FuzzRNG rng(seed);
    
    GenerateMalformedPattern(rng, arch, outBytes, outLength);
    return true;
}

bool FuzzingEngine::Mutate(const uint8_t* original, uint32_t length,
                           uint8_t* outBytes, uint32_t* outLength, uint64_t seed) {
    FuzzRNG rng(seed);
    
    // Copy original
    memcpy(outBytes, original, length);
    *outLength = length;
    
    // Apply random mutations
    uint32_t mutations = rng.Range(1, 5);
    for (uint32_t i = 0; i < mutations; i++) {
        uint32_t pos = rng.Range(0, length - 1);
        uint32_t bit = rng.Range(0, 7);
        outBytes[pos] ^= (1 << bit);
    }
    
    return true;
}

} // namespace RawrCodex

// Malformed input handler implementation
namespace RawrCodex {

bool MalformedInputHandler::Generate(TestCase testCase, ArchType arch,
                                     uint8_t* outBytes, uint32_t* outLength) {
    uint64_t seed = 12345; // Fixed seed for reproducibility
    FuzzRNG rng(seed);
    
    switch (testCase) {
        case TestCase::ILLEGAL_ENCODING:
            // All zeros is often illegal
            memset(outBytes, 0, 4);
            *outLength = 4;
            break;
            
        case TestCase::RESERVED_OPCODE:
            // Reserved space
            if (arch == ArchType::ARM_64) {
                uint32_t val = 0x00000000; // ARM64 reserved
                memcpy(outBytes, &val, 4);
            } else {
                GenerateRandomBytes(rng, outBytes, 4);
            }
            *outLength = 4;
            break;
            
        case TestCase::TRUNCATED_INSTRUCTION:
            // Only 1-2 bytes
            outBytes[0] = rng.NextByte();
            *outLength = rng.Range(1, 2);
            break;
            
        case TestCase::MISALIGNED_ADDRESS:
            // Address alignment doesn't affect instruction bytes
            // Just generate normal instruction
            GenerateInstruction(rng, arch, outBytes, outLength, true);
            break;
            
        case TestCase::INVALID_PREFIX:
            // Invalid prefix bytes
            outBytes[0] = 0xFF;
            outBytes[1] = 0xFF;
            outBytes[2] = rng.NextByte();
            outBytes[3] = rng.NextByte();
            *outLength = 4;
            break;
            
        case TestCase::OVERLONG_ENCODING:
            // Longer than max instruction
            for (int i = 0; i < 16; i++) {
                outBytes[i] = rng.NextByte();
            }
            *outLength = 16;
            break;
            
        case TestCase::PRIVILEGE_VIOLATION:
            // Privileged instruction
            if (arch == ArchType::ARM_64) {
                // MRS
                uint32_t val = 0xD5300000;
                memcpy(outBytes, &val, 4);
            } else {
                GenerateRandomBytes(rng, outBytes, 4);
            }
            *outLength = 4;
            break;
            
        case TestCase::UNDEFINED_SUBCODE:
            // Valid opcode, undefined subcode
            if (arch == ArchType::ARM_64) {
                // Data processing with undefined variant
                uint32_t val = 0x0B000000 | (0xF << 10); // Undefined shift
                memcpy(outBytes, &val, 4);
            } else {
                GenerateRandomBytes(rng, outBytes, 4);
            }
            *outLength = 4;
            break;
            
        default:
            GenerateRandomBytes(rng, outBytes, 4);
            *outLength = 4;
    }
    
    return true;
}

bool MalformedInputHandler::TestResilience(DecodeFn decoder, ArchType arch,
                                           uint32_t* crashCount, uint32_t* errorCount) {
    *crashCount = 0;
    *errorCount = 0;
    
    uint8_t bytes[16];
    uint32_t length;
    
    // Test all malformed cases
    for (int i = 0; i < 8; i++) {
        TestCase tc = static_cast<TestCase>(i);
        Generate(tc, arch, bytes, &length);
        
        DecodedInstruction result;
        bool crashed = false;
        
        __try {
            RawInstruction raw;
            raw.va = 0x1000;
            raw.length = length;
            raw.arch = arch;
            memcpy(raw.bytes, bytes, length);
            raw.encoding = *(uint32_t*)bytes;
            
            SemanticInstruction semantic;
            decoder(&raw, &semantic);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            crashed = true;
        }
        
        if (crashed) {
            (*crashCount)++;
        }
    }
    
    return *crashCount == 0;
}

} // namespace RawrCodex

// Main entry point
int main(int argc, char* argv[]) {
    FuzzingEngine::FuzzConfig config = {
        .seed = std::chrono::high_resolution_clock::now().time_since_epoch().count(),
        .iterationCount = 100000,
        .targetArch = ArchType::ARM_64,
        .testMalformed = true,
        .testTruncated = true,
        .testReserved = true
    };
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            config.seed = strtoull(argv[++i], nullptr, 10);
        }
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            config.iterationCount = strtoull(argv[++i], nullptr, 10);
        }
        else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            config.targetArch = static_cast<ArchType>(atoi(argv[++i]));
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Fuzzing Engine for RawrCodex Multi-Architecture Decoder\n");
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -s <seed>    Random seed (default: time-based)\n");
            printf("  -n <count>   Number of iterations (default: 100000)\n");
            printf("  -a <arch>    Architecture (1=x64, 4=ARM64, 7=MIPS32, 9=RISCV32)\n");
            printf("  -h, --help   Show this help\n");
            return 0;
        }
    }
    
    FuzzingEngine::FuzzResult result;
    bool success = FuzzingEngine::Run(config, &result);
    
    return success ? 0 : 1;
}
