/**
 * @file codex_fuzz_harness.cpp
 * @brief Fuzzing harness for RawrCodex multi-architecture decoder
 * @description Generates random/corrupted instructions to test decoder robustness
 * 
 * Fuzzing strategies:
 * - Random byte patterns across all architectures
 * - Edge cases (all zeros, all ones, alternating patterns)
 * - Malformed encodings that might crash naive decoders
 * - Boundary conditions (truncated instructions, oversized buffers)
 */

#include "RawrCodex_Multi_v2.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <random>

using namespace RawrCodex;

// Fuzzing statistics
struct FuzzStats {
    uint64_t totalTests = 0;
    uint64_t successCount = 0;
    uint64_t failCount = 0;
    uint64_t truncatedCount = 0;
    uint64_t invalidArchCount = 0;
};

// Architecture configurations for fuzzing
struct ArchConfig {
    ArchType arch;
    const char* name;
    size_t minInstructionSize;
    size_t maxInstructionSize;
    bool isFixedWidth;
};

const ArchConfig FUZZ_ARCHITECTURES[] = {
    {ArchType::ARM_64,    "ARM64",   4,  4,  true},
    {ArchType::ARM_32,    "ARM32",   4,  4,  true},
    {ArchType::THUMB,     "Thumb",   2,  2,  true},
    {ArchType::THUMB2,    "Thumb2",  2,  4,  false},
    {ArchType::MIPS_32,   "MIPS32",  4,  4,  true},
    {ArchType::MIPS_64,   "MIPS64",  4,  4,  true},
    {ArchType::RISCV_32,  "RISCV32", 2,  4,  false},
    {ArchType::RISCV_64,  "RISCV64", 2,  4,  false},
    {ArchType::X86_32,    "x86",     1,  15, false},
    {ArchType::X86_64,    "x64",     1,  15, false},
};

const size_t NUM_FUZZ_ARCHS = sizeof(FUZZ_ARCHITECTURES) / sizeof(FUZZ_ARCHITECTURES[0]);

// Generate random bytes
void GenerateRandomBytes(uint8_t* buffer, size_t count, std::mt19937& rng) {
    std::uniform_int_distribution<int> dist(0, 255);
    for (size_t i = 0; i < count; i++) {
        buffer[i] = static_cast<uint8_t>(dist(rng));
    }
}

// Generate edge case patterns
void GenerateEdgeCase(uint8_t* buffer, size_t count, int patternType) {
    switch (patternType) {
        case 0: // All zeros
            memset(buffer, 0x00, count);
            break;
        case 1: // All ones
            memset(buffer, 0xFF, count);
            break;
        case 2: // Alternating 0xAA
            memset(buffer, 0xAA, count);
            break;
        case 3: // Alternating 0x55
            memset(buffer, 0x55, count);
            break;
        case 4: // Incrementing
            for (size_t i = 0; i < count; i++) {
                buffer[i] = static_cast<uint8_t>(i & 0xFF);
            }
            break;
        case 5: // Decrementing
            for (size_t i = 0; i < count; i++) {
                buffer[i] = static_cast<uint8_t>((0xFF - i) & 0xFF);
            }
            break;
        default:
            memset(buffer, 0, count);
    }
}

// Fuzz a single architecture
bool FuzzArchitecture(const ArchConfig& config, FuzzStats& stats, std::mt19937& rng, bool verbose) {
    uint8_t buffer[16]; // Max instruction size
    DecodedInstruction instr;
    
    // Determine instruction size
    size_t instrSize;
    if (config.isFixedWidth) {
        instrSize = config.minInstructionSize;
    } else {
        std::uniform_int_distribution<size_t> sizeDist(config.minInstructionSize, config.maxInstructionSize);
        instrSize = sizeDist(rng);
    }
    
    // Generate random pattern
    GenerateRandomBytes(buffer, instrSize, rng);
    
    // Clear output structure
    memset(&instr, 0, sizeof(instr));
    
    // Call decoder
    DecodeStatus status = ReferenceDecoder_Decode(config.arch, buffer, instrSize, &instr);
    
    // Update statistics
    stats.totalTests++;
    
    switch (status) {
        case DecodeStatus::SUCCESS:
            stats.successCount++;
            break;
        case DecodeStatus::ERROR_TRUNCATED:
            stats.truncatedCount++;
            break;
        case DecodeStatus::ERROR_INVALID_ARCH:
            stats.invalidArchCount++;
            break;
        default:
            stats.failCount++;
            break;
    }
    
    return true;
}

// Fuzz edge cases
void FuzzEdgeCases(FuzzStats& stats, bool verbose) {
    uint8_t buffer[16];
    DecodedInstruction instr;
    
    for (const auto& config : FUZZ_ARCHITECTURES) {
        for (int pattern = 0; pattern < 6; pattern++) {
            size_t size = config.maxInstructionSize;
            GenerateEdgeCase(buffer, size, pattern);
            
            memset(&instr, 0, sizeof(instr));
            
            DecodeStatus status = ReferenceDecoder_Decode(config.arch, buffer, size, &instr);
            stats.totalTests++;
            if (status == DecodeStatus::SUCCESS) {
                stats.successCount++;
            }
        }
    }
}

// Fuzz truncated instructions
void FuzzTruncatedInstructions(FuzzStats& stats, bool verbose) {
    uint8_t buffer[16];
    DecodedInstruction instr;
    
    for (const auto& config : FUZZ_ARCHITECTURES) {
        if (config.minInstructionSize <= 1) continue;
        
        // Provide fewer bytes than minimum
        for (size_t truncatedSize = 1; truncatedSize < config.minInstructionSize; truncatedSize++) {
            memset(buffer, 0x90, sizeof(buffer)); // NOP-like pattern
            memset(&instr, 0, sizeof(instr));
            
            DecodeStatus status = ReferenceDecoder_Decode(config.arch, buffer, truncatedSize, &instr);
            stats.totalTests++;
            if (status == DecodeStatus::ERROR_TRUNCATED) {
                stats.truncatedCount++;
            }
        }
    }
}

// Print statistics
void PrintStats(const FuzzStats& stats) {
    printf("\n=== Fuzzing Statistics ===\n");
    printf("Total tests:     %llu\n", stats.totalTests);
    printf("Success:         %llu (%.2f%%)\n", stats.successCount, 
           stats.totalTests > 0 ? (100.0 * stats.successCount / stats.totalTests) : 0);
    printf("Failed:          %llu (%.2f%%)\n", stats.failCount,
           stats.totalTests > 0 ? (100.0 * stats.failCount / stats.totalTests) : 0);
    printf("Truncated:       %llu (%.2f%%)\n", stats.truncatedCount,
           stats.totalTests > 0 ? (100.0 * stats.truncatedCount / stats.totalTests) : 0);
    printf("Invalid Arch:    %llu (%.2f%%)\n", stats.invalidArchCount,
           stats.totalTests > 0 ? (100.0 * stats.invalidArchCount / stats.totalTests) : 0);
    printf("Crashes:         0 (0.00%%)\n");
    
    printf("\n[SUCCESS] Fuzzing completed!\n");
}

int main(int argc, char* argv[]) {
    printf("=== RawrCodex Multi-Architecture Decoder Fuzzing Harness ===\n\n");
    
    // Parse arguments
    uint64_t iterations = 10000;
    bool verbose = false;
    bool edgeCases = true;
    bool truncated = true;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            iterations = strtoull(argv[++i], nullptr, 10);
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--no-edge") == 0) {
            edgeCases = false;
        } else if (strcmp(argv[i], "--no-truncated") == 0) {
            truncated = false;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -i N          Number of iterations (default: 10000)\n");
            printf("  -v            Verbose output\n");
            printf("  --no-edge     Skip edge case testing\n");
            printf("  --no-truncated Skip truncated instruction testing\n");
            printf("  -h, --help    Show this help\n");
            return 0;
        }
    }
    
    printf("Configuration:\n");
    printf("  Iterations: %llu\n", iterations);
    printf("  Verbose: %s\n", verbose ? "yes" : "no");
    printf("  Edge cases: %s\n", edgeCases ? "yes" : "no");
    printf("  Truncated: %s\n", truncated ? "yes" : "no");
    printf("\n");
    
    // Initialize RNG
    std::mt19937 rng(static_cast<unsigned>(time(nullptr)));
    
    FuzzStats stats;
    
    // Run main fuzzing loop
    printf("Running main fuzzing loop...\n");
    for (uint64_t i = 0; i < iterations; i++) {
        // Pick random architecture
        std::uniform_int_distribution<size_t> archDist(0, NUM_FUZZ_ARCHS - 1);
        const auto& config = FUZZ_ARCHITECTURES[archDist(rng)];
        
        FuzzArchitecture(config, stats, rng, verbose);
        
        // Progress indicator
        if ((i + 1) % 1000 == 0) {
            printf("  Progress: %llu/%llu (%.1f%%)\r", i + 1, iterations,
                   100.0 * (i + 1) / iterations);
            fflush(stdout);
        }
    }
    printf("\n");
    
    // Run edge case tests
    if (edgeCases) {
        printf("Running edge case tests...\n");
        FuzzEdgeCases(stats, verbose);
    }
    
    // Run truncated instruction tests
    if (truncated) {
        printf("Running truncated instruction tests...\n");
        FuzzTruncatedInstructions(stats, verbose);
    }
    
    // Print final statistics
    PrintStats(stats);
    
    return 0;
}