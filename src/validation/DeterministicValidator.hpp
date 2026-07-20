/*===========================================================================
 * DeterministicValidator.hpp
 * 
 * Golden Hash Verification Suite for RawrXD Inference
 * 
 * Purpose: Validate that inference is actually executing the transformer
 *          and not bypassing via cache, fast-path, or degenerate mode.
 * 
 * Test Strategy:
 *   1. Fixed seed + temperature=0 → deterministic output
 *   2. Reset KV cache between runs
 *   3. Compare output hash against known "golden" values
 *   4. If hash matches → inference is genuine
 *   5. If hash differs → possible cache hit, quantization error, or bypass
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <cstring>
#include <functional>

namespace RawrXD {
namespace Validation {

// Test case definition
struct GoldenTest {
    const char* name;           // Test identifier
    const char* prompt;         // Input prompt
    uint32_t seed;              // Random seed
    float temperature;          // Must be 0.0 for determinism
    uint32_t maxTokens;         // Tokens to generate
    const char* expectedHash;   // SHA-256 of expected output (hex)
    const char* expectedPrefix; // Human-readable expected start
};

// Validation result
struct ValidationResult {
    bool passed;
    const char* testName;
    char actualHash[65];        // SHA-256 hex string
    char actualOutput[256];     // First 255 chars of output
    uint64_t latencyUs;         // Microseconds for inference
    uint32_t tokensGenerated;
};

// Hash computation (simple FNV-1a for speed, or SHA-256 if available)
class OutputHasher {
public:
    // FNV-1a 64-bit hash (fast, good distribution)
    static uint64_t FNV1a(const char* data, size_t len);
    
    // SHA-256 if crypto library available
    static bool SHA256(const char* data, size_t len, char* outHex);
    
    // Compare hash against expected
    static bool Verify(const char* output, const char* expectedHash);
};

// Main validator class
class DeterministicValidator {
public:
    using InferenceFunc = std::function<std::string(const char*, uint32_t, float, uint32_t)>;
    using ResetFunc = std::function<void()>;
    
    // Initialize with inference engine hooks
    void Initialize(InferenceFunc infer, ResetFunc reset);
    
    // Run single test
    ValidationResult RunTest(const GoldenTest& test);
    
    // Run full suite
    struct SuiteResult {
        uint32_t passed;
        uint32_t failed;
        uint32_t total;
        ValidationResult* results;
    };
    SuiteResult RunSuite(const GoldenTest* tests, uint32_t count);
    
    // Predefined test cases for DeepSeek-V3.1
    static const GoldenTest kDeepSeekTests[];
    static const uint32_t kNumDeepSeekTests;
    
private:
    InferenceFunc inference_;
    ResetFunc reset_;
    bool initialized_;
};

// C-compatible exports for MASM integration
extern "C" {
    // Run validation and return pass/fail
    __declspec(dllexport) int RawrXD_ValidateInference();
    
    // Get last validation error
    __declspec(dllexport) const char* RawrXD_GetValidationError();
}

} // namespace Validation
} // namespace RawrXD
