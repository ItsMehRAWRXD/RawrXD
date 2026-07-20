/*===========================================================================
 * flash_attention_validator.hpp
 * 
 * Flash Attention Numerical Correctness Validation Suite
 * 
 * Validates:
 *   - Numerical equivalence with reference attention
 *   - Online softmax stability
 *   - AVX-512 dispatch verification
 *   - Performance telemetry
 * 
 * Thresholds:
 *   - Max absolute error: < 1e-4 (FP32)
 *   - Mean error: < 1e-5
 *   - Softmax sum: 0.9999 - 1.0001
 *   - NaN/Inf count: 0
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <cmath>

namespace RawrXD {
namespace Validation {

// Validation thresholds
struct ValidationThresholds {
    static constexpr float MAX_ABS_ERROR = 1e-4f;
    static constexpr float MEAN_ERROR = 1e-5f;
    static constexpr float SOFTMAX_SUM_MIN = 0.9999f;
    static constexpr float SOFTMAX_SUM_MAX = 1.0001f;
    static constexpr uint32_t MAX_NAN_INF_COUNT = 0;
};

// Test dimensions for comprehensive coverage
struct TestDimensions {
    std::vector<uint32_t> heads = {8, 16, 32, 64, 128};
    std::vector<uint32_t> seqLengths = {128, 512, 1024, 2048, 4096, 8192};
    std::vector<uint32_t> headDims = {64, 128};
    std::vector<uint32_t> blockSizes = {64, 128, 256};
};

// Validation result for single test
struct ValidationResult {
    bool passed = false;
    float maxAbsError = 0.0f;
    float meanError = 0.0f;
    float softmaxSumMin = 1.0f;
    float softmaxSumMax = 1.0f;
    uint32_t nanCount = 0;
    uint32_t infCount = 0;
    double executionTimeMs = 0.0;
    
    std::string ToString() const;
    bool IsWithinThresholds() const;
};

// Comprehensive test report
struct ValidationReport {
    std::string timestamp;
    uint32_t totalTests = 0;
    uint32_t passedTests = 0;
    uint32_t failedTests = 0;
    
    std::vector<ValidationResult> results;
    
    // Summary statistics
    float worstMaxError = 0.0f;
    float avgMeanError = 0.0f;
    double totalExecutionTime = 0.0;
    
    void GenerateSummary();
    void ExportJSON(const std::string& path) const;
    void ExportCSV(const std::string& path) const;
    bool AllPassed() const { return failedTests == 0; }
};

// Reference attention implementation (naive but correct)
class ReferenceAttention {
public:
    // Compute standard attention: softmax(QK^T / sqrt(d)) @ V
    static void Compute(
        const float* Q,      // [num_heads, head_dim]
        const float* K,      // [seq_len, num_heads, head_dim]
        const float* V,      // [seq_len, num_heads, head_dim]
        float* Output,       // [num_heads, head_dim]
        uint32_t numHeads,
        uint32_t seqLen,
        uint32_t headDim,
        uint32_t currentPos
    );
    
    // Compute attention scores only (for verification)
    static void ComputeScores(
        const float* Q,
        const float* K,
        float* scores,       // [seq_len]
        uint32_t numHeads,
        uint32_t seqLen,
        uint32_t headDim,
        uint32_t headIdx,
        uint32_t currentPos
    );
};

// Flash Attention validator
class FlashAttentionValidator {
public:
    FlashAttentionValidator();
    ~FlashAttentionValidator();
    
    // Initialize with test configuration
    bool Initialize(const TestDimensions& dims = TestDimensions{});
    
    // Run full validation suite
    ValidationReport RunFullSuite();
    
    // Run specific test
    ValidationResult RunSingleTest(
        uint32_t numHeads,
        uint32_t seqLen,
        uint32_t headDim,
        uint32_t blockSize
    );
    
    // Verify AVX-512 dispatch
    bool VerifyAVX512Dispatch();
    
    // Check numerical stability over extended run
    bool RunSoakTest(
        uint32_t durationMinutes = 60,
        uint32_t contextLength = 16384
    );
    
    // Get telemetry data
    struct Telemetry {
        uint64_t tilesProcessed = 0;
        uint64_t kvBytesRead = 0;
        uint64_t qBytesRead = 0;
        double attentionTimeMs = 0.0;
        double softmaxTimeMs = 0.0;
        uint32_t tileSize = 0;
        uint32_t headDimension = 0;
        bool avx512Active = false;
        bool onlineSoftmax = false;
    };
    Telemetry GetTelemetry() const;
    
private:
    TestDimensions m_dims;
    bool m_initialized = false;
    
    // Aligned buffers for testing
    float* m_qBuffer = nullptr;
    float* m_kBuffer = nullptr;
    float* m_vBuffer = nullptr;
    float* m_refOutput = nullptr;
    float* m_faOutput = nullptr;
    
    bool AllocateBuffers(size_t maxSize);
    void FreeBuffers();
    
    // Comparison utilities
    static void CompareOutputs(
        const float* ref,
        const float* test,
        uint32_t numElements,
        ValidationResult& result
    );
    
    // Random data generation
    static void GenerateRandomData(float* data, uint32_t count, uint32_t seed = 42);
};

// C API for integration
extern "C" {
    __declspec(dllexport) int RawrXD_ValidateFlashAttention(
        uint32_t numHeads,
        uint32_t seqLen,
        uint32_t headDim,
        float* outMaxError,
        float* outMeanError
    );
    
    __declspec(dllexport) int RawrXD_RunFlashAttentionSoakTest(
        uint32_t durationMinutes,
        uint32_t contextLength
    );
}

} // namespace Validation
} // namespace RawrXD
