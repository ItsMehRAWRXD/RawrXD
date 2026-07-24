// ============================================================================
// Deep2Validation.hpp - Numerical Validation Framework
// Validates correctness of Deep2 inference against reference implementations
// ============================================================================

#pragma once

#include <vector>
#include <string>
#include <functional>
#include <cmath>
#include <random>

namespace Deep2 {
namespace Validation {

// Validation result structure
struct ValidationResult {
    std::string testName;
    bool passed;
    double maxError;
    double meanError;
    double cosineSimilarity;
    std::string details;
    
    ValidationResult(const std::string& name) 
        : testName(name), passed(false), maxError(0.0), 
          meanError(0.0), cosineSimilarity(0.0) {}
};

// Validation metrics
struct ValidationMetrics {
    static double computeCosineSimilarity(const float* a, const float* b, size_t n);
    static double computeMaxError(const float* a, const float* b, size_t n);
    static double computeMeanError(const float* a, const float* b, size_t n);
    static double computeRelativeError(const float* a, const float* b, size_t n);
};

// ============================================================================
// VAL-001: Tokenizer Validation
// ============================================================================
class TokenizerValidator {
public:
    ValidationResult validate(const std::string& testText);
    ValidationResult validateRoundtrip(const std::string& original);
    ValidationResult validateSpecialTokens();
};

// ============================================================================
// VAL-002: Embedding Validation
// ============================================================================
class EmbeddingValidator {
public:
    ValidationResult validateEmbeddingLookup(int tokenId, size_t hiddenDim);
    ValidationResult validateEmbeddingTable(const std::vector<int>& tokenIds);
    ValidationResult validateQuantizedEmbedding(int tokenId, int quantType);
};

// ============================================================================
// VAL-003: Attention Validation
// ============================================================================
class AttentionValidator {
public:
    // Reference attention implementation (FP32, naive but correct)
    static void referenceAttention(const float* Q, const float* K, const float* V,
                                   float* output, size_t seqLen, size_t headDim,
                                   size_t numHeads, bool causal = true);
    
    // Validate Deep2 attention against reference
    ValidationResult validateAttentionCorrectness(size_t seqLen, size_t headDim, 
                                                   size_t numHeads, uint32_t seed = 42);
    
    // Validate causal masking
    ValidationResult validateCausalMasking(size_t seqLen, size_t headDim);
    
    // Validate scaling factor
    ValidationResult validateScalingFactor(size_t headDim);
    
    // Validate multi-head consistency
    ValidationResult validateMultiHeadConsistency(size_t seqLen, size_t headDim, 
                                                   size_t numHeads);
};

// ============================================================================
// VAL-004: KV Cache Validation
// ============================================================================
class KVCacheValidator {
public:
    // Validate prefill vs decode consistency
    ValidationResult validatePrefillDecodeConsistency(size_t promptLen, 
                                                       size_t numLayers,
                                                       size_t numHeads,
                                                       size_t headDim);
    
    // Validate cache stride correctness
    ValidationResult validateCacheStrides(size_t seqLen, size_t headDim);
    
    // Validate position indexing
    ValidationResult validatePositionIndexing(size_t maxSeqLen);
    
    // Full cache stress test
    ValidationResult validateCacheStressTest(size_t numLayers, size_t numHeads,
                                             size_t headDim, size_t maxSeqLen);
};

// ============================================================================
// VAL-005: Quantization Kernel Validation
// ============================================================================
class QuantizationValidator {
public:
    // Validate Q4_K GEMV against FP16 reference
    ValidationResult validateQ4K_GEMV(size_t rows, size_t cols);
    
    // Validate Q8_0 GEMV against FP16 reference
    ValidationResult validateQ8_0_GEMV(size_t rows, size_t cols);
    
    // Per-tensor validation report
    struct TensorValidationReport {
        std::string tensorName;
        int layer;
        std::string quantType;
        double maxError;
        double meanError;
        double cosineSimilarity;
        bool passed;
    };
    
    std::vector<TensorValidationReport> validateAllQuantizedTensors();
    
    // Generate full quantization report
    void generateQuantizationReport(const std::string& outputPath);
};

// ============================================================================
// VAL-006: Sampler Validation
// ============================================================================
class SamplerValidator {
public:
    // Validate temperature application
    ValidationResult validateTemperature(float temperature);
    
    // Validate top-k filtering
    ValidationResult validateTopK(size_t k);
    
    // Validate top-p (nucleus) filtering
    ValidationResult validateTopP(float p);
    
    // Validate repetition penalty
    ValidationResult validateRepetitionPenalty(float penalty, 
                                               const std::vector<int>& recentTokens);
    
    // Validate deterministic mode (temperature = 0)
    ValidationResult validateDeterministicMode();
    
    // Validate seeded stochastic mode
    ValidationResult validateSeededStochastic(uint32_t seed);
    
    // Full sampler pipeline validation
    ValidationResult validateSamplerPipeline(const std::vector<float>& logits,
                                             float temperature,
                                             size_t topK,
                                             float topP,
                                             float repetitionPenalty);
};

// ============================================================================
// VAL-007: End-to-End Generation Validation
// ============================================================================
class EndToEndValidator {
public:
    struct GenerationResult {
        std::vector<int> tokens;
        std::vector<std::vector<float>> perTokenLogits;
        double generationTimeMs;
        size_t tokensPerSecond;
    };
    
    // Golden test prompts
    static const std::vector<std::string> GoldenPrompts;
    
    // Run generation and compare with reference
    ValidationResult validateGenerationParity(const std::string& prompt,
                                              const GenerationResult& reference);
    
    // Measure first token agreement
    ValidationResult validateFirstTokenAgreement(const std::string& prompt,
                                                  int expectedFirstToken);
    
    // Measure top-5 overlap
    ValidationResult validateTop5Overlap(const std::string& prompt,
                                        const std::vector<int>& expectedTop5);
    
    // Full golden test suite
    std::vector<ValidationResult> runGoldenTestSuite();
    
    // Generate comparison report
    void generateComparisonReport(const std::string& outputPath);
};

// ============================================================================
// VAL-008: Performance Regression Validation
// ============================================================================
class PerformanceValidator {
public:
    struct PerformanceMetrics {
        double tokensPerSecond;
        double latencyMs;
        double memoryBandwidthGBps;
        double computeUtilization;
    };
    
    // Validate performance meets baseline
    ValidationResult validatePerformanceBaseline(const std::string& testName,
                                               double minTokensPerSecond,
                                               double maxLatencyMs);
    
    // Validate no regression from previous run
    ValidationResult validateNoRegression(const PerformanceMetrics& current,
                                          const PerformanceMetrics& baseline,
                                          double tolerancePercent = 5.0);
    
    // Memory bandwidth validation
    ValidationResult validateMemoryBandwidth(double minBandwidthGBps);
    
    // Full performance report
    void generatePerformanceReport(const std::string& outputPath);
};

// ============================================================================
// Master Validation Runner
// ============================================================================
class ValidationRunner {
public:
    ValidationRunner();
    
    // Run all validation gates
    std::vector<ValidationResult> runAllValidations();
    
    // Run specific validation gate
    ValidationResult runValidation(const std::string& gateName);
    
    // Generate comprehensive report
    void generateReport(const std::string& outputPath);
    
    // Check if all gates pass
    bool allGatesPass() const;
    
    // Get summary statistics
    struct SummaryStats {
        size_t totalTests;
        size_t passedTests;
        size_t failedTests;
        double overallPassRate;
    };
    SummaryStats getSummary() const;
    
private:
    std::vector<ValidationResult> results_;
    
    // Individual gate runners
    ValidationResult runVAL001_Tokenizer();
    ValidationResult runVAL002_Embedding();
    ValidationResult runVAL003_Attention();
    ValidationResult runVAL004_KVCache();
    ValidationResult runVAL005_Quantization();
    ValidationResult runVAL006_Sampler();
    ValidationResult runVAL007_EndToEnd();
    ValidationResult runVAL008_Performance();
};

// ============================================================================
// Utility Functions
// ============================================================================
namespace Utils {
    // Generate random tensor with fixed seed
    std::vector<float> generateRandomTensor(size_t n, uint32_t seed = 42, 
                                           float min = -1.0f, float max = 1.0f);
    
    // Save tensor to file for debugging
    void saveTensor(const std::string& path, const float* data, size_t n);
    
    // Load tensor from file
    std::vector<float> loadTensor(const std::string& path);
    
    // Compare two tensors with tolerance
    bool compareTensors(const float* a, const float* b, size_t n, 
                       double tolerance = 1e-5);
    
    // Print tensor statistics
    void printTensorStats(const std::string& name, const float* data, size_t n);
}

} // namespace Validation
} // namespace Deep2
