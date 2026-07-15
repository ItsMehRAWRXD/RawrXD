/**
 * @file reference_validator.hpp
 * @brief Reference Validation Harness for RawrXD
 *
 * Compares RawrXD outputs against a reference implementation (e.g., llama.cpp)
 * to ensure numerical correctness before optimization.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace rawrxd {
namespace validation {

// ============================================================================
// Validation Metrics
// ============================================================================

struct ValidationMetrics {
    // Logit comparison
    double max_abs_error = 0.0;
    double mean_squared_error = 0.0;
    double mean_absolute_error = 0.0;
    
    // Token agreement
    double top1_agreement = 0.0;  // Percentage of positions where top token matches
    double top5_agreement = 0.0;  // Percentage where reference top-5 contains predicted
    
    // Per-layer metrics (for debugging)
    std::vector<double> layer_max_errors;
    
    // Overall pass/fail
    bool passed = false;
    std::string failure_reason;
};

// ============================================================================
// Validation Configuration
// ============================================================================

struct ValidationConfig {
    // Model paths
    std::string rawrxd_model_path;
    std::string reference_model_path;  // For llama.cpp comparison
    
    // Test prompts
    std::vector<std::string> test_prompts = {
        "Hello",
        "The quick brown fox",
        "Explain quantum computing",
        "int main() {",
        "The capital of France is"
    };
    
    // Sampling parameters (must match between implementations)
    float temperature = 1.0f;
    uint32_t top_k = 40;
    float top_p = 1.0f;
    
    // Validation thresholds
    double max_abs_error_threshold = 1e-3;  // For FP32 comparison
    double top1_agreement_threshold = 0.95;    // 95% token agreement
    
    // Test configuration
    uint32_t max_tokens = 10;
    bool compare_logits = true;
    bool compare_tokens = true;
    bool verbose = true;
};

// ============================================================================
// Reference Implementation Interface
// ============================================================================

class ReferenceImplementation {
public:
    virtual ~ReferenceImplementation() = default;
    
    // Load model
    virtual bool LoadModel(const std::string& path) = 0;
    
    // Run inference and return logits for each token position
    virtual std::vector<std::vector<float>> RunInference(
        const std::string& prompt,
        uint32_t max_tokens) = 0;
    
    // Get model info
    virtual std::string GetName() const = 0;
    virtual std::string GetVersion() const = 0;
};

// ============================================================================
// Validation Harness
// ============================================================================

class ReferenceValidator {
public:
    ReferenceValidator(const ValidationConfig& config);
    ~ReferenceValidator();
    
    // Run full validation suite
    ValidationMetrics Validate();
    
    // Run single test
    ValidationMetrics ValidatePrompt(const std::string& prompt);
    
    // Compare logits directly
    ValidationMetrics CompareLogits(
        const std::vector<std::vector<float>>& rawrxd_logits,
        const std::vector<std::vector<float>>& reference_logits);
    
    // Set custom reference implementation
    void SetReferenceImpl(std::unique_ptr<ReferenceImplementation> impl);
    
    // Generate validation report
    std::string GenerateReport(const ValidationMetrics& metrics);

private:
    ValidationConfig config_;
    std::unique_ptr<ReferenceImplementation> reference_impl_;
    
    // Internal comparison helpers
    double CalculateMaxAbsError(
        const std::vector<float>& a,
        const std::vector<float>& b);
    
    double CalculateMSE(
        const std::vector<float>& a,
        const std::vector<float>& b);
    
    std::vector<uint32_t> GetTopKTokens(
        const std::vector<float>& logits,
        uint32_t k);
};

// ============================================================================
// Mock Reference Implementation (for testing)
// ============================================================================

class MockReferenceImpl : public ReferenceImplementation {
public:
    bool LoadModel(const std::string& path) override;
    std::vector<std::vector<float>> RunInference(
        const std::string& prompt,
        uint32_t max_tokens) override;
    std::string GetName() const override { return "MockReference"; }
    std::string GetVersion() const override { return "1.0.0"; }
    
    // For testing: set expected outputs
    void SetExpectedOutputs(std::vector<std::vector<float>> outputs);
    
private:
    std::vector<std::vector<float>> expected_outputs_;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick validation with default config
ValidationMetrics QuickValidate(
    const std::string& model_path,
    const std::string& reference_path);

// Validate against saved reference outputs
ValidationMetrics ValidateAgainstSnapshot(
    const std::string& model_path,
    const std::string& snapshot_path);

// Save reference outputs for future validation
bool SaveReferenceSnapshot(
    const std::string& model_path,
    const std::string& output_path,
    const std::vector<std::string>& prompts);

} // namespace validation
} // namespace rawrxd
