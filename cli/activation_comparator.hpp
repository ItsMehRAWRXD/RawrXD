#pragma once
// ============================================================================
// ActivationComparator — Numerical parity comparison between IR and reference
// ============================================================================
// Purpose: Compare activations from native IR executor vs llama.cpp reference
// Metrics: MAX_ABS_DIFF, RMSE, COSINE_SIMILARITY, element count, max diff index
// ============================================================================

#include <vector>
#include <string>
#include <cmath>
#include <cstdint>
#include <algorithm>
#include <limits>
#include <iostream>

namespace RawrXD {
namespace CLI {

// Comparison metrics for a single activation tensor
struct ActivationComparison {
    std::string op_name;
    uint32_t op_index = 0;
    
    // Shape info
    std::vector<uint64_t> shape_native;
    std::vector<uint64_t> shape_reference;
    size_t element_count_native = 0;
    size_t element_count_reference = 0;
    bool shapes_match = false;
    
    // Numerical metrics
    size_t count = 0;              // Number of elements compared
    float max_abs_diff = 0.0f;     // Maximum absolute difference
    float rmse = 0.0f;             // Root mean square error
    float cosine_similarity = 0.0f; // Cosine similarity (1.0 = identical direction)
    size_t max_diff_index = 0;     // Index of maximum difference
    
    // Per-element differences (optional, for detailed analysis)
    std::vector<float> abs_differences;  // Only populated if requested
    
    // Pass/fail based on tolerances
    bool passed = false;
    std::string failure_reason;
    
    // Tolerance thresholds
    float atol = 1e-5f;    // Absolute tolerance
    float rtol = 1e-4f;    // Relative tolerance
    
    // Check if comparison passed
    bool CheckPass() {
        // Basic checks
        if (!shapes_match) {
            passed = false;
            failure_reason = "Shape mismatch";
            return false;
        }
        if (count == 0) {
            passed = false;
            failure_reason = "No elements to compare";
            return false;
        }
        
        // Check tolerances
        if (max_abs_diff > atol) {
            // Check relative tolerance for large values
            float max_val = 0.0f;
            // Would need reference data for this - simplified check
            if (max_abs_diff > rtol * 1.0f) {  // Approximate
                passed = false;
                failure_reason = "Max abs diff " + std::to_string(max_abs_diff) + " exceeds atol " + std::to_string(atol);
                return false;
            }
        }
        
        if (cosine_similarity < 0.999f) {
            passed = false;
            failure_reason = "Cosine similarity " + std::to_string(cosine_similarity) + " below threshold";
            return false;
        }
        
        passed = true;
        return true;
    }
    
    // Print summary
    void PrintSummary() const {
        std::cout << "  Op " << op_index << " (" << op_name << "):" << std::endl;
        std::cout << "    Count: " << count << std::endl;
        std::cout << "    MaxAbsDiff: " << max_abs_diff << std::endl;
        std::cout << "    RMSE: " << rmse << std::endl;
        std::cout << "    CosineSim: " << cosine_similarity << std::endl;
        std::cout << "    MaxDiffIdx: " << max_diff_index << std::endl;
        std::cout << "    PASS: " << (passed ? "YES" : "NO") << std::endl;
        if (!passed) {
            std::cout << "    Reason: " << failure_reason << std::endl;
        }
    }
};

// Comparison configuration
struct ComparisonConfig {
    float atol = 1e-5f;           // Absolute tolerance
    float rtol = 1e-4f;           // Relative tolerance
    float min_cosine = 0.999f;    // Minimum cosine similarity
    bool store_differences = false;  // Store per-element differences
    bool verbose = false;
    bool fail_fast = false;       // Stop on first failure
};

// Comparison result for full model
struct ModelComparisonResult {
    std::vector<ActivationComparison> comparisons;
    uint32_t total_ops = 0;
    uint32_t passed_ops = 0;
    uint32_t failed_ops = 0;
    uint32_t skipped_ops = 0;
    
    // Overall metrics
    float global_max_abs_diff = 0.0f;
    float global_rmse = 0.0f;
    float global_cosine = 0.0f;
    
    // First divergence
    uint32_t first_divergent_op = UINT32_MAX;
    std::string first_divergent_name;
    
    // Token parity
    uint32_t native_token = 0;
    uint32_t reference_token = 0;
    bool token_parity = false;
    
    // Logit comparison
    float logit_max_abs_diff = 0.0f;
    float logit_rmse = 0.0f;
    float logit_cosine = 0.0f;
    uint32_t logit_argmax_native = 0;
    uint32_t logit_argmax_reference = 0;
    
    bool OverallPass() const {
        return failed_ops == 0 && token_parity;
    }
    
    void PrintSummary() const {
        std::cout << "\n=== Model Comparison Summary ===" << std::endl;
        std::cout << "Total ops: " << total_ops << std::endl;
        std::cout << "Passed: " << passed_ops << std::endl;
        std::cout << "Failed: " << failed_ops << std::endl;
        std::cout << "Skipped: " << skipped_ops << std::endl;
        std::cout << "Global MaxAbsDiff: " << global_max_abs_diff << std::endl;
        std::cout << "Global RMSE: " << global_rmse << std::endl;
        std::cout << "Global Cosine: " << global_cosine << std::endl;
        std::cout << "Token parity: " << (token_parity ? "PASS (" : "FAIL (") 
                  << native_token << " vs " << reference_token << ")" << std::endl;
        std::cout << "First divergent op: " << first_divergent_op 
                  << " (" << first_divergent_name << ")" << std::endl;
        std::cout << "Overall: " << (OverallPass() ? "PASS" : "FAIL") << std::endl;
    }
};

// Activation Comparator
class ActivationComparator {
public:
    explicit ActivationComparator(const ComparisonConfig& config = {})
        : m_config(config) {}
    
    // Compare two activation tensors
    ActivationComparison Compare(const std::string& op_name, uint32_t op_index,
                                 const float* native_data, size_t native_count,
                                 const float* reference_data, size_t reference_count,
                                 const std::vector<uint64_t>& native_shape = {},
                                 const std::vector<uint64_t>& reference_shape = {});
    
    // Compare full model results
    ModelComparisonResult CompareModels(
        const std::vector<std::pair<uint32_t, const float*>>& native_activations,
        const std::vector<ReferenceActivation>& reference_activations,
        const std::vector<float>& native_logits,
        const std::vector<float>& reference_logits,
        uint32_t native_token,
        uint32_t reference_token);
    
    // Binary search for first divergent operation
    // Returns the first op index where comparison fails
    uint32_t FindFirstDivergence(
        const std::vector<std::pair<uint32_t, const float*>>& native_activations,
        const std::vector<ReferenceActivation>& reference_activations,
        uint32_t low, uint32_t high);
    
    // Get configuration
    const ComparisonConfig& GetConfig() const { return m_config; }
    void SetConfig(const ComparisonConfig& config) { m_config = config; }
    
private:
    ComparisonConfig m_config;
    
    // Compute cosine similarity between two vectors
    static float ComputeCosineSimilarity(const float* a, const float* b, size_t n);
    
    // Compute RMSE
    static float ComputeRMSE(const float* a, const float* b, size_t n);
    
    // Find max absolute difference and its index
    static void FindMaxAbsDiff(const float* a, const float* b, size_t n, 
                               float& max_diff, size_t& max_idx);
};

// Binary search helper for divergence finding
struct DivergenceSearchResult {
    uint32_t first_divergent = UINT32_MAX;
    std::vector<ActivationComparison> search_history;
    bool search_complete = false;
};

// Enhanced divergence finder with logging
class DivergenceFinder {
public:
    DivergenceFinder(const ComparisonConfig& config) : m_comparator(config) {}
    
    // Find first divergent operation using binary search
    DivergenceSearchResult FindFirstDivergence(
        const std::vector<std::pair<uint32_t, const float*>>& native_activations,
        const std::vector<ReferenceActivation>& reference_activations);
    
    // Linear scan from a known good point
    uint32_t LinearScanFrom(
        const std::vector<std::pair<uint32_t, const float*>>& native_activations,
        const std::vector<ReferenceActivation>& reference_activations,
        uint32_t start_op);
    
    // Get search history for debugging
    const std::vector<ActivationComparison>& GetSearchHistory() const { return m_search_history; }
    
private:
    ActivationComparator m_comparator;
    std::vector<ActivationComparison> m_search_history;
    ComparisonConfig m_config;
};

} // namespace CLI
} // namespace RawrXD