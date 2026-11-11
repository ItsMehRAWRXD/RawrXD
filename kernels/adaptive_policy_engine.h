/**
 * @file adaptive_policy_engine.h
 * @brief RawrXD L4.3.1 Adaptive Policy Engine
 *
 * Constrained optimization for compression codec selection.
 * Consumes TensorProfile, outputs CompressionPolicy.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include "tensor_profiler.h"
#include <vector>
#include <map>
#include <functional>
#include <optional>

namespace rawrxd {
namespace policy {

// ============================================================================
// Policy Decision Structure
// ============================================================================

/**
 * @brief Compression policy for a single tensor
 *
 * Immutable decision produced by the policy engine.
 * Consumed by L4.2 Compression ABI without modification.
 */
struct CompressionPolicy {
    // Tensor identification
    std::string tensor_name;
    std::string tensor_id;      // Unique identifier (GGUF key)
    
    // Selected compression
    compression::CompressionType codec;
    
    // Expected characteristics
    float expected_compression_ratio;
    float expected_quantization_error;
    float expected_quality_cost;    // Impact on model output quality
    
    // Resource impact
    size_t original_size_bytes;
    size_t compressed_size_bytes;
    size_t memory_saved_bytes;
    
    // Performance characteristics
    float decode_latency_ms;        // Estimated decompression time
    float gemm_throughput;          // Estimated GEMM performance
    
    // Decision rationale (for debugging/auditing)
    struct Rationale {
        float sensitivity_score;
        float quant_error_contribution;
        float memory_contribution;
        std::string primary_reason;     // "sensitivity", "budget", "speed"
    } rationale;
    
    // Validation
    bool IsValid() const {
        return !tensor_name.empty() && 
               expected_compression_ratio > 0.0f &&
               compressed_size_bytes > 0;
    }
};

// ============================================================================
// Optimization Constraints
// ============================================================================

/**
 * @brief Constraints for policy optimization
 *
 * Defines the optimization problem boundaries.
 */
struct OptimizationConstraints {
    // Memory constraints
    float target_compression_ratio;     // e.g., 5.0 = 5:1 compression
    size_t max_model_size_bytes;        // Hard limit
    size_t min_model_size_bytes;        // Don't over-compress
    
    // Quality constraints
    float min_cosine_similarity;          // L4.2.3 gate: ≥0.999
    float max_rmse;                       // L4.2.3 gate: ≤0.01
    float max_quality_degradation;      // Acceptable quality loss (0-1)
    
    // Performance constraints
    float max_decode_latency_ms;        // Per-tensor decode budget
    float min_gemm_throughput;            // Minimum GEMM performance
    bool prioritize_speed;                // Prefer faster codecs
    
    // Tensor-specific overrides
    std::map<std::string, compression::CompressionType> forced_codecs;
    std::vector<std::string> protected_tensors;  // Never compress these
    
    OptimizationConstraints()
        : target_compression_ratio(5.0f)
        , max_model_size_bytes(0)           // 0 = unlimited
        , min_model_size_bytes(0)
        , min_cosine_similarity(0.999f)     // L4.2.3 STANDARD gate
        , max_rmse(0.01f)                   // L4.2.3 STANDARD gate
        , max_quality_degradation(0.05f)    // 5% acceptable loss
        , max_decode_latency_ms(10.0f)     // 10ms per tensor
        , min_gemm_throughput(0.0f)
        , prioritize_speed(true) {}
};

// ============================================================================
// Optimization Objective
// ============================================================================

/**
 * @brief What to optimize for
 */
enum class OptimizationObjective {
    MAXIMIZE_COMPRESSION,       // Maximize memory savings
    MINIMIZE_QUALITY_LOSS,      // Preserve model quality
    BALANCED,                   // Trade-off between compression and quality
    MINIMIZE_LATENCY,           // Prioritize decode speed
    CUSTOM                      // User-defined objective function
};

// ============================================================================
// Policy Resolver
// ============================================================================

/**
 * @brief Resolves TensorProfile to CompressionPolicy
 *
 * Core component: maps sensitivity analysis to concrete codec decisions.
 */
class PolicyResolver {
public:
    PolicyResolver();
    ~PolicyResolver();

    // Resolve single tensor
    CompressionPolicy ResolveTensor(
        const profiler::TensorProfile& profile,
        const OptimizationConstraints& constraints
    );

    // Batch resolution
    std::vector<CompressionPolicy> ResolveAll(
        const std::vector<profiler::TensorProfile>& profiles,
        const OptimizationConstraints& constraints
    );

    // Check if profile meets constraints
    bool ValidateProfile(
        const profiler::TensorProfile& profile,
        const OptimizationConstraints& constraints,
        std::string* out_reason = nullptr
    );

    // Select codec for profile
    compression::CompressionType SelectCodec(
        const profiler::TensorProfile& profile,
        const OptimizationConstraints& constraints
    );

    // Estimate policy characteristics
    void EstimateCharacteristics(
        const profiler::TensorProfile& profile,
        compression::CompressionType codec,
        float* out_ratio,
        float* out_error,
        float* out_latency
    );

private:
    bool IsForced(const std::string& tensor_name, 
                  const OptimizationConstraints& constraints,
                  compression::CompressionType* out_codec);
    bool IsProtected(const std::string& tensor_name,
                     const OptimizationConstraints& constraints);
};

// ============================================================================
// Budget Optimizer
// ============================================================================

/**
 * @brief Constrained optimization for memory/quality trade-off
 *
 * Solves: maximize memory_saved subject to quality >= gate
 */
class BudgetOptimizer {
public:
    BudgetOptimizer();
    ~BudgetOptimizer();

    // Optimize policy to meet constraints
    std::vector<CompressionPolicy> Optimize(
        const std::vector<CompressionPolicy>& initial_policies,
        const OptimizationConstraints& constraints,
        OptimizationObjective objective
    );

    // Specific optimization strategies
    std::vector<CompressionPolicy> MaximizeCompression(
        const std::vector<CompressionPolicy>& policies,
        const OptimizationConstraints& constraints
    );

    std::vector<CompressionPolicy> MinimizeQualityLoss(
        const std::vector<CompressionPolicy>& policies,
        const OptimizationConstraints& constraints
    );

    std::vector<CompressionPolicy> BalancedOptimization(
        const std::vector<CompressionPolicy>& policies,
        const OptimizationConstraints& constraints
    );

    // Check if constraints are satisfied
    bool CheckConstraints(
        const std::vector<CompressionPolicy>& policies,
        const OptimizationConstraints& constraints,
        std::vector<std::string>* out_violations = nullptr
    );

    // Calculate aggregate metrics
    struct AggregateMetrics {
        float achieved_compression_ratio;
        float total_memory_saved_mb;
        float weighted_quality_cost;
        float min_cosine_similarity;
        float max_rmse;
        size_t total_size_bytes;
        size_t q4_0_count;
        size_t q5_count;
        size_t q6_count;
        size_t q8_count;
        size_t fp16_count;
    };

    AggregateMetrics CalculateMetrics(
        const std::vector<CompressionPolicy>& policies
    );

private:
    // Greedy optimization: upgrade/downgrade codecs to meet constraints
    std::vector<CompressionPolicy> GreedyOptimize(
        std::vector<CompressionPolicy> policies,
        const OptimizationConstraints& constraints,
        bool upgrade_quality    // true = improve quality, false = improve compression
    );

    // Calculate quality score for a policy set
    float CalculateQualityScore(const std::vector<CompressionPolicy>& policies);
    
    // Calculate compression score for a policy set
    float CalculateCompressionScore(const std::vector<CompressionPolicy>& policies);
};

// ============================================================================
// Policy Engine (Main Interface)
// ============================================================================

/**
 * @brief High-level interface for L4.3.1 Adaptive Policy Engine
 *
 * Orchestrates resolution and optimization into unified workflow.
 */
class AdaptivePolicyEngine {
public:
    AdaptivePolicyEngine();
    ~AdaptivePolicyEngine();

    // Initialize with model metadata
    bool Initialize(const std::string& model_name);
    bool IsInitialized() const { return initialized_; }

    // Run complete policy generation
    std::vector<CompressionPolicy> GeneratePolicy(
        const std::vector<profiler::TensorProfile>& profiles,
        const OptimizationConstraints& constraints,
        OptimizationObjective objective = OptimizationObjective::BALANCED
    );

    // Step-by-step workflow
    std::vector<CompressionPolicy> ResolvePolicies(
        const std::vector<profiler::TensorProfile>& profiles,
        const OptimizationConstraints& constraints
    );

    std::vector<CompressionPolicy> OptimizePolicies(
        const std::vector<CompressionPolicy>& policies,
        const OptimizationConstraints& constraints,
        OptimizationObjective objective
    );

    // Validation
    bool ValidatePolicies(
        const std::vector<CompressionPolicy>& policies,
        const OptimizationConstraints& constraints,
        std::vector<std::string>* out_failures = nullptr
    );

    // Access results
    const std::vector<CompressionPolicy>& GetCurrentPolicy() const { return current_policy_; }
    const OptimizationConstraints& GetConstraints() const { return last_constraints_; }

    // Export/Import
    bool ExportPolicyJSON(const std::string& filename) const;
    bool ImportPolicyJSON(const std::string& filename);
    bool ExportPolicyGGUF(const std::string& filename) const;  // Embed in GGUF metadata

    // Summary and reporting
    void PrintPolicySummary() const;
    void PrintTensorDetails(const std::string& tensor_name) const;
    std::string GeneratePolicyReport() const;

    // Comparison
    static bool ComparePolicies(
        const std::vector<CompressionPolicy>& a,
        const std::vector<CompressionPolicy>& b,
        float tolerance = 0.001f
    );

    // Presets
    static OptimizationConstraints Preset_MaximumCompression();
    static OptimizationConstraints Preset_MaximumQuality();
    static OptimizationConstraints Preset_Balanced();
    static OptimizationConstraints Preset_Interactive();

private:
    bool initialized_;
    std::string model_name_;
    PolicyResolver resolver_;
    BudgetOptimizer optimizer_;
    std::vector<CompressionPolicy> current_policy_;
    OptimizationConstraints last_constraints_;
};

// ============================================================================
// Policy Application (L4.3.2)
// ============================================================================

/**
 * @brief Applies compression policy to GGUF model
 *
 * Consumes policy, produces compressed model.
 */
class PolicyApplicator {
public:
    PolicyApplicator();
    ~PolicyApplicator();

    // Load policy
    bool LoadPolicy(const std::vector<CompressionPolicy>& policy);
    bool LoadPolicyFromJSON(const std::string& filename);

    // Apply to GGUF
    bool ApplyToGGUF(
        const std::string& input_gguf,
        const std::string& output_gguf
    );

    // Validation
    bool ValidateApplication(
        const std::string& original_gguf,
        const std::string& compressed_gguf,
        std::vector<std::string>* out_errors = nullptr
    );

private:
    std::vector<CompressionPolicy> policy_;
    std::map<std::string, CompressionPolicy> policy_map_;
};

// ============================================================================
// Utility Functions
// ============================================================================

// Convert policy to JSON string
std::string PolicyToJSON(const CompressionPolicy& policy);
std::string PolicyToJSON(const std::vector<CompressionPolicy>& policies);

// Parse policy from JSON
bool PolicyFromJSON(const std::string& json, CompressionPolicy* out_policy);
bool PolicyFromJSON(const std::string& json, std::vector<CompressionPolicy>* out_policies);

// Calculate memory savings
float CalculateMemorySavingsMB(const std::vector<CompressionPolicy>& policies);
float CalculateMemorySavingsPercent(const std::vector<CompressionPolicy>& policies);

// Estimate quality impact
float EstimateQualityImpact(const std::vector<CompressionPolicy>& policies);

// Validate against L4.2.3 gates
bool ValidateAgainstL4_2_3_Gates(
    const std::vector<CompressionPolicy>& policies,
    std::vector<std::string>* out_failures = nullptr
);

} // namespace policy
} // namespace rawrxd
