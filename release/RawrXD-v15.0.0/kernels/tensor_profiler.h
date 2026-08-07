/**
 * @file tensor_profiler.h
 * @brief RawrXD L4.3.0 Tensor Profiler - Sensitivity Analysis for Adaptive Compression
 *
 * Read-only analysis layer producing compression policy maps.
 * Consumes calibration data, outputs TensorProfile recommendations.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <memory>
#include "compression_codec.h"

namespace rawrxd {
namespace profiler {

// ============================================================================
// Tensor Profile Structure
// ============================================================================

/**
 * @brief Complete sensitivity profile for a single tensor
 *
 * Captures tensor characteristics, sensitivity metrics, and
 * recommended compression parameters. Immutable after construction.
 */
struct TensorProfile {
    // Tensor identification
    std::string name;
    std::string layer_type;  // "attn.q", "ffn.down", "embed", etc.
    uint64_t elements;
    uint32_t dimensions;
    std::vector<size_t> shape;

    // Sensitivity metrics (0.0 = insensitive, 1.0 = highly sensitive)
    float activation_variance;      // Variance in activation values
    float quantization_error;       // Measured quantization error
    float output_impact;            // Impact on final output
    float gradient_sensitivity;     // Gradient flow sensitivity

    // Derived composite score
    float sensitivity_score;        // Weighted combination of above

    // Compression recommendation
    compression::CompressionType recommended_codec;
    float expected_ratio;           // Expected compression ratio
    float expected_error;         // Expected quantization error

    // Calibration metadata
    uint32_t sample_count;          // Number of calibration samples
    float confidence;               // Confidence in recommendation (0-1)

    // Comparison operators for sorting/filtering
    bool operator<(const TensorProfile& other) const {
        return sensitivity_score < other.sensitivity_score;
    }
    bool operator>(const TensorProfile& other) const {
        return sensitivity_score > other.sensitivity_score;
    }

    // Check if profile meets quality gates
    bool IsHighConfidence() const { return confidence >= 0.9f; }
    bool IsSensitive() const { return sensitivity_score >= 0.6f; }
    bool IsCritical() const { return sensitivity_score >= 0.85f; }
};

// ============================================================================
// Calibration Sample
// ============================================================================

/**
 * @brief Single calibration observation for a tensor
 *
 * Captures runtime statistics for one forward pass.
 */
struct TensorObservation {
    std::string tensor_name;
    std::vector<float> values;      // Raw values (sampled if large)
    float min_value;
    float max_value;
    float mean;
    float variance;
    uint32_t outlier_count;
    float outlier_ratio;
    uint64_t timestamp;             // Sample sequence number
};

/**
 * @brief Complete calibration sample across all tensors
 */
struct CalibrationSample {
    uint64_t sample_id;
    uint64_t timestamp;
    std::map<std::string, TensorObservation> observations;
    std::string context;            // Token context or description
};

// ============================================================================
// Calibration Collector
 * ============================================================================

/**
 * @brief Collects activation statistics during calibration runs
 *
 * Read-only observer of the validated L4.2 runtime.
 * Records tensor distributions without modifying execution.
 */
class CalibrationCollector {
public:
    CalibrationCollector();
    ~CalibrationCollector();

    // Session management
    void BeginSession(const std::string& model_name);
    void EndSession();
    bool IsActive() const { return session_active_; }

    // Sample collection
    void BeginSample(uint64_t token_id);
    void EndSample();
    bool IsSampling() const { return sample_active_; }

    // Record tensor observation (called by runtime hooks)
    void RecordTensor(
        const std::string& name,
        const float* data,
        size_t count,
        const std::vector<size_t>& shape = {}
    );

    // Record with pre-computed statistics (for efficiency)
    void RecordTensorStats(
        const std::string& name,
        float min_val,
        float max_val,
        float mean,
        float variance,
        uint32_t outliers,
        size_t count
    );

    // Access collected data
    const std::vector<CalibrationSample>& GetSamples() const { return samples_; }
    size_t GetSampleCount() const { return samples_.size(); }
    size_t GetTensorCount() const { return tensor_names_.size(); }

    // Export/Import
    bool ExportToJSON(const std::string& filename) const;
    bool ImportFromJSON(const std::string& filename);

    // Clear all data
    void Clear();

private:
    bool session_active_;
    bool sample_active_;
    std::string model_name_;
    std::vector<CalibrationSample> samples_;
    CalibrationSample current_sample_;
    std::set<std::string> tensor_names_;

    void ComputeObservationStats(TensorObservation* obs);
};

// ============================================================================
// Sensitivity Analyzer
// ============================================================================

/**
 * @brief Analyzes calibration data to compute tensor sensitivity scores
 *
 * Combines multiple signals into composite sensitivity metrics.
 * Determines optimal compression codec for each tensor.
 */
class SensitivityAnalyzer {
public:
    // Weight configuration for sensitivity calculation
    struct Weights {
        float activation_variance;
        float quantization_error;
        float output_impact;
        float gradient_sensitivity;

        Weights()
            : activation_variance(0.35f)
            , quantization_error(0.35f)
            , output_impact(0.20f)
            , gradient_sensitivity(0.10f) {}
    };

    // Sensitivity thresholds for codec selection
    struct Thresholds {
        float q4_0_max;     // 0.0 - 0.25
        float q5_max;       // 0.25 - 0.60
        float q6_max;       // 0.60 - 0.85
        // > 0.85 -> Q8_0 or FP16

        Thresholds()
            : q4_0_max(0.25f)
            , q5_max(0.60f)
            , q6_max(0.85f) {}
    };

    SensitivityAnalyzer();
    ~SensitivityAnalyzer();

    // Configuration
    void SetWeights(const Weights& weights) { weights_ = weights; }
    void SetThresholds(const Thresholds& thresholds) { thresholds_ = thresholds; }
    const Weights& GetWeights() const { return weights_; }
    const Thresholds& GetThresholds() const { return thresholds_; }

    // Analyze single tensor from observations
    TensorProfile AnalyzeTensor(
        const std::string& name,
        const std::vector<TensorObservation>& observations
    );

    // Batch analysis from calibration data
    std::vector<TensorProfile> AnalyzeCalibrationData(
        const std::vector<CalibrationSample>& samples
    );

    // Compute individual metrics
    float ComputeActivationVariance(const std::vector<TensorObservation>& obs);
    float ComputeQuantizationError(const std::vector<TensorObservation>& obs);
    float ComputeOutputImpact(const std::string& tensor_name);
    float ComputeGradientSensitivity(const std::string& tensor_name);

    // Composite score calculation
    float ComputeSensitivityScore(
        float activation_variance,
        float quantization_error,
        float output_impact,
        float gradient_sensitivity
    );

    // Codec selection based on sensitivity
    compression::CompressionType SelectCodec(float sensitivity_score);
    compression::CompressionType SelectCodecWithBudget(
        float sensitivity_score,
        float target_memory_ratio
    );

    // Estimate compression parameters
    void EstimateCompressionParams(
        const TensorProfile& profile,
        float* out_ratio,
        float* out_error
    );

private:
    Weights weights_;
    Thresholds thresholds_;

    float NormalizeMetric(float value, float min_val, float max_val);
    float Clamp(float value, float min_val, float max_val);
};

// ============================================================================
// Compression Planner
// ============================================================================

/**
 * @brief Plans compression strategy across all model tensors
 *
 * Consumes TensorProfile map, outputs compression policy.
 * Respects memory budgets and quality constraints.
 */
class CompressionPlanner {
public:
    // Planning constraints
    struct Constraints {
        float target_memory_ratio;      // Target compression (e.g., 0.25 = 4x)
        float min_quality_score;        // Minimum acceptable quality (0-1)
        size_t max_model_size_bytes;    // Hard size limit
        bool prioritize_speed;          // Prefer faster codecs

        Constraints()
            : target_memory_ratio(0.20f)  // 5:1 default
            , min_quality_score(0.95f)
            , max_model_size_bytes(0)    // 0 = unlimited
            , prioritize_speed(true) {}
    };

    // Planned compression policy
    struct Policy {
        std::string model_name;
        std::vector<TensorProfile> profiles;
        float achieved_ratio;
        float estimated_quality;
        size_t estimated_size_bytes;
        bool meets_constraints;
        std::vector<std::string> warnings;
    };

    CompressionPlanner();
    ~CompressionPlanner();

    // Create plan from profiles
    Policy CreatePlan(
        const std::vector<TensorProfile>& profiles,
        const Constraints& constraints
    );

    // Optimize plan for constraints
    Policy OptimizePlan(
        const Policy& initial_plan,
        const Constraints& constraints
    );

    // Validate plan against L4.2.3 gates
    bool ValidatePlan(const Policy& plan, std::string* out_error = nullptr);

    // Export/Import
    bool ExportPolicyToJSON(const Policy& policy, const std::string& filename);
    bool ImportPolicyFromJSON(const std::string& filename, Policy* out_policy);

    // Summary statistics
    void PrintPolicySummary(const Policy& policy);

private:
    float CalculateTotalSize(const Policy& policy);
    float CalculateAchievedRatio(const Policy& policy);
    bool AdjustForMemoryBudget(Policy* policy, const Constraints& constraints);
    bool AdjustForQuality(Policy* policy, const Constraints& constraints);
};

// ============================================================================
// Tensor Profiler (Main Interface)
// ============================================================================

/**
 * @brief High-level interface for L4.3.0 tensor profiling
 *
 * Orchestrates calibration collection, sensitivity analysis,
 * and compression planning into unified workflow.
 */
class TensorProfiler {
public:
    TensorProfiler();
    ~TensorProfiler();

    // Initialize with model
    bool Initialize(const std::string& model_path);
    bool IsInitialized() const { return initialized_; }

    // Run complete profiling workflow
    bool RunProfiling(
        const std::vector<uint32_t>& calibration_tokens,
        CompressionPlanner::Constraints constraints
    );

    // Step-by-step workflow (for custom integration)
    bool BeginCalibration();
    bool RecordSample(const std::map<std::string, std::vector<float>>& tensor_data);
    bool EndCalibration();
    bool AnalyzeSensitivity();
    bool CreatePlan(const CompressionPlanner::Constraints& constraints);

    // Access results
    const std::vector<TensorProfile>& GetProfiles() const { return profiles_; }
    const CompressionPlanner::Policy& GetPlan() const { return plan_; }
    const CalibrationCollector& GetCollector() const { return collector_; }

    // Export results
    bool ExportProfiles(const std::string& filename) const;
    bool ExportPlan(const std::string& filename) const;
    bool ExportFullReport(const std::string& filename) const;

    // Validation
    bool ValidateAgainstGates(std::vector<std::string>* out_failures = nullptr);

    // Configuration
    void SetAnalyzerWeights(const SensitivityAnalyzer::Weights& weights);
    void SetAnalyzerThresholds(const SensitivityAnalyzer::Thresholds& thresholds);

private:
    bool initialized_;
    CalibrationCollector collector_;
    SensitivityAnalyzer analyzer_;
    CompressionPlanner planner_;
    std::vector<TensorProfile> profiles_;
    CompressionPlanner::Policy plan_;
    std::string model_path_;
};

// ============================================================================
// Utility Functions
// ============================================================================

// Codec to string for JSON output
const char* CodecToString(compression::CompressionType codec);

// Parse codec from string
compression::CompressionType StringToCodec(const std::string& str);

// Sensitivity score to human-readable category
const char* SensitivityCategory(float score);

// Calculate memory savings from policy
float CalculateMemorySavings(const CompressionPlanner::Policy& policy);

// Compare two policies (for regression testing)
bool ComparePolicies(
    const CompressionPlanner::Policy& a,
    const CompressionPlanner::Policy& b,
    float tolerance = 0.001f
);

} // namespace profiler
} // namespace rawrxd
