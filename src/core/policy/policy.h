// policy.h
// Layer 3: Statistical Policy Learner
// Pure observation→recommendation - NEVER controls execution
//
// CRITICAL INVARIANT: This layer:
//   - ONLY produces: recommendations, drift bands, equivalence classes
//   - NEVER does: direct execution control, routing decisions, scheduling
//
// Execution may read PolicySnapshot at construct-time, but never during execution.

#pragma once

#include <cstdint>
#include <chrono>
#include <optional>
#include <string>
#include <vector>
#include <memory>
#include <map>

namespace rawrxd::policy {

// Forward declarations
class PolicyLearnerImpl;

// ═══════════════════════════════════════════════════════════════════════════════
// Core Types
// ═══════════════════════════════════════════════════════════════════════════════

using TraceId = uint64_t;
using PolicyVersion = uint32_t;

// ═══════════════════════════════════════════════════════════════════════════════
// Execution Trace (Input to Policy)
// ═══════════════════════════════════════════════════════════════════════════════

struct Trace {
    TraceId id;
    std::chrono::steady_clock::time_point timestamp;
    
    // Execution characteristics
    std::string model_architecture;
    uint32_t input_tokens;
    uint32_t output_tokens;
    std::chrono::microseconds latency;
    bool success;
    std::string backend_used;
    
    // Resource usage
    size_t memory_used;
    uint32_t compute_units;
    
    // Outcome
    float quality_score;  // 0.0 - 1.0
    std::string error_type;  // Empty if success
};

// ═══════════════════════════════════════════════════════════════════════════════
// Recommendation (Output from Policy)
// ═══════════════════════════════════════════════════════════════════════════════

struct Recommendation {
    std::string target_architecture;
    std::string recommended_backend;
    float confidence;  // 0.0 - 1.0
    
    // Rationale (human-readable)
    std::string rationale;
    
    // Supporting data
    uint32_t supporting_traces;
    double observed_latency_ms;
    double observed_success_rate;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Drift Band (Equivalence Detection)
// ═══════════════════════════════════════════════════════════════════════════════

struct DriftBand {
    float threshold;  // Outputs within this band are considered equivalent
    std::string metric;  // "latency", "quality", "cost"
    
    bool IsEquivalent(float a, float b) const {
        return std::abs(a - b) < threshold;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Policy Snapshot (Immutable, Versioned)
// ═══════════════════════════════════════════════════════════════════════════════

struct PolicySnapshot {
    PolicyVersion version;
    std::chrono::steady_clock::time_point created_at;
    
    // Routing recommendations by architecture
    std::map<std::string, Recommendation> routing_recommendations;
    
    // Drift bands for equivalence detection
    std::map<std::string, DriftBand> drift_bands;
    
    // Statistical summaries
    double avg_latency_ms;
    double p99_latency_ms;
    double overall_success_rate;
    uint32_t total_traces_analyzed;
    
    bool IsExpired(std::chrono::seconds max_age) const {
        auto now = std::chrono::steady_clock::now();
        return (now - created_at) > max_age;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Policy Learner Interface
// ═══════════════════════════════════════════════════════════════════════════════

class StatisticalPolicyLearner {
public:
    StatisticalPolicyLearner();
    ~StatisticalPolicyLearner();

    // Disable copy/move
    StatisticalPolicyLearner(const StatisticalPolicyLearner&) = delete;
    StatisticalPolicyLearner& operator=(const StatisticalPolicyLearner&) = delete;
    StatisticalPolicyLearner(StatisticalPolicyLearner&&) = delete;
    StatisticalPolicyLearner& operator=(StatisticalPolicyLearner&&) = delete;

    // ═══════════════════════════════════════════════════════════════════════════
    // Observation (Input)
    // ═══════════════════════════════════════════════════════════════════════════

    // Observe an execution trace
    // Thread-safe, can be called from multiple threads
    void Observe(const Trace& trace);

    // Batch observe multiple traces
    void ObserveBatch(const std::vector<Trace>& traces);

    // ═══════════════════════════════════════════════════════════════════════════
    // Recommendation (Output)
    // ═══════════════════════════════════════════════════════════════════════════

    // Produce recommendation for a target architecture
    // Returns nullopt if insufficient data
    std::optional<Recommendation> Recommend(const std::string& architecture) const;

    // Compute drift band for two outputs
    DriftBand ComputeEquivalence(const std::string& metric, 
                                  float threshold) const;

    // Produce immutable policy snapshot
    // This is what execution layers read at construct-time
    PolicySnapshot ProduceSnapshot() const;

    // ═══════════════════════════════════════════════════════════════════════════
    // Analysis
    // ═══════════════════════════════════════════════════════════════════════════

    // Detect anomalous traces
    std::vector<TraceId> DetectAnomalies() const;

    // Find similar traces
    std::vector<TraceId> FindSimilar(const Trace& pattern, float similarity_threshold) const;

    // Compute trend (improving/degrading)
    enum class Trend { Improving, Stable, Degrading, InsufficientData };
    Trend ComputeTrend(const std::string& metric, std::chrono::hours window) const;

    // ═══════════════════════════════════════════════════════════════════════════
    // Statistics
    // ═══════════════════════════════════════════════════════════════════════════

    struct Statistics {
        uint64_t total_traces_observed;
        uint64_t unique_architectures;
        uint64_t unique_backends;
        double avg_traces_per_hour;
        PolicyVersion current_version;
    };

    Statistics GetStatistics() const;
    void ResetStatistics();

    // ═══════════════════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════════════════

    void SetMinTracesForRecommendation(uint32_t min_traces);
    void SetConfidenceThreshold(float threshold);  // 0.0 - 1.0
    void SetMaxSnapshotAge(std::chrono::seconds age);

private:
    std::unique_ptr<PolicyLearnerImpl> impl_;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Global Policy Learner Instance
// ═══════════════════════════════════════════════════════════════════════════════

StatisticalPolicyLearner& GetPolicyLearner();
bool InitializePolicyLearner(const std::string& config_path);
void ShutdownPolicyLearner();

} // namespace rawrxd::policy
