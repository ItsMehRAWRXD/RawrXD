/**
 * SEGPerformanceBridge.hpp
 * 
 * Phase C.0 Batch 1/5: SEG Performance Instrumentation Bridge
 * 
 * Connects TPS benchmarks to SEG telemetry:
 * - Records inference metrics (prompt/generation TPS)
 * - Records cycle execution metrics
 * - Records graph build/plan/execution timing
 * - Provides performance snapshots for adaptive scheduler
 * - Exports metrics for optimization decisions
 */

#pragma once

#include "SovereignExecutionGraph.hpp"
#include "SovereignExecutionPlanner.hpp"
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <atomic>
#include <mutex>

// Forward declaration
namespace Sovereign {
class InfinitePerfectionTelemetry;
}

namespace Sovereign {
namespace SEG {

/**
 * Inference performance metric from TPS benchmarks
 */
struct InferenceMetric {
    std::string model;              // e.g., "phi3-mini"
    std::string backend;            // e.g., "native", "vulkan", "cuda"
    double promptTps{0.0};          // Tokens per second (prompt processing)
    double generationTps{0.0};      // Tokens per second (generation)
    double avgLatencyMs{0.0};       // Average latency in milliseconds
    double p99LatencyMs{0.0};       // P99 latency
    size_t tokensProcessed{0};      // Total tokens processed
    size_t contextLength{0};        // Context length used
    std::chrono::steady_clock::time_point timestamp;
    
    InferenceMetric() : timestamp(std::chrono::steady_clock::now()) {}
};

/**
 * Cycle execution metric from SEG
 */
struct CycleMetric {
    std::string cycleName;          // e.g., "RunUnityCycle"
    int batchNumber{0};             // e.g., 243
    double durationMs{0.0};       // Execution duration
    double convergenceDelta{0.0};   // Convergence metric (0-1)
    bool success{false};            // Execution success
    size_t nodesExecuted{0};        // Nodes in this cycle
    size_t nodesFailed{0};          // Failed nodes
    std::chrono::steady_clock::time_point timestamp;
    
    CycleMetric() : timestamp(std::chrono::steady_clock::now()) {}
};

/**
 * Graph execution performance metric
 */
struct GraphPerformanceMetric {
    double graphBuildMs{0.0};       // Time to build graph
    double planGenerationMs{0.0}; // Time to generate execution plan
    double executionMs{0.0};        // Total execution time
    double parallelEfficiency{0.0}; // Actual parallelism / theoretical max
    size_t totalNodes{0};           // Total nodes in graph
    size_t stagesExecuted{0};       // Execution stages completed
    int maxParallelism{0};          // Maximum parallel workers used
    std::chrono::steady_clock::time_point timestamp;
    
    GraphPerformanceMetric() : timestamp(std::chrono::steady_clock::now()) {}
};

/**
 * Performance snapshot for scheduler decisions
 */
struct PerformanceSnapshot {
    std::chrono::steady_clock::time_point capturedAt;
    
    // Inference metrics (latest)
    double latestPromptTps{0.0};
    double latestGenerationTps{0.0};
    double avgPromptTps{0.0};
    double avgGenerationTps{0.0};
    
    // Cycle metrics (aggregated)
    double avgCycleDurationMs{0.0};
    double avgConvergenceDelta{0.0};
    double cycleSuccessRate{0.0};
    
    // Graph metrics (latest)
    double latestGraphBuildMs{0.0};
    double latestPlanGenerationMs{0.0};
    double latestExecutionMs{0.0};
    double latestParallelEfficiency{0.0};
    
    // Derived scores for scheduler
    double throughputScore{0.0};      // Normalized 0-1
    double convergenceScore{0.0};     // Normalized 0-1
    double reliabilityScore{0.0};     // Normalized 0-1
    double resourceEfficiencyScore{0.0}; // Normalized 0-1
    
    PerformanceSnapshot() : capturedAt(std::chrono::steady_clock::now()) {}
    
    std::string ToJson() const;
};

/**
 * Performance history for trend analysis
 */
struct PerformanceHistory {
    std::vector<InferenceMetric> inferenceMetrics;
    std::vector<CycleMetric> cycleMetrics;
    std::vector<GraphPerformanceMetric> graphMetrics;
    
    static constexpr size_t MAX_HISTORY_SIZE = 1000;
    
    void AddInferenceMetric(const InferenceMetric& metric);
    void AddCycleMetric(const CycleMetric& metric);
    void AddGraphMetric(const GraphPerformanceMetric& metric);
    
    void Clear();
    size_t Size() const;
};

/**
 * SEG Performance Bridge
 * 
 * Connects benchmark measurements to SEG telemetry
 * and provides performance data for adaptive scheduling
 */
class SEGPerformanceBridge {
public:
    SEGPerformanceBridge();
    ~SEGPerformanceBridge();
    
    // Configuration
    void SetMaxHistorySize(size_t size);
    void EnableAutoSnapshot(bool enable);
    void SetSnapshotIntervalMs(int intervalMs);
    
    // Metric recording (thread-safe)
    void RecordInferenceMetric(const InferenceMetric& metric);
    void RecordCycleMetric(const CycleMetric& metric);
    void RecordGraphMetric(const GraphPerformanceMetric& metric);
    
    // Telemetry integration
    void AttachTelemetry(InfinitePerfectionTelemetry* telemetry);
    void FlushToTelemetry();
    
    // Snapshot generation
    PerformanceSnapshot GetSnapshot() const;
    PerformanceSnapshot CalculateDerivedScores(const PerformanceSnapshot& base) const;
    
    // History access
    PerformanceHistory GetHistory() const;
    void ClearHistory();
    
    // Export
    std::string ExportToJson() const;
    bool ExportToFile(const std::string& filepath) const;
    
    // Validation
    bool HasSufficientData() const;
    size_t GetInferenceMetricCount() const;
    size_t GetCycleMetricCount() const;
    size_t GetGraphMetricCount() const;
    
    // Scheduler integration
    double GetThroughputScore() const;
    double GetConvergenceScore() const;
    double GetReliabilityScore() const;
    double GetResourceEfficiencyScore() const;
    
private:
    mutable std::mutex mutex_;
    PerformanceHistory history_;
    InfinitePerfectionTelemetry* telemetry_{nullptr};
    
    // Configuration
    size_t maxHistorySize_{PerformanceHistory::MAX_HISTORY_SIZE};
    bool autoSnapshotEnabled_{false};
    int snapshotIntervalMs_{1000};
    
    // Cached snapshots
    mutable PerformanceSnapshot lastSnapshot_;
    mutable std::atomic<bool> snapshotDirty_{true};
    
    // Calculation helpers
    double CalculateAveragePromptTps() const;
    double CalculateAverageGenerationTps() const;
    double CalculateAverageCycleDuration() const;
    double CalculateCycleSuccessRate() const;
    double CalculateAverageConvergence() const;
};

/**
 * Performance-aware execution config
 * Uses bridge data to optimize execution
 */
struct PerformanceAwareConfig {
    double throughputWeight{1.0};
    double convergenceWeight{1.0};
    double reliabilityWeight{1.0};
    double resourceEfficiencyWeight{1.0};
    
    double minAcceptableThroughput{100.0};  // TPS
    double minAcceptableConvergence{0.7};   // 0-1
    double minAcceptableReliability{0.9};     // Success rate
    
    // Calculate priority score for a cycle
    double CalculatePriority(
        double convergenceScore,
        double historicalSuccess,
        double throughputScore,
        double resourceCost
    ) const {
        return 
            convergenceWeight * convergenceScore +
            reliabilityWeight * historicalSuccess +
            throughputWeight * throughputScore +
            resourceEfficiencyWeight * (1.0 / (resourceCost + 0.01));
    }
};

/**
 * Quick validation function
 */
bool ValidatePerformanceBridge();

/**
 * Export performance report
 */
std::string ExportPerformanceReport(const SEGPerformanceBridge& bridge);

} // namespace SEG
} // namespace Sovereign
