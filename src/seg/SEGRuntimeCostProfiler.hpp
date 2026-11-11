/**
 * SEGRuntimeCostProfiler.hpp
 * 
 * Phase C.0 Batch 2/5: Runtime Cost Profiler
 * 
 * Per-component cost attribution for SEG execution:
 * - Graph Build costs
 * - Planner costs
 * - Engine Cycle costs
 * - Swarm Task costs
 * - Telemetry costs
 * - Checkpoint costs
 * 
 * Enables scheduler to distinguish:
 * - Fast but ineffective paths
 * - Slow but high-convergence paths
 * - Expensive failure patterns
 */

#pragma once

#include "SovereignExecutionGraph.hpp"
#include "SovereignExecutionPlanner.hpp"
#include "SEGPerformanceBridge.hpp"
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <atomic>
#include <mutex>

namespace Sovereign {
namespace SEG {

/**
 * Component types for cost attribution
 */
enum class ComponentType {
    GraphBuild,
    Planner,
    EngineCycle,
    SwarmTask,
    Telemetry,
    Checkpoint,
    Unknown
};

/**
 * Cost metric for a single component execution
 */
struct ComponentCost {
    ComponentType type{ComponentType::Unknown};
    std::string componentName;
    std::string instanceId;
    
    // Timing
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    double durationMs{0.0};
    
    // Memory
    size_t memoryBeforeBytes{0};
    size_t memoryAfterBytes{0};
    double memoryDeltaMB{0.0};
    
    // Execution
    bool success{false};
    std::string errorMessage;
    int retryCount{0};
    
    // Convergence (for cycles/tasks)
    double convergenceGain{0.0};      // Convergence improvement
    double convergenceDelta{0.0};       // Raw convergence metric
    
    // Throughput
    double tokensProcessed{0};
    double throughputTps{0.0};
    
    // Resource usage
    int cpuCoresUsed{0};
    double cpuUtilization{0.0};        // 0-1
    bool gpuUsed{false};
    int gpuMemoryMB{0};
    
    ComponentCost() : startTime(std::chrono::steady_clock::now()) {}
    
    void Finalize() {
        endTime = std::chrono::steady_clock::now();
        durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        memoryDeltaMB = static_cast<double>(memoryAfterBytes - memoryBeforeBytes) / (1024.0 * 1024.0);
    }
};

/**
 * Aggregated cost statistics for a component type
 */
struct ComponentCostStats {
    ComponentType type{ComponentType::Unknown};
    std::string typeName;
    
    // Counts
    size_t executionCount{0};
    size_t successCount{0};
    size_t failureCount{0};
    
    // Timing
    double totalDurationMs{0.0};
    double avgDurationMs{0.0};
    double minDurationMs{std::numeric_limits<double>::max()};
    double maxDurationMs{0.0};
    double p99DurationMs{0.0};
    
    // Memory
    double avgMemoryDeltaMB{0.0};
    double maxMemoryDeltaMB{0.0};
    
    // Convergence
    double avgConvergenceGain{0.0};
    double totalConvergenceGain{0.0};
    
    // Throughput
    double avgThroughputTps{0.0};
    double totalTokensProcessed{0.0};
    
    // Success rate
    double successRate{0.0};
    
    void AddCost(const ComponentCost& cost);
    void FinalizeStats();
};

/**
 * Cost profile for an execution plan
 */
struct ExecutionCostProfile {
    std::string executionId;
    std::chrono::steady_clock::time_point executionStart;
    std::chrono::steady_clock::time_point executionEnd;
    double totalDurationMs{0.0};
    
    std::vector<ComponentCost> componentCosts;
    std::map<ComponentType, ComponentCostStats> aggregatedStats;
    
    // Critical path analysis
    double criticalPathDurationMs{0.0};
    std::vector<std::string> criticalPathComponents;
    
    // Efficiency metrics
    double parallelEfficiency{0.0};
    double resourceUtilization{0.0};
    double convergenceEfficiency{0.0};  // Convergence gain per ms
    
    void Finalize();
    ComponentCostStats GetStatsForType(ComponentType type) const;
    double GetTotalCost() const;
    std::string ToJson() const;
};

/**
 * Cost comparison result
 */
struct CostComparison {
    std::string baselineExecutionId;
    std::string comparisonExecutionId;
    
    double durationDeltaPercent{0.0};
    double memoryDeltaPercent{0.0};
    double convergenceDeltaPercent{0.0};
    double throughputDeltaPercent{0.0};
    
    bool isRegression{false};
    bool isImprovement{false};
    std::vector<std::string> regressionComponents;
    std::vector<std::string> improvementComponents;
    
    std::string ToJson() const;
};

/**
 * Runtime Cost Profiler
 * 
 * Tracks per-component costs for adaptive scheduling decisions
 */
class SEGRuntimeCostProfiler {
public:
    SEGRuntimeCostProfiler();
    ~SEGRuntimeCostProfiler();
    
    // Configuration
    void SetMemoryTrackingEnabled(bool enable);
    void SetConvergenceTrackingEnabled(bool enable);
    void SetThroughputTrackingEnabled(bool enable);
    void SetMaxHistorySize(size_t size);
    
    // Component lifecycle
    ComponentCost* StartComponent(ComponentType type, const std::string& name);
    void EndComponent(ComponentCost* cost, bool success = true);
    void EndComponent(ComponentCost* cost, bool success, const std::string& error);
    
    // Execution lifecycle
    void StartExecution(const std::string& executionId);
    ExecutionCostProfile* EndExecution();
    
    // Memory tracking
    void RecordMemoryBefore(ComponentCost* cost);
    void RecordMemoryAfter(ComponentCost* cost);
    
    // Convergence tracking
    void RecordConvergenceGain(ComponentCost* cost, double gain);
    void RecordConvergenceDelta(ComponentCost* cost, double delta);
    
    // Throughput tracking
    void RecordThroughput(ComponentCost* cost, double tokens, double durationMs);
    
    // Statistics
    ComponentCostStats GetStatsForType(ComponentType type) const;
    std::map<ComponentType, ComponentCostStats> GetAllStats() const;
    
    // Comparison
    CostComparison CompareExecutions(const std::string& baselineId, const std::string& comparisonId) const;
    CostComparison CompareToAverage(const std::string& executionId) const;
    
    // History
    std::vector<ExecutionCostProfile> GetExecutionHistory() const;
    void ClearHistory();
    size_t GetHistorySize() const;
    
    // Export
    std::string ExportToJson() const;
    bool ExportToFile(const std::string& filepath) const;
    
    // Validation
    bool HasSufficientData() const;
    bool DetectRegression(const std::string& executionId) const;
    std::vector<std::string> GetExpensiveComponents(double thresholdMs = 100.0) const;
    std::vector<std::string> GetFailureProneComponents(double thresholdRate = 0.1) const;
    
    // Scheduler integration
    double GetComponentCostEstimate(ComponentType type) const;
    double GetComponentSuccessRate(ComponentType type) const;
    double GetComponentConvergenceEfficiency(ComponentType type) const;
    
private:
    mutable std::mutex mutex_;
    
    // Configuration
    bool memoryTrackingEnabled_{true};
    bool convergenceTrackingEnabled_{true};
    bool throughputTrackingEnabled_{true};
    size_t maxHistorySize_{100};
    
    // Current execution
    std::unique_ptr<ExecutionCostProfile> currentExecution_;
    ComponentCost* currentComponent_{nullptr};
    
    // History
    std::vector<ExecutionCostProfile> executionHistory_;
    std::map<ComponentType, std::vector<ComponentCost>> componentHistory_;
    
    // Calculation helpers
    double CalculateCriticalPath(const ExecutionCostProfile& profile) const;
    double CalculateParallelEfficiency(const ExecutionCostProfile& profile) const;
    double CalculateConvergenceEfficiency(const ExecutionCostProfile& profile) const;
    size_t GetCurrentMemoryUsage() const;
};

/**
 * Cost-aware execution config
 */
struct CostAwareExecutionConfig {
    double maxAcceptableDurationMs{1000.0};
    double maxAcceptableMemoryMB{100.0};
    double minAcceptableSuccessRate{0.95};
    double minAcceptableConvergenceEfficiency{0.01};  // Convergence per ms
    
    bool ShouldAcceptCost(const ComponentCost& cost) const {
        if (cost.durationMs > maxAcceptableDurationMs) return false;
        if (cost.memoryDeltaMB > maxAcceptableMemoryMB) return false;
        return true;
    }
};

/**
 * Component type to string conversion
 */
std::string ComponentTypeToString(ComponentType type);

/**
 * Quick validation
 */
bool ValidateRuntimeCostProfiler();

} // namespace SEG
} // namespace Sovereign
