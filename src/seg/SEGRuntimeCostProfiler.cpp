/**
 * SEGRuntimeCostProfiler.cpp
 * 
 * Phase C.0 Batch 2/5: Runtime Cost Profiler Implementation
 */

#include "SEGRuntimeCostProfiler.hpp"
#include <sstream>
#include <iomanip>
#include <numeric>
#include <algorithm>
#include <fstream>
#include <thread>

namespace Sovereign {
namespace SEG {

// ============================================================================
// ComponentCostStats Implementation
// ============================================================================

void ComponentCostStats::AddCost(const ComponentCost& cost) {
    executionCount++;
    if (cost.success) {
        successCount++;
    } else {
        failureCount++;
    }
    
    totalDurationMs += cost.durationMs;
    minDurationMs = std::min(minDurationMs, cost.durationMs);
    maxDurationMs = std::max(maxDurationMs, cost.durationMs);
    
    avgMemoryDeltaMB += cost.memoryDeltaMB;
    maxMemoryDeltaMB = std::max(maxMemoryDeltaMB, cost.memoryDeltaMB);
    
    totalConvergenceGain += cost.convergenceGain;
    totalTokensProcessed += cost.tokensProcessed;
}

void ComponentCostStats::FinalizeStats() {
    if (executionCount > 0) {
        avgDurationMs = totalDurationMs / executionCount;
        avgMemoryDeltaMB /= executionCount;
        avgConvergenceGain = totalConvergenceGain / executionCount;
        avgThroughputTps = totalTokensProcessed / (totalDurationMs / 1000.0); // tokens per second
        successRate = static_cast<double>(successCount) / executionCount;
    }
    
    // P99 calculation would require storing all durations
    p99DurationMs = maxDurationMs; // Simplified
}

// ============================================================================
// ExecutionCostProfile Implementation
// ============================================================================

void ExecutionCostProfile::Finalize() {
    executionEnd = std::chrono::steady_clock::now();
    totalDurationMs = std::chrono::duration<double, std::milli>(executionEnd - executionStart).count();
    
    // Aggregate stats by component type
    for (const auto& cost : componentCosts) {
        auto& stats = aggregatedStats[cost.type];
        stats.type = cost.type;
        stats.typeName = ComponentTypeToString(cost.type);
        stats.AddCost(cost);
    }
    
    for (auto& [type, stats] : aggregatedStats) {
        stats.FinalizeStats();
    }
}

ComponentCostStats ExecutionCostProfile::GetStatsForType(ComponentType type) const {
    auto it = aggregatedStats.find(type);
    if (it != aggregatedStats.end()) {
        return it->second;
    }
    return ComponentCostStats{};
}

double ExecutionCostProfile::GetTotalCost() const {
    double total = 0.0;
    for (const auto& cost : componentCosts) {
        total += cost.durationMs;
    }
    return total;
}

std::string ExecutionCostProfile::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"execution_id\": \"" << executionId << "\",\n";
    json << "  \"total_duration_ms\": " << totalDurationMs << ",\n";
    json << "  \"component_count\": " << componentCosts.size() << ",\n";
    json << "  \"aggregated_stats\": {\n";
    
    size_t i = 0;
    for (const auto& [type, stats] : aggregatedStats) {
        json << "    \"" << stats.typeName << "\": {\n";
        json << "      \"execution_count\": " << stats.executionCount << ",\n";
        json << "      \"success_count\": " << stats.successCount << ",\n";
        json << "      \"failure_count\": " << stats.failureCount << ",\n";
        json << "      \"avg_duration_ms\": " << stats.avgDurationMs << ",\n";
        json << "      \"min_duration_ms\": " << stats.minDurationMs << ",\n";
        json << "      \"max_duration_ms\": " << stats.maxDurationMs << ",\n";
        json << "      \"success_rate\": " << stats.successRate << ",\n";
        json << "      \"avg_convergence_gain\": " << stats.avgConvergenceGain << "\n";
        json << "    }";
        if (++i < aggregatedStats.size()) json << ",";
        json << "\n";
    }
    
    json << "  }\n";
    json << "}\n";
    return json.str();
}

// ============================================================================
// CostComparison Implementation
// ============================================================================

std::string CostComparison::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"baseline_execution\": \"" << baselineExecutionId << "\",\n";
    json << "  \"comparison_execution\": \"" << comparisonExecutionId << "\",\n";
    json << "  \"duration_delta_percent\": " << durationDeltaPercent << ",\n";
    json << "  \"memory_delta_percent\": " << memoryDeltaPercent << ",\n";
    json << "  \"convergence_delta_percent\": " << convergenceDeltaPercent << ",\n";
    json << "  \"throughput_delta_percent\": " << throughputDeltaPercent << ",\n";
    json << "  \"is_regression\": " << (isRegression ? "true" : "false") << ",\n";
    json << "  \"is_improvement\": " << (isImprovement ? "true" : "false") << ",\n";
    json << "  \"regression_components\": [";
    for (size_t i = 0; i < regressionComponents.size(); ++i) {
        json << "\"" << regressionComponents[i] << "\"";
        if (i + 1 < regressionComponents.size()) json << ", ";
    }
    json << "],\n";
    json << "  \"improvement_components\": [";
    for (size_t i = 0; i < improvementComponents.size(); ++i) {
        json << "\"" << improvementComponents[i] << "\"";
        if (i + 1 < improvementComponents.size()) json << ", ";
    }
    json << "]\n";
    json << "}\n";
    return json.str();
}

// ============================================================================
// SEGRuntimeCostProfiler Implementation
// ============================================================================

SEGRuntimeCostProfiler::SEGRuntimeCostProfiler() = default;
SEGRuntimeCostProfiler::~SEGRuntimeCostProfiler() = default;

void SEGRuntimeCostProfiler::SetMemoryTrackingEnabled(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    memoryTrackingEnabled_ = enable;
}

void SEGRuntimeCostProfiler::SetConvergenceTrackingEnabled(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    convergenceTrackingEnabled_ = enable;
}

void SEGRuntimeCostProfiler::SetThroughputTrackingEnabled(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    throughputTrackingEnabled_ = enable;
}

void SEGRuntimeCostProfiler::SetMaxHistorySize(size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    maxHistorySize_ = size;
}

ComponentCost* SEGRuntimeCostProfiler::StartComponent(ComponentType type, const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!currentExecution_) {
        return nullptr;
    }
    
    auto& cost = currentExecution_->componentCosts.emplace_back();
    cost.type = type;
    cost.componentName = name;
    cost.instanceId = std::to_string(currentExecution_->componentCosts.size());
    
    if (memoryTrackingEnabled_) {
        cost.memoryBeforeBytes = GetCurrentMemoryUsage();
    }
    
    currentComponent_ = &cost;
    return &cost;
}

void SEGRuntimeCostProfiler::EndComponent(ComponentCost* cost, bool success) {
    EndComponent(cost, success, "");
}

void SEGRuntimeCostProfiler::EndComponent(ComponentCost* cost, bool success, const std::string& error) {
    if (!cost) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    cost->success = success;
    cost->errorMessage = error;
    
    if (memoryTrackingEnabled_) {
        cost->memoryAfterBytes = GetCurrentMemoryUsage();
    }
    
    cost->Finalize();
    currentComponent_ = nullptr;
}

void SEGRuntimeCostProfiler::StartExecution(const std::string& executionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    currentExecution_ = std::make_unique<ExecutionCostProfile>();
    currentExecution_->executionId = executionId;
    currentExecution_->executionStart = std::chrono::steady_clock::now();
}

ExecutionCostProfile* SEGRuntimeCostProfiler::EndExecution() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!currentExecution_) {
        return nullptr;
    }
    
    currentExecution_->Finalize();
    
    // Store in history
    executionHistory_.push_back(*currentExecution_);
    if (executionHistory_.size() > maxHistorySize_) {
        executionHistory_.erase(executionHistory_.begin());
    }
    
    // Store component costs
    for (const auto& cost : currentExecution_->componentCosts) {
        componentHistory_[cost.type].push_back(cost);
        if (componentHistory_[cost.type].size() > maxHistorySize_) {
            componentHistory_[cost.type].erase(componentHistory_[cost.type].begin());
        }
    }
    
    ExecutionCostProfile* result = currentExecution_.get();
    currentExecution_.release();
    return result;
}

void SEGRuntimeCostProfiler::RecordMemoryBefore(ComponentCost* cost) {
    if (!cost || !memoryTrackingEnabled_) return;
    cost->memoryBeforeBytes = GetCurrentMemoryUsage();
}

void SEGRuntimeCostProfiler::RecordMemoryAfter(ComponentCost* cost) {
    if (!cost || !memoryTrackingEnabled_) return;
    cost->memoryAfterBytes = GetCurrentMemoryUsage();
}

void SEGRuntimeCostProfiler::RecordConvergenceGain(ComponentCost* cost, double gain) {
    if (!cost || !convergenceTrackingEnabled_) return;
    cost->convergenceGain = gain;
}

void SEGRuntimeCostProfiler::RecordConvergenceDelta(ComponentCost* cost, double delta) {
    if (!cost || !convergenceTrackingEnabled_) return;
    cost->convergenceDelta = delta;
}

void SEGRuntimeCostProfiler::RecordThroughput(ComponentCost* cost, double tokens, double durationMs) {
    if (!cost || !throughputTrackingEnabled_) return;
    cost->tokensProcessed = tokens;
    cost->throughputTps = durationMs > 0 ? tokens / (durationMs / 1000.0) : 0.0;
}

ComponentCostStats SEGRuntimeCostProfiler::GetStatsForType(ComponentType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = componentHistory_.find(type);
    if (it == componentHistory_.end() || it->second.empty()) {
        return ComponentCostStats{};
    }
    
    ComponentCostStats stats;
    stats.type = type;
    stats.typeName = ComponentTypeToString(type);
    
    for (const auto& cost : it->second) {
        stats.AddCost(cost);
    }
    stats.FinalizeStats();
    
    return stats;
}

std::map<ComponentType, ComponentCostStats> SEGRuntimeCostProfiler::GetAllStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<ComponentType, ComponentCostStats> result;
    
    for (const auto& [type, costs] : componentHistory_) {
        if (!costs.empty()) {
            ComponentCostStats stats;
            stats.type = type;
            stats.typeName = ComponentTypeToString(type);
            for (const auto& cost : costs) {
                stats.AddCost(cost);
            }
            stats.FinalizeStats();
            result[type] = stats;
        }
    }
    
    return result;
}

std::vector<ExecutionCostProfile> SEGRuntimeCostProfiler::GetExecutionHistory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return executionHistory_;
}

void SEGRuntimeCostProfiler::ClearHistory() {
    std::lock_guard<std::mutex> lock(mutex_);
    executionHistory_.clear();
    componentHistory_.clear();
}

size_t SEGRuntimeCostProfiler::GetHistorySize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return executionHistory_.size();
}

std::string SEGRuntimeCostProfiler::ExportToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"runtime_cost_profiler\": {\n";
    json << "    \"execution_count\": " << executionHistory_.size() << ",\n";
    json << "    \"component_types\": [\n";
    
    size_t i = 0;
    for (const auto& [type, costs] : componentHistory_) {
        json << "      {\n";
        json << "        \"type\": \"" << ComponentTypeToString(type) << "\",\n";
        json << "        \"count\": " << costs.size() << "\n";
        json << "      }";
        if (++i < componentHistory_.size()) json << ",";
        json << "\n";
    }
    
    json << "    ]\n";
    json << "  }\n";
    json << "}\n";
    return json.str();
}

bool SEGRuntimeCostProfiler::ExportToFile(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file) return false;
    file << ExportToJson();
    return file.good();
}

bool SEGRuntimeCostProfiler::HasSufficientData() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return executionHistory_.size() >= 3;
}

CostComparison SEGRuntimeCostProfiler::CompareExecutions(
    const std::string& baselineId, const std::string& comparisonId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    CostComparison result;
    result.baselineExecutionId = baselineId;
    result.comparisonExecutionId = comparisonId;
    
    // Find executions
    const ExecutionCostProfile* baseline = nullptr;
    const ExecutionCostProfile* comparison = nullptr;
    
    for (const auto& exec : executionHistory_) {
        if (exec.executionId == baselineId) baseline = &exec;
        if (exec.executionId == comparisonId) comparison = &exec;
    }
    
    if (!baseline || !comparison) {
        return result; // Empty comparison
    }
    
    // Calculate deltas
    result.durationDeltaPercent = ((comparison->totalDurationMs - baseline->totalDurationMs) 
                                   / baseline->totalDurationMs) * 100.0;
    result.isRegression = result.durationDeltaPercent > 10.0; // >10% slower
    result.isImprovement = result.durationDeltaPercent < -10.0; // >10% faster
    
    return result;
}

CostComparison SEGRuntimeCostProfiler::CompareToAverage(const std::string& executionId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    CostComparison result;
    result.baselineExecutionId = "average";
    result.comparisonExecutionId = executionId;
    
    if (executionHistory_.size() < 2) {
        return result;
    }
    
    // Find the execution
    const ExecutionCostProfile* target = nullptr;
    for (const auto& exec : executionHistory_) {
        if (exec.executionId == executionId) {
            target = &exec;
            break;
        }
    }
    
    if (!target) {
        return result;
    }
    
    // Calculate average duration (excluding target)
    double totalDuration = 0.0;
    size_t count = 0;
    for (const auto& exec : executionHistory_) {
        if (exec.executionId != executionId) {
            totalDuration += exec.totalDurationMs;
            count++;
        }
    }
    
    if (count == 0) {
        return result;
    }
    
    double avgDuration = totalDuration / count;
    result.durationDeltaPercent = ((target->totalDurationMs - avgDuration) / avgDuration) * 100.0;
    result.isRegression = result.durationDeltaPercent > 10.0;
    result.isImprovement = result.durationDeltaPercent < -10.0;
    
    return result;
}

bool SEGRuntimeCostProfiler::DetectRegression(const std::string& executionId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (executionHistory_.size() < 2) {
        return false;
    }
    
    // Find the execution
    const ExecutionCostProfile* target = nullptr;
    for (const auto& exec : executionHistory_) {
        if (exec.executionId == executionId) {
            target = &exec;
            break;
        }
    }
    
    if (!target) {
        return false;
    }
    
    // Calculate average duration (excluding target)
    double totalDuration = 0.0;
    size_t count = 0;
    for (const auto& exec : executionHistory_) {
        if (exec.executionId != executionId) {
            totalDuration += exec.totalDurationMs;
            count++;
        }
    }
    
    if (count == 0) {
        return false;
    }
    
    double avgDuration = totalDuration / count;
    double deltaPercent = ((target->totalDurationMs - avgDuration) / avgDuration) * 100.0;
    return deltaPercent > 10.0; // >10% slower than average
}

std::vector<std::string> SEGRuntimeCostProfiler::GetExpensiveComponents(double thresholdMs) const {
    std::vector<std::string> result;
    
    for (const auto& [type, costs] : componentHistory_) {
        if (!costs.empty()) {
            double avgDuration = 0.0;
            for (const auto& cost : costs) {
                avgDuration += cost.durationMs;
            }
            avgDuration /= costs.size();
            
            if (avgDuration > thresholdMs) {
                result.push_back(ComponentTypeToString(type));
            }
        }
    }
    
    return result;
}

std::vector<std::string> SEGRuntimeCostProfiler::GetFailureProneComponents(double thresholdRate) const {
    std::vector<std::string> result;
    
    for (const auto& [type, costs] : componentHistory_) {
        if (costs.empty()) continue;
        
        size_t failures = 0;
        for (const auto& cost : costs) {
            if (!cost.success) failures++;
        }
        
        double failureRate = static_cast<double>(failures) / costs.size();
        if (failureRate > thresholdRate) {
            result.push_back(ComponentTypeToString(type));
        }
    }
    
    return result;
}

double SEGRuntimeCostProfiler::GetComponentCostEstimate(ComponentType type) const {
    auto stats = GetStatsForType(type);
    return stats.avgDurationMs;
}

double SEGRuntimeCostProfiler::GetComponentSuccessRate(ComponentType type) const {
    auto stats = GetStatsForType(type);
    return stats.successRate;
}

double SEGRuntimeCostProfiler::GetComponentConvergenceEfficiency(ComponentType type) const {
    auto stats = GetStatsForType(type);
    if (stats.avgDurationMs > 0) {
        return stats.avgConvergenceGain / stats.avgDurationMs;
    }
    return 0.0;
}

// ============================================================================
// Helper Functions
// ============================================================================

std::string ComponentTypeToString(ComponentType type) {
    switch (type) {
        case ComponentType::GraphBuild: return "GraphBuild";
        case ComponentType::Planner: return "Planner";
        case ComponentType::EngineCycle: return "EngineCycle";
        case ComponentType::SwarmTask: return "SwarmTask";
        case ComponentType::Telemetry: return "Telemetry";
        case ComponentType::Checkpoint: return "Checkpoint";
        default: return "Unknown";
    }
}

size_t SEGRuntimeCostProfiler::GetCurrentMemoryUsage() const {
    // Platform-specific implementation would go here
    // For now, return 0 as placeholder
    return 0;
}

bool ValidateRuntimeCostProfiler() {
    SEGRuntimeCostProfiler profiler;
    
    // Start execution
    profiler.StartExecution("test-execution");
    
    // Profile a component
    auto* cost = profiler.StartComponent(ComponentType::EngineCycle, "RunUnityCycle");
    if (!cost) return false;
    
    // Simulate work
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    
    // End component
    profiler.EndComponent(cost, true);
    
    // End execution
    auto* profile = profiler.EndExecution();
    if (!profile) return false;
    
    // Verify stats
    auto stats = profiler.GetStatsForType(ComponentType::EngineCycle);
    return stats.executionCount > 0;
}

} // namespace SEG
} // namespace Sovereign
