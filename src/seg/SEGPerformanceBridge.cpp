/**
 * SEGPerformanceBridge.cpp
 * 
 * Phase C.0 Batch 1/5: SEG Performance Instrumentation Bridge Implementation
 */

#include "SEGPerformanceBridge.hpp"
#include <sstream>
#include <iomanip>
#include <numeric>
#include <algorithm>
#include <fstream>

namespace Sovereign {
namespace SEG {

// ============================================================================
// PerformanceSnapshot Implementation
// ============================================================================

std::string PerformanceSnapshot::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"performance_snapshot\": {\n";
    json << "    \"captured_at\": \"" << std::chrono::duration_cast<std::chrono::milliseconds>(
        capturedAt.time_since_epoch()).count() << "\",\n";
    json << "    \"inference\": {\n";
    json << "      \"latest_prompt_tps\": " << latestPromptTps << ",\n";
    json << "      \"latest_generation_tps\": " << latestGenerationTps << ",\n";
    json << "      \"avg_prompt_tps\": " << avgPromptTps << ",\n";
    json << "      \"avg_generation_tps\": " << avgGenerationTps << "\n";
    json << "    },\n";
    json << "    \"cycles\": {\n";
    json << "      \"avg_duration_ms\": " << avgCycleDurationMs << ",\n";
    json << "      \"avg_convergence_delta\": " << avgConvergenceDelta << ",\n";
    json << "      \"success_rate\": " << cycleSuccessRate << "\n";
    json << "    },\n";
    json << "    \"graph\": {\n";
    json << "      \"build_ms\": " << latestGraphBuildMs << ",\n";
    json << "      \"plan_generation_ms\": " << latestPlanGenerationMs << ",\n";
    json << "      \"execution_ms\": " << latestExecutionMs << ",\n";
    json << "      \"parallel_efficiency\": " << latestParallelEfficiency << "\n";
    json << "    },\n";
    json << "    \"scheduler_scores\": {\n";
    json << "      \"throughput\": " << throughputScore << ",\n";
    json << "      \"convergence\": " << convergenceScore << ",\n";
    json << "      \"reliability\": " << reliabilityScore << ",\n";
    json << "      \"resource_efficiency\": " << resourceEfficiencyScore << "\n";
    json << "    }\n";
    json << "  }\n";
    json << "}\n";
    return json.str();
}

// ============================================================================
// PerformanceHistory Implementation
// ============================================================================

void PerformanceHistory::AddInferenceMetric(const InferenceMetric& metric) {
    inferenceMetrics.push_back(metric);
    if (inferenceMetrics.size() > MAX_HISTORY_SIZE) {
        inferenceMetrics.erase(inferenceMetrics.begin());
    }
}

void PerformanceHistory::AddCycleMetric(const CycleMetric& metric) {
    cycleMetrics.push_back(metric);
    if (cycleMetrics.size() > MAX_HISTORY_SIZE) {
        cycleMetrics.erase(cycleMetrics.begin());
    }
}

void PerformanceHistory::AddGraphMetric(const GraphPerformanceMetric& metric) {
    graphMetrics.push_back(metric);
    if (graphMetrics.size() > MAX_HISTORY_SIZE) {
        graphMetrics.erase(graphMetrics.begin());
    }
}

void PerformanceHistory::Clear() {
    inferenceMetrics.clear();
    cycleMetrics.clear();
    graphMetrics.clear();
}

size_t PerformanceHistory::Size() const {
    return inferenceMetrics.size() + cycleMetrics.size() + graphMetrics.size();
}

// ============================================================================
// SEGPerformanceBridge Implementation
// ============================================================================

SEGPerformanceBridge::SEGPerformanceBridge() = default;
SEGPerformanceBridge::~SEGPerformanceBridge() = default;

void SEGPerformanceBridge::SetMaxHistorySize(size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    maxHistorySize_ = size;
}

void SEGPerformanceBridge::EnableAutoSnapshot(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    autoSnapshotEnabled_ = enable;
}

void SEGPerformanceBridge::SetSnapshotIntervalMs(int intervalMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    snapshotIntervalMs_ = intervalMs;
}

void SEGPerformanceBridge::RecordInferenceMetric(const InferenceMetric& metric) {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.AddInferenceMetric(metric);
    snapshotDirty_.store(true, std::memory_order_relaxed);
    
    if (telemetry_) {
        // TODO: Send to telemetry system
    }
}

void SEGPerformanceBridge::RecordCycleMetric(const CycleMetric& metric) {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.AddCycleMetric(metric);
    snapshotDirty_.store(true, std::memory_order_relaxed);
}

void SEGPerformanceBridge::RecordGraphMetric(const GraphPerformanceMetric& metric) {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.AddGraphMetric(metric);
    snapshotDirty_.store(true, std::memory_order_relaxed);
}

void SEGPerformanceBridge::AttachTelemetry(InfinitePerfectionTelemetry* telemetry) {
    std::lock_guard<std::mutex> lock(mutex_);
    telemetry_ = telemetry;
}

void SEGPerformanceBridge::FlushToTelemetry() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!telemetry_) return;
    
    // TODO: Flush accumulated metrics to telemetry
}

PerformanceSnapshot SEGPerformanceBridge::GetSnapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    PerformanceSnapshot snapshot;
    
    // Inference metrics
    snapshot.latestPromptTps = history_.inferenceMetrics.empty() ? 0.0 : 
        history_.inferenceMetrics.back().promptTps;
    snapshot.latestGenerationTps = history_.inferenceMetrics.empty() ? 0.0 :
        history_.inferenceMetrics.back().generationTps;
    snapshot.avgPromptTps = CalculateAveragePromptTps();
    snapshot.avgGenerationTps = CalculateAverageGenerationTps();
    
    // Cycle metrics
    snapshot.avgCycleDurationMs = CalculateAverageCycleDuration();
    snapshot.avgConvergenceDelta = CalculateAverageConvergence();
    snapshot.cycleSuccessRate = CalculateCycleSuccessRate();
    
    // Graph metrics
    if (!history_.graphMetrics.empty()) {
        const auto& latest = history_.graphMetrics.back();
        snapshot.latestGraphBuildMs = latest.graphBuildMs;
        snapshot.latestPlanGenerationMs = latest.planGenerationMs;
        snapshot.latestExecutionMs = latest.executionMs;
        snapshot.latestParallelEfficiency = latest.parallelEfficiency;
    }
    
    // Calculate derived scores
    snapshot = CalculateDerivedScores(snapshot);
    
    lastSnapshot_ = snapshot;
    snapshotDirty_.store(false, std::memory_order_relaxed);
    
    return snapshot;
}

PerformanceSnapshot SEGPerformanceBridge::CalculateDerivedScores(const PerformanceSnapshot& base) const {
    PerformanceSnapshot scored = base;
    
    // Throughput score: normalize to 0-1 (assuming max 5000 TPS)
    double maxTps = 5000.0;
    scored.throughputScore = std::min(1.0, (scored.avgPromptTps + scored.avgGenerationTps) / (2.0 * maxTps));
    
    // Convergence score: already 0-1
    scored.convergenceScore = scored.avgConvergenceDelta;
    
    // Reliability score: success rate
    scored.reliabilityScore = scored.cycleSuccessRate;
    
    // Resource efficiency: parallel efficiency
    scored.resourceEfficiencyScore = scored.latestParallelEfficiency;
    
    return scored;
}

PerformanceHistory SEGPerformanceBridge::GetHistory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_;
}

void SEGPerformanceBridge::ClearHistory() {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.Clear();
    snapshotDirty_.store(true, std::memory_order_relaxed);
}

std::string SEGPerformanceBridge::ExportToJson() const {
    auto snapshot = GetSnapshot();
    return snapshot.ToJson();
}

bool SEGPerformanceBridge::ExportToFile(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file) return false;
    
    file << ExportToJson();
    return file.good();
}

bool SEGPerformanceBridge::HasSufficientData() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_.inferenceMetrics.size() >= 3 &&
           history_.cycleMetrics.size() >= 3 &&
           history_.graphMetrics.size() >= 1;
}

size_t SEGPerformanceBridge::GetInferenceMetricCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_.inferenceMetrics.size();
}

size_t SEGPerformanceBridge::GetCycleMetricCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_.cycleMetrics.size();
}

size_t SEGPerformanceBridge::GetGraphMetricCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_.graphMetrics.size();
}

double SEGPerformanceBridge::GetThroughputScore() const {
    auto snapshot = GetSnapshot();
    return snapshot.throughputScore;
}

double SEGPerformanceBridge::GetConvergenceScore() const {
    auto snapshot = GetSnapshot();
    return snapshot.convergenceScore;
}

double SEGPerformanceBridge::GetReliabilityScore() const {
    auto snapshot = GetSnapshot();
    return snapshot.reliabilityScore;
}

double SEGPerformanceBridge::GetResourceEfficiencyScore() const {
    auto snapshot = GetSnapshot();
    return snapshot.resourceEfficiencyScore;
}

// ============================================================================
// Calculation Helpers
// ============================================================================

double SEGPerformanceBridge::CalculateAveragePromptTps() const {
    if (history_.inferenceMetrics.empty()) return 0.0;
    
    double sum = 0.0;
    for (const auto& m : history_.inferenceMetrics) {
        sum += m.promptTps;
    }
    return sum / history_.inferenceMetrics.size();
}

double SEGPerformanceBridge::CalculateAverageGenerationTps() const {
    if (history_.inferenceMetrics.empty()) return 0.0;
    
    double sum = 0.0;
    for (const auto& m : history_.inferenceMetrics) {
        sum += m.generationTps;
    }
    return sum / history_.inferenceMetrics.size();
}

double SEGPerformanceBridge::CalculateAverageCycleDuration() const {
    if (history_.cycleMetrics.empty()) return 0.0;
    
    double sum = 0.0;
    for (const auto& m : history_.cycleMetrics) {
        sum += m.durationMs;
    }
    return sum / history_.cycleMetrics.size();
}

double SEGPerformanceBridge::CalculateCycleSuccessRate() const {
    if (history_.cycleMetrics.empty()) return 0.0;
    
    size_t successes = 0;
    for (const auto& m : history_.cycleMetrics) {
        if (m.success) successes++;
    }
    return static_cast<double>(successes) / history_.cycleMetrics.size();
}

double SEGPerformanceBridge::CalculateAverageConvergence() const {
    if (history_.cycleMetrics.empty()) return 0.0;
    
    double sum = 0.0;
    for (const auto& m : history_.cycleMetrics) {
        sum += m.convergenceDelta;
    }
    return sum / history_.cycleMetrics.size();
}

// ============================================================================
// Global Functions
// ============================================================================

bool ValidatePerformanceBridge() {
    SEGPerformanceBridge bridge;
    
    // Add some test metrics
    InferenceMetric inf;
    inf.model = "test-model";
    inf.backend = "native";
    inf.promptTps = 1000.0;
    inf.generationTps = 200.0;
    bridge.RecordInferenceMetric(inf);
    
    CycleMetric cycle;
    cycle.cycleName = "RunUnityCycle";
    cycle.batchNumber = 243;
    cycle.durationMs = 14.0;
    cycle.convergenceDelta = 0.85;
    cycle.success = true;
    bridge.RecordCycleMetric(cycle);
    
    GraphPerformanceMetric graph;
    graph.graphBuildMs = 42.0;
    graph.planGenerationMs = 8.0;
    graph.executionMs = 1200.0;
    graph.parallelEfficiency = 0.84;
    bridge.RecordGraphMetric(graph);
    
    // Verify snapshot generation
    auto snapshot = bridge.GetSnapshot();
    
    return snapshot.latestPromptTps > 0 &&
           snapshot.avgCycleDurationMs > 0 &&
           snapshot.latestGraphBuildMs > 0;
}

std::string ExportPerformanceReport(const SEGPerformanceBridge& bridge) {
    return bridge.ExportToJson();
}

} // namespace SEG
} // namespace Sovereign
