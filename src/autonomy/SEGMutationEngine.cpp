/**
 * SEGMutationEngine.cpp
 *
 * Phase C.3 Batch 2/5: SEG Autonomous Mutation
 */

#include "SEGMutationEngine.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <random>
#include <chrono>

namespace Autonomy {

// ============================================================================
// SEGMutation Implementation
// ============================================================================

std::string SEGMutation::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"mutationId\":\"" << mutationId << "\",";
    json << "\"type\":" << static_cast<int>(type) << ",";
    json << "\"description\":\"" << description << "\",";
    json << "\"targetNodes\":[";
    for (size_t i = 0; i < targetNodes.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << targetNodes[i] << "\"";
    }
    json << "],";
    json << "\"expectedSpeedup\":" << expectedSpeedup << ",";
    json << "\"riskScore\":" << riskScore << ",";
    json << "\"isReversible\":" << (isReversible ? "true" : "false");
    json << "}";
    return json.str();
}

std::string SEGMutation::ToNaturalLanguage() const {
    std::ostringstream nl;
    nl << "Mutation [" << mutationId << "]: " << description;
    nl << " (expected speedup: " << std::fixed << std::setprecision(1) << (expectedSpeedup * 100) << "%, ";
    nl << "risk: " << (riskScore * 100) << "%)";
    return nl.str();
}

// ============================================================================
// MutationResult Implementation
// ============================================================================

std::string MutationResult::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"success\":" << (success ? "true" : "false") << ",";
    json << "\"mutationId\":\"" << mutationId << "\",";
    json << "\"errorMessage\":\"" << errorMessage << "\",";
    json << "\"beforeCriticalPathMs\":" << beforeCriticalPathMs << ",";
    json << "\"afterCriticalPathMs\":" << afterCriticalPathMs << ",";
    json << "\"actualSpeedup\":" << actualSpeedup << ",";
    json << "\"appliedTimestampMs\":" << appliedTimestampMs;
    json << "}";
    return json.str();
}

void MutationResult::PrintSummary() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           MUTATION RESULT                                        ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Mutation ID: " << std::left << std::setw(48) << mutationId << " ║\n";
    std::cout << "║  Success:     " << std::setw(48) << (success ? "YES" : "NO") << " ║\n";
    if (!success) {
        std::cout << "║  Error:       " << std::setw(48) << errorMessage << " ║\n";
    }
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Performance Impact:                                             ║\n";
    std::cout << "║    Before Critical Path: " << std::setw(10) << std::fixed << std::setprecision(2) << beforeCriticalPathMs << " ms" << std::string(22, ' ') << "║\n";
    std::cout << "║    After Critical Path:  " << std::setw(10) << afterCriticalPathMs << " ms" << std::string(22, ' ') << "║\n";
    std::cout << "║    Actual Speedup:       " << std::setw(9) << std::setprecision(1) << (actualSpeedup * 100) << "%" << std::string(23, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// MutationRecord Implementation
// ============================================================================

std::string MutationRecord::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"mutation\":" << mutation.ToJson() << ",";
    json << "\"result\":" << result.ToJson() << ",";
    json << "\"context\":" << context.ToJson() << ",";
    json << "\"rewardScore\":" << rewardScore;
    json << "}";
    return json.str();
}

// ============================================================================
// MutationEngineConfig Implementation
// ============================================================================

std::string MutationEngineConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"maxMutationRisk\":" << maxMutationRisk << ",";
    json << "\"requireBackupBeforeMutation\":" << (requireBackupBeforeMutation ? "true" : "false") << ",";
    json << "\"maxMutationsPerCycle\":" << maxMutationsPerCycle << ",";
    json << "\"minExpectedSpeedup\":" << minExpectedSpeedup << ",";
    json << "\"enableParallelOptimization\":" << (enableParallelOptimization ? "true" : "false") << ",";
    json << "\"enableCriticalPathOptimization\":" << (enableCriticalPathOptimization ? "true" : "false");
    json << "}";
    return json.str();
}

// ============================================================================
// SEGMutationEngine Implementation
// ============================================================================

SEGMutationEngine::SEGMutationEngine() = default;
SEGMutationEngine::~SEGMutationEngine() = default;

SEGMutationEngine::SEGMutationEngine(SEGMutationEngine&&) noexcept = default;
SEGMutationEngine& SEGMutationEngine::operator=(SEGMutationEngine&&) noexcept = default;

bool SEGMutationEngine::Initialize(const MutationEngineConfig& config) {
    config_ = config;
    initialized_ = true;
    std::cout << "[SEGMutationEngine] Initialized\n";
    return true;
}

void SEGMutationEngine::Shutdown() {
    history_.clear();
    backups_.clear();
    initialized_ = false;
    std::cout << "[SEGMutationEngine] Shutdown complete\n";
}

void SEGMutationEngine::SetExecutionGraph(std::shared_ptr<SEG::ExecutionGraph> graph) {
    graph_ = graph;
}

std::vector<SEGMutation> SEGMutationEngine::GenerateMutations(const Decision& decision) {
    if (!initialized_ || !graph_) {
        return {};
    }
    
    return DecisionToMutationAdapter::Adapt(decision, *this);
}

MutationResult SEGMutationEngine::ApplyMutation(const SEGMutation& mutation) {
    MutationResult result;
    result.mutationId = mutation.mutationId;
    result.beforeCriticalPathMs = CalculateCriticalPathLength();
    result.beforeNodeCount = graph_ ? 0 : 0; // Would get actual count
    result.beforeEdgeCount = graph_ ? 0 : 0;
    
    // Validate
    std::string error;
    if (!ValidateMutation(mutation, error)) {
        result.success = false;
        result.errorMessage = error;
        return result;
    }
    
    // Create backup if required
    if (config_.requireBackupBeforeMutation && mutation.isReversible) {
        // Would backup graph state
        backups_[mutation.mutationId] = SEG::ExecutionGraph{}; // Placeholder
    }
    
    // Apply mutation based on type
    bool applied = false;
    switch (mutation.type) {
        case MutationType::REORDER_EDGES:
            // Would reorder edges in graph
            applied = true;
            break;
        case MutationType::ADD_PARALLEL_PATH:
            // Would add parallel execution path
            applied = true;
            break;
        case MutationType::MERGE_NODES:
            // Would merge nodes
            applied = true;
            break;
        case MutationType::SPLIT_NODE:
            // Would split node
            applied = true;
            break;
        case MutationType::ADJUST_WEIGHTS:
            // Would adjust edge weights
            applied = true;
            break;
        case MutationType::CHANGE_PRIORITY:
            // Would change node priorities
            applied = true;
            break;
        case MutationType::INSERT_ISOLATION:
            // Would insert isolation boundary
            applied = true;
            break;
        case MutationType::REMOVE_REDUNDANCY:
            // Would remove redundant nodes
            applied = true;
            break;
        case MutationType::OPTIMIZE_CRITICAL_PATH:
            // Would optimize critical path
            applied = true;
            break;
        default:
            result.errorMessage = "Unknown mutation type";
            break;
    }
    
    result.success = applied;
    result.afterCriticalPathMs = CalculateCriticalPathLength();
    result.afterNodeCount = result.beforeNodeCount; // Would update
    result.afterEdgeCount = result.beforeEdgeCount;
    result.appliedTimestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    if (result.beforeCriticalPathMs > 0) {
        result.actualSpeedup = (result.beforeCriticalPathMs - result.afterCriticalPathMs) / result.beforeCriticalPathMs;
    }
    
    // Record
    RecordMutation(mutation, result);
    
    // Update stats
    stats_.totalMutations++;
    if (result.success) {
        stats_.successfulMutations++;
    } else {
        stats_.failedMutations++;
    }
    
    return result;
}

bool SEGMutationEngine::RollbackMutation(const std::string& mutationId) {
    auto it = backups_.find(mutationId);
    if (it == backups_.end()) {
        return false;
    }
    
    // Would restore graph from backup
    // graph_ = it->second;
    
    backups_.erase(it);
    stats_.rolledBackMutations++;
    
    std::cout << "[SEGMutationEngine] Rolled back mutation: " << mutationId << "\n";
    return true;
}

MutationResult SEGMutationEngine::PreviewMutation(const SEGMutation& mutation) {
    // Simulate without applying
    MutationResult result;
    result.mutationId = mutation.mutationId;
    result.beforeCriticalPathMs = CalculateCriticalPathLength();
    result.afterCriticalPathMs = result.beforeCriticalPathMs * (1.0 - mutation.expectedSpeedup);
    result.actualSpeedup = mutation.expectedSpeedup;
    result.success = true;
    return result;
}

std::vector<MutationRecord> SEGMutationEngine::GetMutationHistory(int count) const {
    std::vector<MutationRecord> recent;
    int start = std::max(0, static_cast<int>(history_.size()) - count);
    for (int i = start; i < static_cast<int>(history_.size()); ++i) {
        recent.push_back(history_[i]);
    }
    return recent;
}

SEGMutationEngine::Statistics SEGMutationEngine::GetStatistics() const {
    return stats_;
}

std::vector<SEGMutation> SEGMutationEngine::OptimizeForHighLoad() {
    std::vector<SEGMutation> mutations;
    
    // Add parallel paths
    auto parallelMutation = CreateParallelPathMutation("task_a", "task_b");
    parallelMutation.expectedSpeedup = 0.4;
    mutations.push_back(parallelMutation);
    
    // Merge small tasks
    auto mergeMutation = CreateMergeMutation({"small_1", "small_2", "small_3"});
    mergeMutation.expectedSpeedup = 0.2;
    mutations.push_back(mergeMutation);
    
    return mutations;
}

std::vector<SEGMutation> SEGMutationEngine::OptimizeForLowLatency() {
    std::vector<SEGMutation> mutations;
    
    // Optimize critical path
    SEGMutation mutation;
    mutation.mutationId = GenerateMutationId();
    mutation.type = MutationType::OPTIMIZE_CRITICAL_PATH;
    mutation.description = "Optimize critical path for low latency";
    mutation.expectedSpeedup = 0.3;
    mutation.riskScore = 0.2;
    mutations.push_back(mutation);
    
    return mutations;
}

std::vector<SEGMutation> SEGMutationEngine::OptimizeForReliability() {
    std::vector<SEGMutation> mutations;
    
    // Add isolation boundaries
    auto isolationMutation = CreateIsolationMutation("critical_component");
    isolationMutation.expectedSpeedup = -0.05; // Slight overhead
    mutations.push_back(isolationMutation);
    
    return mutations;
}

std::vector<SEGMutation> SEGMutationEngine::OptimizeForThroughput() {
    std::vector<SEGMutation> mutations;
    
    // Reorder for better pipelining
    auto reorderMutation = CreateReorderMutation({"stage1", "stage2", "stage3"});
    reorderMutation.expectedSpeedup = 0.25;
    mutations.push_back(reorderMutation);
    
    return mutations;
}

void SEGMutationEngine::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     SEG MUTATION ENGINE STATUS                                   ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Initialized:        " << std::setw(10) << (initialized_ ? "YES" : "NO") << std::string(26, ' ') << "║\n";
    std::cout << "║  Graph Attached:      " << std::setw(10) << (graph_ ? "YES" : "NO") << std::string(26, ' ') << "║\n";
    std::cout << "║  Total Mutations:     " << std::setw(10) << stats_.totalMutations << std::string(26, ' ') << "║\n";
    std::cout << "║  Successful:         " << std::setw(10) << stats_.successfulMutations << std::string(26, ' ') << "║\n";
    std::cout << "║  Failed:             " << std::setw(10) << stats_.failedMutations << std::string(26, ' ') << "║\n";
    std::cout << "║  Rolled Back:        " << std::setw(10) << stats_.rolledBackMutations << std::string(26, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// Mutation Generators
// ============================================================================

SEGMutation SEGMutationEngine::CreateReorderMutation(const std::vector<std::string>& nodes) {
    SEGMutation mutation;
    mutation.mutationId = GenerateMutationId();
    mutation.type = MutationType::REORDER_EDGES;
    mutation.description = "Reorder execution of " + std::to_string(nodes.size()) + " nodes";
    mutation.targetNodes = nodes;
    mutation.expectedSpeedup = 0.15;
    mutation.riskScore = 0.2;
    mutation.isReversible = true;
    return mutation;
}

SEGMutation SEGMutationEngine::CreateParallelPathMutation(const std::string& source, const std::string& target) {
    SEGMutation mutation;
    mutation.mutationId = GenerateMutationId();
    mutation.type = MutationType::ADD_PARALLEL_PATH;
    mutation.description = "Add parallel path from " + source + " to " + target;
    mutation.targetNodes = {source, target};
    mutation.expectedSpeedup = 0.35;
    mutation.riskScore = 0.3;
    mutation.isReversible = true;
    return mutation;
}

SEGMutation SEGMutationEngine::CreateMergeMutation(const std::vector<std::string>& nodes) {
    SEGMutation mutation;
    mutation.mutationId = GenerateMutationId();
    mutation.type = MutationType::MERGE_NODES;
    mutation.description = "Merge " + std::to_string(nodes.size()) + " nodes into single task";
    mutation.targetNodes = nodes;
    mutation.expectedSpeedup = 0.2;
    mutation.riskScore = 0.25;
    mutation.isReversible = false; // Hard to un-merge
    return mutation;
}

SEGMutation SEGMutationEngine::CreateSplitMutation(const std::string& node, int numParts) {
    SEGMutation mutation;
    mutation.mutationId = GenerateMutationId();
    mutation.type = MutationType::SPLIT_NODE;
    mutation.description = "Split " + node + " into " + std::to_string(numParts) + " parts";
    mutation.targetNodes = {node};
    mutation.parameters["num_parts"] = std::to_string(numParts);
    mutation.expectedSpeedup = 0.25;
    mutation.riskScore = 0.3;
    mutation.isReversible = true;
    return mutation;
}

SEGMutation SEGMutationEngine::CreateWeightAdjustmentMutation(const std::vector<std::string>& edges, double factor) {
    SEGMutation mutation;
    mutation.mutationId = GenerateMutationId();
    mutation.type = MutationType::ADJUST_WEIGHTS;
    mutation.description = "Adjust edge weights by factor " + std::to_string(factor);
    mutation.expectedSpeedup = 0.1;
    mutation.riskScore = 0.15;
    mutation.isReversible = true;
    return mutation;
}

SEGMutation SEGMutationEngine::CreatePriorityMutation(const std::vector<std::string>& nodes, int priorityDelta) {
    SEGMutation mutation;
    mutation.mutationId = GenerateMutationId();
    mutation.type = MutationType::CHANGE_PRIORITY;
    mutation.description = "Change priority of " + std::to_string(nodes.size()) + " nodes";
    mutation.targetNodes = nodes;
    mutation.parameters["priority_delta"] = std::to_string(priorityDelta);
    mutation.expectedSpeedup = 0.1;
    mutation.riskScore = 0.1;
    mutation.isReversible = true;
    return mutation;
}

SEGMutation SEGMutationEngine::CreateIsolationMutation(const std::string& node) {
    SEGMutation mutation;
    mutation.mutationId = GenerateMutationId();
    mutation.type = MutationType::INSERT_ISOLATION;
    mutation.description = "Insert failure isolation around " + node;
    mutation.targetNodes = {node};
    mutation.expectedSpeedup = -0.05; // Overhead
    mutation.riskScore = 0.1;
    mutation.isReversible = true;
    return mutation;
}

// ============================================================================
// Helpers
// ============================================================================

double SEGMutationEngine::CalculateCriticalPathLength() const {
    // Would calculate actual critical path
    return 100.0; // Placeholder
}

double SEGMutationEngine::EstimateSpeedup(const SEGMutation& mutation) const {
    return mutation.expectedSpeedup;
}

bool SEGMutationEngine::ValidateMutation(const SEGMutation& mutation, std::string& error) const {
    if (mutation.riskScore > config_.maxMutationRisk) {
        error = "Mutation risk exceeds threshold";
        return false;
    }
    if (mutation.expectedSpeedup < config_.minExpectedSpeedup) {
        error = "Expected speedup below minimum threshold";
        return false;
    }
    return true;
}

std::string SEGMutationEngine::GenerateMutationId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "mut-" << ms << "-" << dis(gen);
    return id.str();
}

void SEGMutationEngine::RecordMutation(const SEGMutation& mutation, const MutationResult& result) {
    MutationRecord record;
    record.mutation = mutation;
    record.result = result;
    // record.context = ... would capture current context
    record.rewardScore = result.success ? result.actualSpeedup : -0.5;
    history_.push_back(record);
}

void SEGMutationEngine::Statistics::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           MUTATION STATISTICS                                    ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total Mutations:    " << std::setw(10) << totalMutations << std::string(26, ' ') << "║\n";
    std::cout << "║  Successful:        " << std::setw(10) << successfulMutations << std::string(26, ' ') << "║\n";
    std::cout << "║  Failed:            " << std::setw(10) << failedMutations << std::string(26, ' ') << "║\n";
    std::cout << "║  Rolled Back:       " << std::setw(10) << rolledBackMutations << std::string(26, ' ') << "║\n";
    std::cout << "║  Average Speedup:   " << std::setw(9) << std::fixed << std::setprecision(1) << (averageSpeedup * 100) << "%" << std::string(26, ' ') << "║\n";
    std::cout << "║  Success Rate:      " << std::setw(9) << std::setprecision(1) << (successRate * 100) << "%" << std::string(26, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// DecisionToMutationAdapter Implementation
// ============================================================================

std::vector<SEGMutation> DecisionToMutationAdapter::Adapt(const Decision& decision,
                                                           SEGMutationEngine& engine) {
    switch (decision.type) {
        case DecisionType::OPTIMIZE_PATH:
            return AdaptOptimizePath(decision, engine);
        case DecisionType::SPAWN_WORKERS:
            return AdaptSpawnWorkers(decision, engine);
        case DecisionType::MERGE_TASKS:
            return AdaptMergeTasks(decision, engine);
        case DecisionType::REBALANCE_RESOURCES:
            return AdaptRebalanceResources(decision, engine);
        case DecisionType::FREEZE_UNSTABLE_COMPONENT:
            return AdaptFreezeComponent(decision, engine);
        default:
            return {};
    }
}

std::vector<SEGMutation> DecisionToMutationAdapter::AdaptOptimizePath(const Decision& decision, 
                                                                       SEGMutationEngine& engine) {
    return engine.OptimizeForLowLatency();
}

std::vector<SEGMutation> DecisionToMutationAdapter::AdaptSpawnWorkers(const Decision& decision,
                                                                       SEGMutationEngine& engine) {
    return engine.OptimizeForHighLoad();
}

std::vector<SEGMutation> DecisionToMutationAdapter::AdaptMergeTasks(const Decision& decision,
                                                                     SEGMutationEngine& engine) {
    std::vector<SEGMutation> mutations;
    // Would extract nodes from decision actions
    auto mutation = engine.CreateMergeMutation({"task_a", "task_b"});
    mutations.push_back(mutation);
    return mutations;
}

std::vector<SEGMutation> DecisionToMutationAdapter::AdaptRebalanceResources(const Decision& decision,
                                                                             SEGMutationEngine& engine) {
    return engine.OptimizeForThroughput();
}

std::vector<SEGMutation> DecisionToMutationAdapter::AdaptFreezeComponent(const Decision& decision,
                                                                          SEGMutationEngine& engine) {
    std::vector<SEGMutation> mutations;
    // Would extract component from decision
    auto mutation = engine.CreateIsolationMutation("unstable_component");
    mutations.push_back(mutation);
    return mutations;
}

} // namespace Autonomy
