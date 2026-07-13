/**
 * SovereignExecutionGraphBuilder.cpp
 * 
 * Phase B.4 Batch 2/5: Graph Builder Auto-Discovery Implementation
 */

#include "SovereignExecutionGraphBuilder.hpp"
#include <algorithm>
#include <sstream>
#include <iostream>
#include <thread>

namespace Sovereign {
namespace SEG {

// ============================================================================
// SovereignExecutionGraphBuilderEnhanced Implementation
// ============================================================================

SovereignExecutionGraphBuilderEnhanced::SovereignExecutionGraphBuilderEnhanced()
    : startBatch_(94), endBatch_(256), includeTelemetry_(true), autoDependencies_(true) {
}

void SovereignExecutionGraphBuilderEnhanced::SetEngine(
    InfinitePerfection::InfinitePerfectionEngine* engine) {
    engine_ = engine;
}

void SovereignExecutionGraphBuilderEnhanced::SetSwarm(SovereignSwarm* swarm) {
    swarm_ = swarm;
}

void SovereignExecutionGraphBuilderEnhanced::SetBatchRange(int startBatch, int endBatch) {
    startBatch_ = startBatch;
    endBatch_ = endBatch;
}

DiscoveryResult SovereignExecutionGraphBuilderEnhanced::DiscoverAll() {
    DiscoveryResult result;
    discoveryErrors_.clear();
    
    // Get built-in cycles and tasks
    result.cycles = GetBuiltInUnityCycles();
    result.tasks = GetBuiltInSwarmTasks();
    
    // Try reflection-based discovery if engine/swarm available
    if (engine_) {
        auto reflectedCycles = DiscoverCyclesViaReflection();
        if (!reflectedCycles.empty()) {
            // Merge with built-in, preferring reflected
            for (auto& rc : reflectedCycles) {
                auto it = std::find_if(result.cycles.begin(), result.cycles.end(),
                    [&rc](const DiscoveredCycle& c) { return c.name == rc.name; });
                if (it == result.cycles.end()) {
                    result.cycles.push_back(rc);
                }
            }
        }
    }
    
    if (swarm_) {
        auto reflectedTasks = DiscoverTasksViaReflection();
        if (!reflectedTasks.empty()) {
            for (auto& rt : reflectedTasks) {
                auto it = std::find_if(result.tasks.begin(), result.tasks.end(),
                    [&rt](const DiscoveredTask& t) { return t.name == rt.name; });
                if (it == result.tasks.end()) {
                    result.tasks.push_back(rt);
                }
            }
        }
    }
    
    // Filter by batch range
    result.cycles.erase(
        std::remove_if(result.cycles.begin(), result.cycles.end(),
            [this](const DiscoveredCycle& c) { 
                return c.batchNumber < startBatch_ || c.batchNumber > endBatch_; 
            }),
        result.cycles.end());
    
    result.tasks.erase(
        std::remove_if(result.tasks.begin(), result.tasks.end(),
            [this](const DiscoveredTask& t) { 
                return t.batchNumber < startBatch_ || t.batchNumber > endBatch_; 
            }),
        result.tasks.end());
    
    // Infer dependencies
    if (autoDependencies_) {
        InferDependencies(result);
    }
    
    // Apply custom mappings
    for (const auto& [cycle, task] : customDependencies_) {
        result.cycleToTaskMapping[cycle] = task;
    }
    
    return result;
}

std::vector<DiscoveredCycle> SovereignExecutionGraphBuilderEnhanced::DiscoverEngineCycles() {
    return GetBuiltInUnityCycles();
}

std::vector<DiscoveredTask> SovereignExecutionGraphBuilderEnhanced::DiscoverSwarmTasks() {
    return GetBuiltInSwarmTasks();
}

std::unique_ptr<ExecutionGraph> SovereignExecutionGraphBuilderEnhanced::BuildFromDiscovery(
    const DiscoveryResult& result) {
    
    auto graph = std::make_unique<ExecutionGraph>("AutoDiscoveredGraph");
    
    // Create nodes for cycles
    std::map<std::string, NodeId> cycleNodeIds;
    for (const auto& cycle : result.cycles) {
        auto* node = graph->AddEngineCycleNode(cycle.name, cycle.batchNumber);
        if (node) {
            cycleNodeIds[cycle.name] = node->id;
            // Store metadata
            node->metadata["description"] = cycle.description;
        }
    }
    
    // Create nodes for tasks
    std::map<std::string, NodeId> taskNodeIds;
    for (const auto& task : result.tasks) {
        auto* node = graph->AddSwarmTaskNode(task.name);
        if (node) {
            taskNodeIds[task.name] = node->id;
            node->metadata["description"] = task.description;
            node->metadata["category"] = task.category;
        }
    }
    
    // Create edges from cycle-task mappings
    for (const auto& [cycleName, taskName] : result.cycleToTaskMapping) {
        auto cycleIt = cycleNodeIds.find(cycleName);
        auto taskIt = taskNodeIds.find(taskName);
        
        if (cycleIt != cycleNodeIds.end() && taskIt != taskNodeIds.end()) {
            // Task feeds into cycle
            graph->AddEdge(taskIt->second, cycleIt->second);
        }
    }
    
    // Create edges from discovered dependencies
    for (const auto& cycle : result.cycles) {
        auto fromIt = cycleNodeIds.find(cycle.name);
        if (fromIt == cycleNodeIds.end()) continue;
        
        for (const auto& depName : cycle.dependencies) {
            auto toIt = cycleNodeIds.find(depName);
            if (toIt != cycleNodeIds.end()) {
                graph->AddEdge(toIt->second, fromIt->second);
            }
        }
    }
    
    // Add telemetry if enabled
    if (includeTelemetry_) {
        auto* telemetryNode = graph->AddTelemetryNode("AutoDiscovery");
        
        // Connect all cycles to telemetry
        for (const auto& [name, id] : cycleNodeIds) {
            graph->AddEdge(id, telemetryNode->id);
        }
    }
    
    return graph;
}

std::unique_ptr<ExecutionGraph> SovereignExecutionGraphBuilderEnhanced::BuildAuto() {
    auto result = DiscoverAll();
    return BuildFromDiscovery(result);
}

void SovereignExecutionGraphBuilderEnhanced::MapCycleToTask(
    const std::string& cycleName, const std::string& taskName) {
    customDependencies_[cycleName] = taskName;
}

void SovereignExecutionGraphBuilderEnhanced::AddCustomDependency(
    const std::string& from, const std::string& to) {
    // Store in custom dependencies (interpreted as task -> cycle mapping)
    customDependencies_[to] = from;
}

bool SovereignExecutionGraphBuilderEnhanced::ValidateDiscovery(
    const DiscoveryResult& result) const {
    return GetDiscoveryErrors().empty();
}

std::vector<std::string> SovereignExecutionGraphBuilderEnhanced::GetDiscoveryErrors() const {
    return discoveryErrors_;
}

// ============================================================================
// Built-in Definitions
// ============================================================================

std::vector<DiscoveredCycle> SovereignExecutionGraphBuilderEnhanced::GetBuiltInUnityCycles() {
    std::vector<DiscoveredCycle> cycles;
    
    // Unity Cycle (Batch 243)
    cycles.push_back({
        "RunUnityCycle", 243,
        "Sovereign Unity: Binds all 9 previous cycles into a single sovereign continuum",
        {}, {"UnityField"}
    });
    
    // Integration Cycle (Batch 244)
    cycles.push_back({
        "RunIntegrationCycle", 244,
        "Sovereign Integration: Weaves Unity outputs into cross-cycle integration substrate",
        {"RunUnityCycle"}, {"IntegrationField"}
    });
    
    // Synthesis Cycle (Batch 245)
    cycles.push_back({
        "RunSynthesisCycle", 245,
        "Sovereign Synthesis: Where woven cycles wake up and new behavior emerges",
        {"RunIntegrationCycle"}, {"SynthesisField"}
    });
    
    // Convergence Cycle (Batch 246)
    cycles.push_back({
        "RunConvergenceCycle", 246,
        "Sovereign Convergence: Where emergent patterns condense into attractors",
        {"RunSynthesisCycle"}, {"ConvergenceField"}
    });
    
    // Coherence Cycle (Batch 247)
    cycles.push_back({
        "RunCoherenceCycle", 247,
        "Sovereign Coherence: Where focal points stabilize into unified behavior",
        {"RunConvergenceCycle"}, {"CoherenceField"}
    });
    
    // Harmony Cycle (Batch 248)
    cycles.push_back({
        "RunHarmonyCycle", 248,
        "Sovereign Harmony: Where phase-locked patterns resonate into unified waveform",
        {"RunCoherenceCycle"}, {"HarmonyField"}
    });
    
    // Balance Cycle (Batch 249)
    cycles.push_back({
        "RunBalanceCycle", 249,
        "Sovereign Balance: Where harmonic resonance stabilizes into balanced state",
        {"RunHarmonyCycle"}, {"BalanceField"}
    });
    
    return cycles;
}

std::vector<DiscoveredTask> SovereignExecutionGraphBuilderEnhanced::GetBuiltInSwarmTasks() {
    std::vector<DiscoveredTask> tasks;
    
    // Batch 250: Order
    tasks.push_back({"ComputeOrderTopology", 250, "Order",
        "Compute emergent role topology", {}});
    tasks.push_back({"DiffuseCapabilities", 250, "Order",
        "Spread capabilities across agents", {"ComputeOrderTopology"}});
    tasks.push_back({"EmergeRoles", 250, "Order",
        "Self-define roles based on demand", {"DiffuseCapabilities"}});
    tasks.push_back({"AlignSubstrate", 250, "Order",
        "Align substrate flows with topology", {"EmergeRoles"}});
    
    // Batch 251: Resonance
    tasks.push_back({"AmplifyPatterns", 251, "Resonance",
        "Amplify stable recurring patterns", {"AlignSubstrate"}});
    tasks.push_back({"StabilizeResonance", 251, "Resonance",
        "Stabilize harmonic resonance", {"AmplifyPatterns"}});
    tasks.push_back({"CoupleHarmonics", 251, "Resonance",
        "Couple harmonic modes across cycles", {"StabilizeResonance"}});
    tasks.push_back({"ReinforceTopology", 251, "Resonance",
        "Reinforce resonant topology", {"CoupleHarmonics"}});
    
    // Batch 252: Amplification
    tasks.push_back({"ScaleAmplification", 252, "Amplification",
        "Scale amplification based on load/complexity", {"ReinforceTopology"}});
    tasks.push_back({"BoostValuePatterns", 252, "Amplification",
        "Boost high-value patterns", {"ScaleAmplification"}});
    tasks.push_back({"SuppressNoisePatterns", 252, "Amplification",
        "Suppress noisy patterns", {"BoostValuePatterns"}});
    tasks.push_back({"AdaptToSubstrateLoad", 252, "Amplification",
        "Adapt amplification to substrate health", {"SuppressNoisePatterns"}});
    
    // Batch 253: Integration
    tasks.push_back({"DetectCrossPatterns", 253, "Integration",
        "Detect patterns across subsystems", {"AdaptToSubstrateLoad"}});
    tasks.push_back({"BuildIntegrationLinks", 253, "Integration",
        "Build links between subsystems", {"DetectCrossPatterns"}});
    tasks.push_back({"StabilizeMultiFlows", 253, "Integration",
        "Stabilize multi-subsystem flows", {"BuildIntegrationLinks"}});
    tasks.push_back({"CoupleUnitySwarm", 253, "Integration",
        "Couple Unity Cycles to Swarm graph", {"StabilizeMultiFlows"}});
    
    // Batch 254: Convergence
    tasks.push_back({"AlignToSharedGoals", 254, "Convergence",
        "Align subsystems toward shared goals", {"CoupleUnitySwarm"}});
    tasks.push_back({"EstablishFeedbackLoops", 254, "Convergence",
        "Establish performance feedback loops", {"AlignToSharedGoals"}});
    tasks.push_back({"ConvergeToAttractors", 254, "Convergence",
        "Converge to optimal attractor states", {"EstablishFeedbackLoops"}});
    tasks.push_back({"OptimizeConvergenceRate", 254, "Convergence",
        "Optimize rate of convergence", {"ConvergeToAttractors"}});
    
    // Batch 255: Coherence
    tasks.push_back({"SynchronizePhases", 255, "Coherence",
        "Synchronize phases across subsystems", {"OptimizeConvergenceRate"}});
    tasks.push_back({"BalanceAmplitudes", 255, "Coherence",
        "Balance amplitudes across components", {"SynchronizePhases"}});
    tasks.push_back({"LockResonances", 255, "Coherence",
        "Lock resonances across components", {"BalanceAmplitudes"}});
    tasks.push_back({"ReinforceCoherence", 255, "Coherence",
        "Reinforce coherence standing waves", {"LockResonances"}});
    
    // Batch 256: Harmony
    tasks.push_back({"AchievePerfectUnity", 256, "Harmony",
        "Achieve perfect unity across all systems", {"ReinforceCoherence"}});
    tasks.push_back({"BalanceAbsolute", 256, "Harmony",
        "Balance all components absolutely", {"AchievePerfectUnity"}});
    tasks.push_back({"AchieveInfiniteResonance", 256, "Harmony",
        "Achieve infinite resonance state", {"BalanceAbsolute"}});
    tasks.push_back({"CompleteUnityCycle", 256, "Harmony",
        "Complete Unity Cycle 243-256", {"AchieveInfiniteResonance"}});
    
    return tasks;
}

// ============================================================================
// Reflection-based Discovery (Stubs for now)
// ============================================================================

std::vector<DiscoveredCycle> 
SovereignExecutionGraphBuilderEnhanced::DiscoverCyclesViaReflection() {
    // TODO: Implement actual reflection using typeid/RTTI
    // For now, return empty to use built-in definitions
    return {};
}

std::vector<DiscoveredTask> 
SovereignExecutionGraphBuilderEnhanced::DiscoverTasksViaReflection() {
    // TODO: Implement actual reflection
    return {};
}

// ============================================================================
// Dependency Inference
// ============================================================================

void SovereignExecutionGraphBuilderEnhanced::InferDependencies(DiscoveryResult& result) {
    // Map Swarm tasks to Unity Cycles
    // Batch 250 tasks feed into Unity Cycle (243)
    result.cycleToTaskMapping["RunUnityCycle"] = "AlignSubstrate";
    
    // Batch 251 tasks feed into Integration Cycle (244)
    result.cycleToTaskMapping["RunIntegrationCycle"] = "ReinforceTopology";
    
    // Batch 252 tasks feed into Synthesis Cycle (245)
    result.cycleToTaskMapping["RunSynthesisCycle"] = "AdaptToSubstrateLoad";
    
    // Batch 253 tasks feed into Convergence Cycle (246)
    result.cycleToTaskMapping["RunConvergenceCycle"] = "CoupleUnitySwarm";
    
    // Batch 254 tasks feed into Coherence Cycle (247)
    result.cycleToTaskMapping["RunCoherenceCycle"] = "OptimizeConvergenceRate";
    
    // Batch 255 tasks feed into Harmony Cycle (248)
    result.cycleToTaskMapping["RunHarmonyCycle"] = "ReinforceCoherence";
    
    // Batch 256 tasks feed into Balance Cycle (249)
    result.cycleToTaskMapping["RunBalanceCycle"] = "CompleteUnityCycle";
}

bool SovereignExecutionGraphBuilderEnhanced::WouldCreateCycle(
    const DiscoveryResult& result, const std::string& from, const std::string& to) const {
    // Simple cycle detection - check if 'to' eventually depends on 'from'
    // This is a simplified check; full implementation would build a dependency graph
    (void)result;
    (void)from;
    (void)to;
    return false;
}

// ============================================================================
// ExecutionPlanner Implementation
// ============================================================================

ExecutionPlanner::ExecutionPlan ExecutionPlanner::CreatePlan(const ExecutionGraph& graph) {
    ExecutionPlan plan;
    
    // Get topological sort
    plan.sequentialOrder = graph.TopologicalSort();
    
    // Group nodes into parallel stages
    // Stage 0: Entry points (no dependencies)
    // Stage N: Nodes whose dependencies are all in stages < N
    std::map<NodeId, int> nodeStage;
    std::vector<std::vector<NodeId>> stages;
    
    // Safety limit to prevent infinite loops
    const size_t maxStages = plan.sequentialOrder.size() + 1;
    
    for (NodeId nodeId : plan.sequentialOrder) {
        auto* node = graph.GetNode(nodeId);
        if (!node) continue;
        
        int maxDepStage = -1;
        for (NodeId depId : node->dependencies) {
            auto it = nodeStage.find(depId);
            if (it != nodeStage.end()) {
                maxDepStage = std::max(maxDepStage, it->second);
            }
        }
        
        int stage = maxDepStage + 1;
        nodeStage[nodeId] = stage;
        
        // Safety check
        if (stage >= static_cast<int>(maxStages)) {
            continue; // Skip nodes that would exceed safety limit
        }
        
        if (stage >= static_cast<int>(stages.size())) {
            stages.resize(stage + 1);
        }
        stages[stage].push_back(nodeId);
    }
    
    // Remove empty stages
    stages.erase(
        std::remove_if(stages.begin(), stages.end(),
            [](const std::vector<NodeId>& s) { return s.empty(); }),
        stages.end());
    
    plan.parallelStages = std::move(stages);
    plan.maxParallelism = 0;
    for (const auto& stage : plan.parallelStages) {
        plan.maxParallelism = std::max(plan.maxParallelism, static_cast<int>(stage.size()));
    }
    
    return plan;
}

ExecutionPlanner::ExecutionPlan ExecutionPlanner::CreateOptimizedPlan(
    const ExecutionGraph& graph, int maxParallelism) {
    auto plan = CreatePlan(graph);
    
    // TODO: Optimize based on maxParallelism constraint
    // Could involve reordering within stages or merging stages
    (void)maxParallelism;
    
    return plan;
}

std::vector<NodeId> ExecutionPlanner::GetCriticalPath(
    const ExecutionGraph& graph, NodeId from, NodeId to) {
    // TODO: Implement critical path analysis
    // For now, return the path from topological sort
    auto sorted = graph.TopologicalSort();
    std::vector<NodeId> path;
    
    bool inPath = false;
    for (NodeId id : sorted) {
        if (id == from) inPath = true;
        if (inPath) path.push_back(id);
        if (id == to) break;
    }
    
    return path;
}

int ExecutionPlanner::EstimateExecutionTime(const ExecutionGraph& graph, int avgNodeTimeMs) {
    auto plan = CreatePlan(graph);
    return static_cast<int>(plan.parallelStages.size()) * avgNodeTimeMs;
}

std::vector<NodeId> ExecutionPlanner::GetReadyNodes(
    const ExecutionGraph& graph, const ExecutionPlan& plan, int stage) {
    if (stage < 0 || stage >= static_cast<int>(plan.parallelStages.size())) {
        return {};
    }
    return plan.parallelStages[stage];
}

bool ExecutionPlanner::IsStageComplete(
    const ExecutionGraph& graph, const ExecutionPlan& plan, int stage) {
    if (stage < 0 || stage >= static_cast<int>(plan.parallelStages.size())) {
        return false;
    }
    
    for (NodeId nodeId : plan.parallelStages[stage]) {
        auto* node = graph.GetNode(nodeId);
        if (node && node->state.load() != ExecutionState::Completed) {
            return false;
        }
    }
    
    return true;
}

// ============================================================================
// GraphExecutor Implementation
// ============================================================================

void GraphExecutor::SetNodeExecutor(NodeType type, NodeExecutor executor) {
    nodeExecutors_[type] = executor;
}

void GraphExecutor::SetProgressCallback(ProgressCallback callback) {
    progressCallback_ = callback;
}

void GraphExecutor::SetCompletionCallback(CompletionCallback callback) {
    completionCallback_ = callback;
}

bool GraphExecutor::ExecuteSequential(ExecutionGraph& graph) {
    isRunning_ = true;
    shouldCancel_ = false;
    
    auto sorted = graph.TopologicalSort();
    
    for (NodeId nodeId : sorted) {
        if (shouldCancel_) {
            isRunning_ = false;
            if (completionCallback_) completionCallback_(false);
            return false;
        }
        
        while (isPaused_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (shouldCancel_) {
                isRunning_ = false;
                if (completionCallback_) completionCallback_(false);
                return false;
            }
        }
        
        auto* node = graph.GetNode(nodeId);
        if (!node) continue;
        
        if (!ExecuteNode(*node)) {
            isRunning_ = false;
            if (completionCallback_) completionCallback_(false);
            return false;
        }
    }
    
    isRunning_ = false;
    if (completionCallback_) completionCallback_(true);
    return true;
}

bool GraphExecutor::ExecuteParallel(ExecutionGraph& graph, int maxConcurrency) {
    // TODO: Implement parallel execution with thread pool
    (void)maxConcurrency;
    return ExecuteSequential(graph);
}

bool GraphExecutor::ExecutePlanned(
    ExecutionGraph& graph, const ExecutionPlanner::ExecutionPlan& plan) {
    isRunning_ = true;
    shouldCancel_ = false;
    
    for (size_t stage = 0; stage < plan.parallelStages.size(); ++stage) {
        if (shouldCancel_) {
            isRunning_ = false;
            if (completionCallback_) completionCallback_(false);
            return false;
        }
        
        // Execute all nodes in this stage
        for (NodeId nodeId : plan.parallelStages[stage]) {
            auto* node = graph.GetNode(nodeId);
            if (!node) continue;
            
            if (!ExecuteNode(*node)) {
                isRunning_ = false;
                if (completionCallback_) completionCallback_(false);
                return false;
            }
        }
    }
    
    isRunning_ = false;
    if (completionCallback_) completionCallback_(true);
    return true;
}

void GraphExecutor::Pause() {
    isPaused_ = true;
}

void GraphExecutor::Resume() {
    isPaused_ = false;
}

void GraphExecutor::Cancel() {
    shouldCancel_ = true;
}

bool GraphExecutor::ExecuteNode(ExecutionNode& node) {
    UpdateNodeState(node, ExecutionState::Running);
    
    auto it = nodeExecutors_.find(node.type);
    if (it != nodeExecutors_.end()) {
        bool success = it->second(node);
        UpdateNodeState(node, success ? ExecutionState::Completed : ExecutionState::Failed);
        return success;
    }
    
    // Default: mark as completed if no executor registered
    UpdateNodeState(node, ExecutionState::Completed);
    return true;
}

void GraphExecutor::UpdateNodeState(ExecutionNode& node, ExecutionState newState) {
    node.state.store(newState);
    
    if (progressCallback_) {
        double progress = (newState == ExecutionState::Completed) ? 1.0 : 
                         (newState == ExecutionState::Running) ? 0.5 : 0.0;
        progressCallback_(node.id, progress);
    }
}

} // namespace SEG
} // namespace Sovereign
