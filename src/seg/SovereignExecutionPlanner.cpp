/**
 * SovereignExecutionPlanner.cpp
 * 
 * Phase B.4 Batch 3/5: Execution Planner Implementation
 */

#include "SovereignExecutionPlanner.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <iostream>

namespace Sovereign {
namespace SEG {

// ============================================================================
// SovereignExecutionPlanner Implementation
// ============================================================================

SovereignExecutionPlanner::ExecutionPlan SovereignExecutionPlanner::CreatePlan(const ExecutionGraph& graph) {
    ExecutionPlan plan;
    
    // Get topological sort
    auto sorted = graph.TopologicalSort();
    plan.criticalPath = sorted; // Initially, critical path is the full sort
    
    // Group nodes into stages based on dependencies
    std::map<NodeId, int> nodeStage;
    std::vector<ExecutionStage> stages;
    
    for (NodeId nodeId : sorted) {
        auto* node = graph.GetNode(nodeId);
        if (!node) continue;
        
        // Calculate stage based on dependencies
        int maxDepStage = -1;
        for (NodeId depId : node->dependencies) {
            auto it = nodeStage.find(depId);
            if (it != nodeStage.end()) {
                maxDepStage = std::max(maxDepStage, it->second);
            }
        }
        
        int stage = maxDepStage + 1;
        nodeStage[nodeId] = stage;
        
        if (stage >= static_cast<int>(stages.size())) {
            stages.resize(stage + 1);
        }
        stages[stage].nodes.push_back(nodeId);
    }
    
    // Assign stage numbers
    for (size_t i = 0; i < stages.size(); ++i) {
        stages[i].stageNumber = static_cast<int>(i);
    }
    
    // Remove empty stages
    stages.erase(
        std::remove_if(stages.begin(), stages.end(),
            [](const ExecutionStage& s) { return s.nodes.empty(); }),
        stages.end());
    
    plan.stages = std::move(stages);
    plan.maxParallelism = 0;
    for (const auto& stage : plan.stages) {
        plan.maxParallelism = std::max(plan.maxParallelism, static_cast<int>(stage.nodes.size()));
    }
    plan.criticalPathLength = static_cast<int>(plan.criticalPath.size());
    
    return plan;
}

SovereignExecutionPlanner::ExecutionPlan SovereignExecutionPlanner::CreateOptimizedPlan(
    const ExecutionGraph& graph, const ExecutionConfig& config) {
    
    auto plan = CreatePlan(graph);
    
    // Limit parallelism based on config
    if (plan.maxParallelism > config.maxConcurrency) {
        // TODO: Rebalance stages to respect concurrency limit
        // For now, just note the constraint
        plan.maxParallelism = config.maxConcurrency;
    }
    
    // Assign resources
    AssignResources(plan, graph);
    
    return plan;
}

std::vector<NodeId> SovereignExecutionPlanner::CalculateCriticalPath(const ExecutionGraph& graph) {
    // For now, return the topological sort as the critical path
    // A more sophisticated implementation would calculate the longest path
    return graph.TopologicalSort();
}

std::vector<NodeId> SovereignExecutionPlanner::CalculateCriticalPath(
    const ExecutionGraph& graph, NodeId start, NodeId end) {
    
    auto sorted = graph.TopologicalSort();
    std::vector<NodeId> path;
    
    bool inPath = false;
    for (NodeId id : sorted) {
        if (id == start) inPath = true;
        if (inPath) path.push_back(id);
        if (id == end) break;
    }
    
    return path;
}

int SovereignExecutionPlanner::CalculatePathLength(const ExecutionGraph& graph, const std::vector<NodeId>& path) {
    (void)graph;
    return static_cast<int>(path.size());
}

void SovereignExecutionPlanner::AssignResources(ExecutionPlan& plan, const ExecutionGraph& graph) {
    for (const auto& stage : plan.stages) {
        for (NodeId nodeId : stage.nodes) {
            auto* node = graph.GetNode(nodeId);
            if (!node) continue;
            
            // Assign default resources based on node type
            ResourceRequirements res;
            switch (node->type) {
                case NodeType::EngineCycle:
                    res.cpuCores = 4;
                    res.memoryBytes = 1024 * 1024 * 1024; // 1GB
                    break;
                case NodeType::SwarmTask:
                    res.cpuCores = 2;
                    res.memoryBytes = 512 * 1024 * 1024; // 512MB
                    break;
                case NodeType::Kernel:
                    res.cpuCores = 8;
                    res.memoryBytes = 2ULL * 1024 * 1024 * 1024; // 2GB
                    res.requiresGPU = true;
                    res.gpuMemoryMB = 4096;
                    break;
                default:
                    res.cpuCores = 1;
                    res.memoryBytes = 128 * 1024 * 1024; // 128MB
                    break;
            }
            plan.resourceMap[nodeId] = res;
        }
    }
}

bool SovereignExecutionPlanner::ValidateResourceConstraints(const ExecutionPlan& plan, const ExecutionConfig& config) {
    // Check if any stage exceeds resource limits
    for (const auto& stage : plan.stages) {
        int totalCores = 0;
        size_t totalMemory = 0;
        
        for (NodeId nodeId : stage.nodes) {
            auto it = plan.resourceMap.find(nodeId);
            if (it != plan.resourceMap.end()) {
                totalCores += it->second.cpuCores;
                totalMemory += it->second.memoryBytes;
            }
        }
        
        if (totalCores > config.maxConcurrency) {
            return false;
        }
    }
    
    return true;
}

ExecutionMetrics SovereignExecutionPlanner::AnalyzePlan(const ExecutionPlan& plan) {
    ExecutionMetrics metrics;
    metrics.stagesExecuted = static_cast<int>(plan.stages.size());
    
    for (const auto& stage : plan.stages) {
        metrics.nodesExecuted += static_cast<int>(stage.nodes.size());
    }
    
    metrics.maxParallelism = plan.maxParallelism;
    metrics.parallelismEfficiency = CalculateParallelismEfficiency(plan);
    
    return metrics;
}

int SovereignExecutionPlanner::EstimateExecutionTime(const ExecutionPlan& plan, int avgNodeTimeMs) {
    int totalTime = 0;
    for (const auto& stage : plan.stages) {
        // Assume perfect parallelism within stage
        totalTime += avgNodeTimeMs;
    }
    return totalTime;
}

double SovereignExecutionPlanner::CalculateParallelismEfficiency(const ExecutionPlan& plan) {
    if (plan.stages.empty()) return 0.0;
    
    int totalNodes = 0;
    for (const auto& stage : plan.stages) {
        totalNodes += static_cast<int>(stage.nodes.size());
    }
    
    // Efficiency = total nodes / (stages * max parallelism)
    double theoreticalMax = static_cast<double>(plan.stages.size() * plan.maxParallelism);
    return theoreticalMax > 0 ? static_cast<double>(totalNodes) / theoreticalMax : 0.0;
}

// ============================================================================
// SovereignParallelExecutor Implementation
// ============================================================================

SovereignParallelExecutor::SovereignParallelExecutor() 
    : config_{} {
}

SovereignParallelExecutor::~SovereignParallelExecutor() {
    ShutdownWorkers();
}

void SovereignParallelExecutor::SetNodeExecutor(NodeType type, NodeExecutor executor) {
    nodeExecutors_[type] = executor;
}

bool SovereignParallelExecutor::Execute(ExecutionGraph& graph, const SovereignExecutionPlanner::ExecutionPlan& plan) {
    isRunning_ = true;
    shouldCancel_ = false;
    completedNodes_ = 0;
    failedNodes_ = 0;
    currentStage_ = 0;
    
    InitializeWorkers(config_.maxConcurrency);
    
    auto startTime = std::chrono::steady_clock::now();
    bool overallSuccess = true;
    
    for (size_t i = 0; i < plan.stages.size(); ++i) {
        if (shouldCancel_) {
            overallSuccess = false;
            break;
        }
        
        while (isPaused_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (shouldCancel_) {
                overallSuccess = false;
                break;
            }
        }
        
        currentStage_ = static_cast<int>(i);
        auto& stage = const_cast<ExecutionStage&>(plan.stages[i]);
        
        if (stageCallback_) {
            stageCallback_(static_cast<int>(i), stage);
        }
        
        auto stageStart = std::chrono::steady_clock::now();
        bool stageSuccess = ExecuteStage(graph, stage);
        stage.actualDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - stageStart);
        
        if (!stageSuccess && !config_.continueOnFailure) {
            overallSuccess = false;
            break;
        }
        
        stage.isComplete = true;
    }
    
    auto endTime = std::chrono::steady_clock::now();
    metrics_.totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    ShutdownWorkers();
    isRunning_ = false;
    
    if (completionCallback_) {
        completionCallback_(overallSuccess, metrics_);
    }
    
    return overallSuccess;
}

bool SovereignParallelExecutor::ExecuteSequential(ExecutionGraph& graph) {
    SovereignExecutionPlanner planner;
    auto plan = planner.CreatePlan(graph);
    return Execute(graph, plan);
}

bool SovereignParallelExecutor::ExecuteParallel(ExecutionGraph& graph, int maxConcurrency) {
    config_.maxConcurrency = maxConcurrency;
    return ExecuteSequential(graph);
}

void SovereignParallelExecutor::Pause() {
    isPaused_ = true;
}

void SovereignParallelExecutor::Resume() {
    isPaused_ = false;
}

void SovereignParallelExecutor::Cancel() {
    shouldCancel_ = true;
}

bool SovereignParallelExecutor::RetryNode(ExecutionGraph& graph, NodeId nodeId) {
    auto* node = graph.GetNode(nodeId);
    if (!node) return false;
    
    node->state.store(ExecutionState::Pending);
    node->progress.store(0.0);
    
    auto result = ExecuteNode(*node);
    UpdateNodeState(graph, nodeId, result.success ? ExecutionState::Completed : ExecutionState::Failed);
    
    return result.success;
}

bool SovereignParallelExecutor::SkipNode(ExecutionGraph& graph, NodeId nodeId) {
    UpdateNodeState(graph, nodeId, ExecutionState::Skipped);
    return true;
}

void SovereignParallelExecutor::MarkNodeFailed(ExecutionGraph& graph, NodeId nodeId, const std::string& error) {
    auto* node = graph.GetNode(nodeId);
    if (node) {
        node->metadata["error"] = error;
    }
    UpdateNodeState(graph, nodeId, ExecutionState::Failed);
}

void SovereignParallelExecutor::InitializeWorkers(int numWorkers) {
    stopWorkers_ = false;
    for (int i = 0; i < numWorkers; ++i) {
        workerThreads_.emplace_back([this]() {
            while (!stopWorkers_) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(queueMutex_);
                    queueCondition_.wait(lock, [this]() { 
                        return !taskQueue_.empty() || stopWorkers_; 
                    });
                    
                    if (stopWorkers_ && taskQueue_.empty()) {
                        return;
                    }
                    
                    if (!taskQueue_.empty()) {
                        task = std::move(taskQueue_.front());
                        taskQueue_.pop();
                    }
                }
                
                if (task) {
                    task();
                }
            }
        });
    }
}

void SovereignParallelExecutor::ShutdownWorkers() {
    {
        std::unique_lock<std::mutex> lock(queueMutex_);
        stopWorkers_ = true;
    }
    queueCondition_.notify_all();
    
    for (auto& thread : workerThreads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    workerThreads_.clear();
}

NodeExecutionResult SovereignParallelExecutor::ExecuteNode(ExecutionNode& node) {
    NodeExecutionResult result;
    result.nodeId = node.id;
    
    auto startTime = std::chrono::steady_clock::now();
    
    auto it = nodeExecutors_.find(node.type);
    if (it != nodeExecutors_.end()) {
        result = it->second(node);
    } else {
        // Default: mark as success
        result.success = true;
    }
    
    result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    
    return result;
}

bool SovereignParallelExecutor::ExecuteStage(ExecutionGraph& graph, ExecutionStage& stage) {
    // Simple sequential execution for now (parallel execution requires more complex synchronization)
    bool stageSuccess = true;
    
    for (NodeId nodeId : stage.nodes) {
        if (shouldCancel_) {
            return false;
        }
        
        while (isPaused_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (shouldCancel_) {
                return false;
            }
        }
        
        auto* node = graph.GetNode(nodeId);
        if (!node) continue;
        
        UpdateNodeState(graph, nodeId, ExecutionState::Running);
        
        auto result = ExecuteNode(*node);
        UpdateMetrics(result);
        
        if (result.success) {
            UpdateNodeState(graph, nodeId, ExecutionState::Completed);
        } else {
            UpdateNodeState(graph, nodeId, ExecutionState::Failed);
            stage.hasFailures = true;
            if (!config_.continueOnFailure) {
                stageSuccess = false;
                break;
            }
        }
        
        if (nodeCallback_) {
            nodeCallback_(nodeId, result);
        }
    }
    
    return stageSuccess;
}

void SovereignParallelExecutor::UpdateMetrics(const NodeExecutionResult& result) {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    
    if (result.success) {
        completedNodes_++;
        metrics_.nodesExecuted++;
    } else {
        failedNodes_++;
        metrics_.nodesFailed++;
    }
}

void SovereignParallelExecutor::UpdateNodeState(ExecutionGraph& graph, NodeId nodeId, ExecutionState state) {
    auto* node = graph.GetNode(nodeId);
    if (node) {
        node->state.store(state);
    }
}

// ============================================================================
// ExecutionMonitor Implementation
// ============================================================================

void ExecutionMonitor::AttachToExecutor(SovereignParallelExecutor* executor) {
    executor_ = executor;
}

void ExecutionMonitor::AttachToGraph(ExecutionGraph* graph) {
    graph_ = graph;
}

ExecutionMonitor::MonitorSnapshot ExecutionMonitor::GetSnapshot() const {
    MonitorSnapshot snapshot;
    
    if (executor_) {
        snapshot.currentStage = executor_->GetCurrentStage();
        snapshot.completedNodes = executor_->GetCompletedNodes();
        snapshot.failedNodes = executor_->GetFailedNodes();
    }
    
    if (graph_) {
        auto stats = graph_->GetStatistics();
        snapshot.totalNodes = static_cast<int>(stats.nodeCount);
    }
    
    if (snapshot.totalNodes > 0) {
        snapshot.progressPercent = (static_cast<double>(snapshot.completedNodes) / snapshot.totalNodes) * 100.0;
    }
    
    return snapshot;
}

std::string ExecutionMonitor::GetSnapshotJson() const {
    auto snapshot = GetSnapshot();
    std::ostringstream json;
    
    json << "{";
    json << "\"currentStage\":" << snapshot.currentStage << ",";
    json << "\"totalStages\":" << snapshot.totalStages << ",";
    json << "\"completedNodes\":" << snapshot.completedNodes << ",";
    json << "\"totalNodes\":" << snapshot.totalNodes << ",";
    json << "\"failedNodes\":" << snapshot.failedNodes << ",";
    json << "\"progressPercent\":" << std::fixed << std::setprecision(2) << snapshot.progressPercent;
    json << "}";
    
    return json.str();
}

void ExecutionMonitor::StartMonitoring() {
    if (isMonitoring_) return;
    
    isMonitoring_ = true;
    monitorThread_ = std::thread([this]() {
        MonitorLoop();
    });
}

void ExecutionMonitor::StopMonitoring() {
    isMonitoring_ = false;
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
}

void ExecutionMonitor::MonitorLoop() {
    while (isMonitoring_) {
        if (snapshotCallback_) {
            snapshotCallback_(GetSnapshot());
        }
        
        std::this_thread::sleep_for(snapshotInterval_);
    }
}

// ============================================================================
// ExecutionCheckpointManager Implementation
// ============================================================================

std::string ExecutionCheckpointManager::CreateCheckpoint(
    const ExecutionGraph& graph, const ExecutionMetrics& metrics) {
    
    Checkpoint checkpoint;
    checkpoint.id = "checkpoint_" + std::to_string(
        std::chrono::system_clock::now().time_since_epoch().count());
    checkpoint.timestamp = std::chrono::system_clock::now();
    checkpoint.metrics = metrics;
    
    // Save node states
    for (const auto& [id, node] : graph.GetNodes()) {
        checkpoint.nodeStates[id] = node->state.load();
        if (node->state.load() == ExecutionState::Completed) {
            checkpoint.completedNodes.push_back(id);
        } else if (node->state.load() == ExecutionState::Failed) {
            checkpoint.failedNodes.push_back(id);
        }
    }
    
    // Serialize and save
    std::string data = SerializeCheckpoint(checkpoint);
    std::string filepath = checkpointDir_ + "/" + checkpoint.id + ".chk";
    
    std::ofstream file(filepath, std::ios::binary);
    if (file) {
        file.write(data.data(), data.size());
    }
    
    return checkpoint.id;
}

bool ExecutionCheckpointManager::RestoreFromCheckpoint(
    ExecutionGraph& graph, ExecutionMetrics& metrics, const std::string& checkpointId) {
    
    std::string filepath = checkpointDir_ + "/" + checkpointId + ".chk";
    std::ifstream file(filepath, std::ios::binary);
    
    if (!file) {
        return false;
    }
    
    std::string data((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    
    Checkpoint checkpoint = DeserializeCheckpoint(data);
    
    // Restore node states
    for (const auto& [nodeId, state] : checkpoint.nodeStates) {
        auto* node = graph.GetNode(nodeId);
        if (node) {
            node->state.store(state);
        }
    }
    
    metrics = checkpoint.metrics;
    return true;
}

bool ExecutionCheckpointManager::DeleteCheckpoint(const std::string& checkpointId) {
    std::string filepath = checkpointDir_ + "/" + checkpointId + ".chk";
    return std::remove(filepath.c_str()) == 0;
}

std::vector<std::string> ExecutionCheckpointManager::ListCheckpoints() const {
    std::vector<std::string> checkpoints;
    // TODO: Implement directory listing
    return checkpoints;
}

std::string ExecutionCheckpointManager::SerializeCheckpoint(const Checkpoint& checkpoint) const {
    std::ostringstream oss;
    
    // Simple serialization - in production, use proper serialization library
    oss << "CHECKPOINT_V1\n";
    oss << checkpoint.id << "\n";
    oss << std::chrono::system_clock::to_time_t(checkpoint.timestamp) << "\n";
    
    oss << checkpoint.completedNodes.size() << "\n";
    for (NodeId id : checkpoint.completedNodes) {
        oss << id << " ";
    }
    oss << "\n";
    
    oss << checkpoint.failedNodes.size() << "\n";
    for (NodeId id : checkpoint.failedNodes) {
        oss << id << " ";
    }
    oss << "\n";
    
    return oss.str();
}

ExecutionCheckpointManager::Checkpoint ExecutionCheckpointManager::DeserializeCheckpoint(
    const std::string& data) const {
    
    Checkpoint checkpoint;
    std::istringstream iss(data);
    
    std::string header;
    std::getline(iss, header); // CHECKPOINT_V1
    
    std::getline(iss, checkpoint.id);
    
    std::time_t timestamp;
    iss >> timestamp;
    checkpoint.timestamp = std::chrono::system_clock::from_time_t(timestamp);
    
    // TODO: Complete deserialization
    
    return checkpoint;
}

} // namespace SEG
} // namespace Sovereign
