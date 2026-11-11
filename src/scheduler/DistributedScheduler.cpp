// DistributedScheduler.cpp
// Phase C.2 Batch 5/5 — Distributed Scheduling Coordination Implementation

#include "DistributedScheduler.hpp"
#include <algorithm>
#include <numeric>
#include <random>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace Scheduler {

// ============================================================================
// NodeInfo Implementation
// ============================================================================

bool NodeInfo::IsHealthy() const {
    return state == NodeState::ACTIVE && 
           (std::chrono::steady_clock::now() - last_heartbeat) < std::chrono::seconds(5);
}

bool NodeInfo::IsAvailable() const {
    return IsHealthy() && current_load < 0.9 && current_workers < max_workers;
}

double NodeInfo::GetUtilization() const {
    if (max_workers == 0) return 0.0;
    return static_cast<double>(current_workers) / max_workers;
}

double NodeInfo::GetScore() const {
    // Composite score for load balancing
    double score = 0.0;
    
    // Prefer nodes with lower load
    score += (1.0 - current_load) * 0.4;
    
    // Prefer nodes with higher capacity
    score += (cpu_capacity / 100.0) * 0.2;
    score += (memory_capacity / 100.0) * 0.2;
    
    // Prefer nodes with better performance
    score += success_rate * 0.1;
    score += (1.0 / (1.0 + average_latency / 100.0)) * 0.1;
    
    return score;
}

// ============================================================================
// NodeRegistry Implementation
// ============================================================================

NodeRegistry::NodeRegistry(const DistributionConfig& config)
    : config_(config) {}

void NodeRegistry::RegisterNode(const NodeInfo& node) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_[node.node_id] = node;
}

void NodeRegistry::UnregisterNode(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_.erase(node_id);
}

void NodeRegistry::UpdateNode(const NodeInfo& node) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_[node.node_id] = node;
}

NodeInfo NodeRegistry::GetNode(const std::string& node_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = nodes_.find(node_id);
    if (it != nodes_.end()) {
        return it->second;
    }
    
    return NodeInfo{};
}

std::vector<NodeInfo> NodeRegistry::GetAllNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<NodeInfo> result;
    for (const auto& [id, node] : nodes_) {
        result.push_back(node);
    }
    
    return result;
}

std::vector<NodeInfo> NodeRegistry::GetHealthyNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<NodeInfo> result;
    for (const auto& [id, node] : nodes_) {
        if (node.IsHealthy()) {
            result.push_back(node);
        }
    }
    
    return result;
}

std::vector<NodeInfo> NodeRegistry::GetNodesByType(NodeType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<NodeInfo> result;
    for (const auto& [id, node] : nodes_) {
        if (node.type == type) {
            result.push_back(node);
        }
    }
    
    return result;
}

std::vector<NodeInfo> NodeRegistry::GetAvailableWorkers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<NodeInfo> result;
    for (const auto& [id, node] : nodes_) {
        if (node.IsAvailable() && (node.type == NodeType::WORKER || node.type == NodeType::HYBRID)) {
            result.push_back(node);
        }
    }
    
    return result;
}

NodeInfo NodeRegistry::SelectLeastLoaded() const {
    auto nodes = GetAvailableWorkers();
    
    if (nodes.empty()) {
        return NodeInfo{};
    }
    
    // Find node with lowest load
    auto it = std::min_element(nodes.begin(), nodes.end(),
        [](const NodeInfo& a, const NodeInfo& b) {
            return a.current_load < b.current_load;
        });
    
    return *it;
}

NodeInfo NodeRegistry::SelectByCapacity() const {
    auto nodes = GetAvailableWorkers();
    
    if (nodes.empty()) {
        return NodeInfo{};
    }
    
    // Find node with highest capacity score
    auto it = std::max_element(nodes.begin(), nodes.end(),
        [](const NodeInfo& a, const NodeInfo& b) {
            return a.GetScore() < b.GetScore();
        });
    
    return *it;
}

NodeInfo NodeRegistry::SelectByLatency() const {
    auto nodes = GetAvailableWorkers();
    
    if (nodes.empty()) {
        return NodeInfo{};
    }
    
    // Find node with lowest latency
    auto it = std::min_element(nodes.begin(), nodes.end(),
        [](const NodeInfo& a, const NodeInfo& b) {
            return a.average_latency < b.average_latency;
        });
    
    return *it;
}

std::vector<NodeInfo> NodeRegistry::SelectCandidates(uint32_t count) const {
    auto nodes = GetAvailableWorkers();
    
    // Sort by score
    std::sort(nodes.begin(), nodes.end(),
        [](const NodeInfo& a, const NodeInfo& b) {
            return a.GetScore() > b.GetScore();
        });
    
    // Return top N
    if (nodes.size() > count) {
        nodes.resize(count);
    }
    
    return nodes;
}

void NodeRegistry::RecordHeartbeat(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = nodes_.find(node_id);
    if (it != nodes_.end()) {
        it->second.last_heartbeat = std::chrono::steady_clock::now();
        it->second.state = NodeState::ACTIVE;
    }
}

void NodeRegistry::UpdateNodeMetrics(const std::string& node_id,
                                     double load, double latency, double throughput) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = nodes_.find(node_id);
    if (it != nodes_.end()) {
        it->second.current_load = load;
        it->second.average_latency = latency;
        it->second.throughput = throughput;
    }
}

std::vector<std::string> NodeRegistry::GetFailedNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> failed;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& [id, node] : nodes_) {
        if ((now - node.last_heartbeat) > config_.heartbeat_timeout) {
            failed.push_back(id);
        }
    }
    
    return failed;
}

uint32_t NodeRegistry::GetNodeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<uint32_t>(nodes_.size());
}

uint32_t NodeRegistry::GetHealthyNodeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint32_t count = 0;
    for (const auto& [id, node] : nodes_) {
        if (node.IsHealthy()) {
            ++count;
        }
    }
    
    return count;
}

double NodeRegistry::GetClusterLoad() const {
    auto nodes = GetAllNodes();
    
    if (nodes.empty()) return 0.0;
    
    double total_load = 0.0;
    for (const auto& node : nodes) {
        total_load += node.current_load;
    }
    
    return total_load / nodes.size();
}

double NodeRegistry::GetClusterThroughput() const {
    auto nodes = GetAllNodes();
    
    double total_throughput = 0.0;
    for (const auto& node : nodes) {
        total_throughput += node.throughput;
    }
    
    return total_throughput;
}

void NodeRegistry::CleanupFailedNodes() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    
    for (auto it = nodes_.begin(); it != nodes_.end();) {
        if ((now - it->second.last_heartbeat) > config_.heartbeat_timeout * 2) {
            it = nodes_.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// TaskDistributor Implementation
// ============================================================================

TaskDistributor::TaskDistributor(NodeRegistry* registry, const DistributionConfig& config)
    : registry_(registry)
    , config_(config) {}

std::string TaskDistributor::DistributeTask(const DistributedTask& task) {
    switch (config_.policy) {
        case DistributionPolicy::ROUND_ROBIN:
            return RoundRobin(task);
        case DistributionPolicy::LEAST_LOADED:
            return LeastLoaded(task);
        case DistributionPolicy::LOCALITY_AWARE:
            return LocalityAware(task);
        case DistributionPolicy::CAPACITY_BASED:
            return CapacityBased(task);
        case DistributionPolicy::LATENCY_OPTIMIZED:
            return LatencyOptimized(task);
        case DistributionPolicy::COST_OPTIMIZED:
            return CostOptimized(task);
        case DistributionPolicy::ADAPTIVE:
            return Adaptive(task);
        default:
            return LeastLoaded(task);
    }
}

std::vector<std::string> TaskDistributor::DistributeTaskReplicated(const DistributedTask& task,
                                                                   uint32_t replication_factor) {
    auto candidates = registry_->SelectCandidates(replication_factor * 2);
    std::vector<std::string> selected;
    
    // Select top nodes by score
    for (const auto& node : candidates) {
        if (selected.size() < replication_factor) {
            selected.push_back(node.node_id);
        }
    }
    
    return selected;
}

std::string TaskDistributor::RoundRobin(const DistributedTask& task) {
    (void)task;
    
    auto nodes = registry_->GetAvailableWorkers();
    if (nodes.empty()) {
        return "";
    }
    
    uint64_t index = round_robin_counter_.fetch_add(1) % nodes.size();
    return nodes[index].node_id;
}

std::string TaskDistributor::LeastLoaded(const DistributedTask& task) {
    (void)task;
    
    auto node = registry_->SelectLeastLoaded();
    return node.node_id;
}

std::string TaskDistributor::LocalityAware(const DistributedTask& task) {
    // Check if source node is available
    if (!task.source_node.empty()) {
        auto node = registry_->GetNode(task.source_node);
        if (node.IsAvailable()) {
            return task.source_node;
        }
    }
    
    // Fall back to least loaded
    return LeastLoaded(task);
}

std::string TaskDistributor::CapacityBased(const DistributedTask& task) {
    (void)task;
    
    auto node = registry_->SelectByCapacity();
    return node.node_id;
}

std::string TaskDistributor::LatencyOptimized(const DistributedTask& task) {
    (void)task;
    
    auto node = registry_->SelectByLatency();
    return node.node_id;
}

std::string TaskDistributor::CostOptimized(const DistributedTask& task) {
    // For now, same as capacity-based
    return CapacityBased(task);
}

std::string TaskDistributor::Adaptive(const DistributedTask& task) {
    // Adaptive policy based on current cluster state
    auto cluster_load = registry_->GetClusterLoad();
    
    if (cluster_load > config_.overload_threshold) {
        // High load - use least loaded to balance
        return LeastLoaded(task);
    } else if (cluster_load < config_.underload_threshold) {
        // Low load - optimize for latency
        return LatencyOptimized(task);
    } else {
        // Normal load - use capacity-based
        return CapacityBased(task);
    }
}

bool TaskDistributor::ShouldMigrate(const DistributedTask& task) const {
    if (task.target_node.empty()) return false;
    
    auto node = registry_->GetNode(task.target_node);
    return node.current_load > config_.migration_threshold;
}

std::string TaskDistributor::SelectMigrationTarget(const DistributedTask& task) {
    // Find least loaded node excluding current
    auto nodes = registry_->GetAvailableWorkers();
    
    std::string best_node;
    double best_load = std::numeric_limits<double>::infinity();
    
    for (const auto& node : nodes) {
        if (node.node_id != task.target_node && node.current_load < best_load) {
            best_load = node.current_load;
            best_node = node.node_id;
        }
    }
    
    return best_node;
}

void TaskDistributor::MigrateTask(DistributedTask& task, const std::string& new_node) {
    task.previous_node = task.target_node;
    task.target_node = new_node;
    task.migration_count++;
    task.migration_time = std::chrono::steady_clock::now();
    task.dist_state = DistributedTask::DistributionState::MIGRATED;
}

std::map<std::string, std::vector<DistributedTask>> TaskDistributor::DistributeBatch(
    const std::vector<DistributedTask>& tasks) {
    
    std::map<std::string, std::vector<DistributedTask>> distribution;
    
    for (const auto& task : tasks) {
        std::string node = DistributeTask(task);
        if (!node.empty()) {
            distribution[node].push_back(task);
        }
    }
    
    return distribution;
}

double TaskDistributor::CalculateNodeScore(const NodeInfo& node, const DistributedTask& task) const {
    (void)task;
    return node.GetScore();
}

// ============================================================================
// LoadBalancer Implementation
// ============================================================================

LoadBalancer::LoadBalancer(NodeRegistry* registry, const DistributionConfig& config)
    : registry_(registry)
    , config_(config)
    , stats_{} {}

void LoadBalancer::Start() {
    running_ = true;
    balancer_thread_ = std::thread(&LoadBalancer::BalancerLoop, this);
}

void LoadBalancer::Stop() {
    running_ = false;
    
    if (balancer_thread_.joinable()) {
        balancer_thread_.join();
    }
}

void LoadBalancer::Rebalance() {
    auto start = std::chrono::steady_clock::now();
    
    // Calculate load variance before
    double variance_before = CalculateLoadVariance();
    
    // Identify overloaded nodes
    auto nodes = registry_->GetAllNodes();
    
    for (const auto& node : nodes) {
        if (node.current_load > config_.overload_threshold) {
            RebalanceNode(node.node_id);
        }
    }
    
    // Calculate load variance after
    double variance_after = CalculateLoadVariance();
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.load_variance_before = variance_before;
        stats_.load_variance_after = variance_after;
        stats_.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        stats_.migrations_triggered++;
    }
}

void LoadBalancer::RebalanceNode(const std::string& node_id) {
    auto tasks = IdentifyTasksToMigrate(node_id);
    
    for (auto& task : tasks) {
        // Find target node
        auto nodes = registry_->GetAvailableWorkers();
        
        for (const auto& target : nodes) {
            if (target.node_id != node_id && target.current_load < config_.underload_threshold) {
                // Migrate task
                task.target_node = target.node_id;
                task.dist_state = DistributedTask::DistributionState::MIGRATED;
                
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.migrations_completed++;
                }
                
                break;
            }
        }
    }
}

std::vector<DistributedTask> LoadBalancer::IdentifyTasksToMigrate(const std::string& overloaded_node) {
    // Simplified - would query actual task state in production
    (void)overloaded_node;
    return {};
}

LoadBalancer::RebalanceStats LoadBalancer::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void LoadBalancer::BalancerLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.rebalance_interval_ms));
        
        if (!running_) break;
        
        // Check if rebalancing is needed
        auto cluster_load = registry_->GetClusterLoad();
        
        if (cluster_load > config_.overload_threshold) {
            Rebalance();
        }
    }
}

double LoadBalancer::CalculateLoadVariance() const {
    auto nodes = registry_->GetAllNodes();
    
    if (nodes.empty()) return 0.0;
    
    // Calculate mean load
    double mean = 0.0;
    for (const auto& node : nodes) {
        mean += node.current_load;
    }
    mean /= nodes.size();
    
    // Calculate variance
    double variance = 0.0;
    for (const auto& node : nodes) {
        variance += std::pow(node.current_load - mean, 2);
    }
    variance /= nodes.size();
    
    return variance;
}

// ============================================================================
// ConsensusManager Implementation
// ============================================================================

ConsensusManager::ConsensusManager(const DistributionConfig& config)
    : config_(config) {}

bool ConsensusManager::ProposeTask(const DistributedTask& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ConsensusState state;
    state.proposal_time = std::chrono::steady_clock::now();
    consensus_states_[task.base_task.task_id] = state;
    
    return true;
}

bool ConsensusManager::AckTask(const std::string& task_id, const std::string& node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = consensus_states_.find(std::stoull(task_id));
    if (it == consensus_states_.end()) {
        return false;
    }
    
    it->second.acks.push_back(node_id);
    return true;
}

bool ConsensusManager::NackTask(const std::string& task_id, const std::string& node_id,
                                const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = consensus_states_.find(std::stoull(task_id));
    if (it == consensus_states_.end()) {
        return false;
    }
    
    it->second.nacks.push_back(node_id);
    (void)reason;
    
    return true;
}

bool ConsensusManager::HasConsensus(const std::string& task_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = consensus_states_.find(std::stoull(task_id));
    if (it == consensus_states_.end()) {
        return false;
    }
    
    return it->second.acks.size() >= config_.consensus_quorum;
}

bool ConsensusManager::IsRejected(const std::string& task_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = consensus_states_.find(std::stoull(task_id));
    if (it == consensus_states_.end()) {
        return false;
    }
    
    // Rejected if too many nacks
    return it->second.nacks.size() > config_.consensus_quorum;
}

std::vector<std::string> ConsensusManager::GetConsensusNodes(const std::string& task_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = consensus_states_.find(std::stoull(task_id));
    if (it != consensus_states_.end()) {
        return it->second.acks;
    }
    
    return {};
}

void ConsensusManager::CleanupCompletedTasks() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    
    for (auto it = consensus_states_.begin(); it != consensus_states_.end();) {
        if ((now - it->second.proposal_time) > std::chrono::minutes(5)) {
            it = consensus_states_.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// FaultToleranceManager Implementation
// ============================================================================

FaultToleranceManager::FaultToleranceManager(NodeRegistry* registry, const DistributionConfig& config)
    : registry_(registry)
    , config_(config) {}

void FaultToleranceManager::DetectFailures() {
    auto failed = registry_->GetFailedNodes();
    
    for (const auto& node_id : failed) {
        HandleNodeFailure(node_id);
    }
}

bool FaultToleranceManager::IsNodeFailed(const std::string& node_id) const {
    auto node = registry_->GetNode(node_id);
    return !node.IsHealthy();
}

void FaultToleranceManager::HandleNodeFailure(const std::string& node_id) {
    // Update node state
    auto node = registry_->GetNode(node_id);
    node.state = NodeState::OFFLINE;
    registry_->UpdateNode(node);
    
    // Recover tasks from failed node
    // (Would query task state in production)
}

void FaultToleranceManager::RecoverTask(const DistributedTask& task) {
    // Resubmit task to another node
    (void)task;
}

bool FaultToleranceManager::ShouldRetry(const DistributedTask& task) const {
    return task.migration_count < config_.max_retries;
}

DistributedTask FaultToleranceManager::PrepareRetry(const DistributedTask& task) {
    DistributedTask retry = task;
    retry.dist_state = DistributedTask::DistributionState::PENDING;
    retry.target_node.clear();
    return retry;
}

void FaultToleranceManager::CheckpointTask(const DistributedTask& task) {
    std::lock_guard<std::mutex> lock(checkpoint_mutex_);
    checkpoints_[task.base_task.task_id] = task;
}

DistributedTask FaultToleranceManager::RestoreFromCheckpoint(const std::string& task_id) {
    std::lock_guard<std::mutex> lock(checkpoint_mutex_);
    
    auto it = checkpoints_.find(std::stoull(task_id));
    if (it != checkpoints_.end()) {
        return it->second;
    }
    
    return DistributedTask{};
}

// ============================================================================
// DistributedScheduler Implementation
// ============================================================================

DistributedScheduler::DistributedScheduler(const std::string& node_id,
                                           NodeType type,
                                           const DistributionConfig& config)
    : node_id_(node_id)
    , type_(type)
    , config_(config)
    , stats_{} {}

DistributedScheduler::~DistributedScheduler() {
    Shutdown();
}

void DistributedScheduler::Initialize() {
    // Create components
    node_registry_ = std::make_unique<NodeRegistry>(config_);
    task_distributor_ = std::make_unique<TaskDistributor>(node_registry_.get(), config_);
    load_balancer_ = std::make_unique<LoadBalancer>(node_registry_.get(), config_);
    consensus_manager_ = std::make_unique<ConsensusManager>(config_);
    ft_manager_ = std::make_unique<FaultToleranceManager>(node_registry_.get(), config_);
    local_scheduler_ = std::make_unique<AdaptiveScheduler>();
    
    // Register self
    NodeInfo self;
    self.node_id = node_id_;
    self.type = type_;
    self.state = NodeState::ACTIVE;
    self.last_heartbeat = std::chrono::steady_clock::now();
    node_registry_->RegisterNode(self);
}

void DistributedScheduler::Start() {
    running_ = true;
    
    // Start local scheduler
    local_scheduler_->Start();
    
    // Start load balancer
    load_balancer_->Start();
    
    // Start heartbeat thread
    heartbeat_thread_ = std::thread(&DistributedScheduler::HeartbeatLoop, this);
    
    // Start monitor thread
    monitor_thread_ = std::thread(&DistributedScheduler::MonitorLoop, this);
}

void DistributedScheduler::Stop() {
    running_ = false;
    
    // Stop threads
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    
    // Stop components
    load_balancer_->Stop();
    local_scheduler_->Stop();
}

void DistributedScheduler::Shutdown() {
    Stop();
    
    // Leave cluster
    LeaveCluster();
}

void DistributedScheduler::JoinCluster(const std::string& coordinator_address) {
    (void)coordinator_address;
    // Would connect to coordinator in production
}

void DistributedScheduler::LeaveCluster() {
    // Unregister from coordinator
    node_registry_->UnregisterNode(node_id_);
}

void DistributedScheduler::RegisterWithCoordinator() {
    // Would send registration message in production
}

uint64_t DistributedScheduler::SubmitDistributedTask(const ScheduledTask& task) {
    DistributedTask dist_task;
    dist_task.base_task = task;
    dist_task.source_node = node_id_;
    dist_task.dist_state = DistributedTask::DistributionState::PENDING;
    
    // Distribute task
    std::string target = task_distributor_->DistributeTask(dist_task);
    dist_task.target_node = target;
    dist_task.dist_state = DistributedTask::DistributionState::ASSIGNED;
    
    // Store task
    uint64_t task_id = task.task_id;
    {
        std::lock_guard<std::mutex> lock(tasks_mutex_);
        distributed_tasks_[task_id] = dist_task;
    }
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.tasks_submitted++;
    }
    
    // If target is local, execute
    if (target == node_id_) {
        ExecuteLocalTask(dist_task);
    } else {
        // Send to remote node
        SubmitTaskToNode(task, target);
    }
    
    return task_id;
}

void DistributedScheduler::SubmitTaskToNode(const ScheduledTask& task, const std::string& node_id) {
    (void)task;
    (void)node_id;
    // Would send task to remote node in production
}

void DistributedScheduler::ExecuteLocalTask(const DistributedTask& task) {
    // Execute on local scheduler
    local_scheduler_->SubmitTask(task.base_task);
}

void DistributedScheduler::CompleteDistributedTask(uint64_t task_id, double tps, bool success) {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    
    auto it = distributed_tasks_.find(task_id);
    if (it != distributed_tasks_.end()) {
        it->second.dist_state = success 
            ? DistributedTask::DistributionState::COMPLETED 
            : DistributedTask::DistributionState::FAILED;
    }
    
    // Update stats
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        if (success) {
            stats_.tasks_executed_locally++;
        } else {
            stats_.tasks_failed++;
        }
    }
    
    // Report to local scheduler
    local_scheduler_->ReportTaskCompletion(task_id, tps, 1.0, success);
}

void DistributedScheduler::FailDistributedTask(uint64_t task_id, const std::string& reason) {
    (void)reason;
    CompleteDistributedTask(task_id, 0.0, false);
}

DistributedTask DistributedScheduler::GetDistributedTask(uint64_t task_id) const {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    
    auto it = distributed_tasks_.find(task_id);
    if (it != distributed_tasks_.end()) {
        return it->second;
    }
    
    return DistributedTask{};
}

std::vector<DistributedTask> DistributedScheduler::GetLocalTasks() const {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    
    std::vector<DistributedTask> local;
    for (const auto& [id, task] : distributed_tasks_) {
        if (task.target_node == node_id_) {
            local.push_back(task);
        }
    }
    
    return local;
}

std::vector<DistributedTask> DistributedScheduler::GetRemoteTasks() const {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    
    std::vector<DistributedTask> remote;
    for (const auto& [id, task] : distributed_tasks_) {
        if (task.target_node != node_id_) {
            remote.push_back(task);
        }
    }
    
    return remote;
}

NodeInfo DistributedScheduler::GetLocalNodeInfo() const {
    return node_registry_->GetNode(node_id_);
}

std::vector<NodeInfo> DistributedScheduler::GetClusterNodes() const {
    return node_registry_->GetAllNodes();
}

bool DistributedScheduler::IsCoordinator() const {
    return type_ == NodeType::COORDINATOR;
}

std::string DistributedScheduler::GetCoordinatorId() const {
    auto coordinators = node_registry_->GetNodesByType(NodeType::COORDINATOR);
    if (!coordinators.empty()) {
        return coordinators[0].node_id;
    }
    return "";
}

DistributedScheduler::DistributedStats DistributedScheduler::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void DistributedScheduler::SetDistributionPolicy(DistributionPolicy policy) {
    config_.policy = policy;
}

DistributionPolicy DistributedScheduler::GetDistributionPolicy() const {
    return config_.policy;
}

void DistributedScheduler::HeartbeatLoop() {
    while (running_) {
        std::this_thread::sleep_for(config_.heartbeat_interval);
        
        if (!running_) break;
        
        // Send heartbeat
        node_registry_->RecordHeartbeat(node_id_);
        
        // Update local metrics
        auto metrics = local_scheduler_->GetMetrics();
        node_registry_->UpdateNodeMetrics(node_id_, 
            metrics.worker_utilization.load(),
            metrics.average_latency.load(),
            metrics.average_tps.load());
    }
}

void DistributedScheduler::MonitorLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        if (!running_) break;
        
        // Detect failures
        ft_manager_->DetectFailures();
        
        // Cleanup old tasks
        consensus_manager_->CleanupCompletedTasks();
    }
}

void DistributedScheduler::ProcessDistributedTask(const DistributedTask& task) {
    (void)task;
    // Process incoming distributed task
}

void DistributedScheduler::HandleTaskCompletion(uint64_t task_id, bool success) {
    (void)task_id;
    (void)success;
    // Handle task completion notification
}

// ============================================================================
// ClusterCoordinator Implementation
// ============================================================================

ClusterCoordinator::ClusterCoordinator(const std::string& coordinator_id,
                                       const DistributionConfig& config)
    : coordinator_id_(coordinator_id)
    , config_(config)
    , stats_{} {}

void ClusterCoordinator::Start() {
    running_ = true;
    
    // Initialize components
    node_registry_ = std::make_unique<NodeRegistry>(config_);
    load_balancer_ = std::make_unique<LoadBalancer>(node_registry_.get(), config_);
    
    // Start load balancer
    load_balancer_->Start();
    
    // Start coordinator loop
    coordinator_thread_ = std::thread(&ClusterCoordinator::CoordinatorLoop, this);
}

void ClusterCoordinator::Stop() {
    running_ = false;
    
    if (coordinator_thread_.joinable()) {
        coordinator_thread_.join();
    }
    
    load_balancer_->Stop();
}

void ClusterCoordinator::RegisterNode(const NodeInfo& node) {
    node_registry_->RegisterNode(node);
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_nodes++;
        stats_.active_nodes++;
    }
}

void ClusterCoordinator::UnregisterNode(const std::string& node_id) {
    node_registry_->UnregisterNode(node_id);
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.active_nodes--;
    }
}

void ClusterCoordinator::UpdateNodeState(const std::string& node_id, NodeState state) {
    auto node = node_registry_->GetNode(node_id);
    node.state = state;
    node_registry_->UpdateNode(node);
}

void ClusterCoordinator::CoordinateTaskDistribution(const DistributedTask& task) {
    (void)task;
    // Coordinate task distribution across cluster
}

void ClusterCoordinator::HandleTaskCompletion(const std::string& node_id, uint64_t task_id) {
    (void)node_id;
    (void)task_id;
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.tasks_completed++;
    }
}

void ClusterCoordinator::HandleTaskFailure(const std::string& node_id, uint64_t task_id,
                                          const std::string& reason) {
    (void)node_id;
    (void)task_id;
    (void)reason;
    // Handle task failure
}

void ClusterCoordinator::TriggerRebalance() {
    load_balancer_->Rebalance();
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.rebalances_triggered++;
    }
}

void ClusterCoordinator::HandleNodeFailure(const std::string& node_id) {
    UpdateNodeState(node_id, NodeState::OFFLINE);
    
    // Migrate tasks from failed node
    // (Would query task state in production)
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.active_nodes--;
    }
}

void ClusterCoordinator::MigrateTasks(const std::string& from_node, const std::string& to_node) {
    (void)from_node;
    (void)to_node;
    // Migrate tasks between nodes
}

ClusterCoordinator::ClusterStats ClusterCoordinator::GetClusterStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    ClusterStats current = stats_;
    current.cluster_load = node_registry_->GetClusterLoad();
    current.cluster_throughput = node_registry_->GetClusterThroughput();
    
    return current;
}

void ClusterCoordinator::CoordinatorLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        if (!running_) break;
        
        // Check cluster health
        auto failed_nodes = node_registry_->GetFailedNodes();
        for (const auto& node_id : failed_nodes) {
            HandleNodeFailure(node_id);
        }
        
        // Update stats
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.active_nodes = node_registry_->GetHealthyNodeCount();
        }
    }
}

// ============================================================================
// DistributedUtils Implementation
// ============================================================================

namespace DistributedUtils {

std::string GetLocalAddress() {
    // Simplified - would get actual local address in production
    return "127.0.0.1";
}

bool IsReachable(const std::string& address, uint16_t port) {
    (void)address;
    (void)port;
    // Would check network reachability in production
    return true;
}

double MeasureLatency(const std::string& address, uint16_t port) {
    (void)address;
    (void)port;
    // Would measure actual network latency in production
    return 1.0; // 1ms placeholder
}

std::string ConsistentHash(const std::string& key,
                          const std::vector<std::string>& nodes) {
    if (nodes.empty()) return "";
    
    // Simple hash
    size_t hash = std::hash<std::string>{}(key);
    size_t index = hash % nodes.size();
    
    return nodes[index];
}

double CalculateLoadScore(const NodeInfo& node) {
    return node.current_load;
}

double CalculateCapacityScore(const NodeInfo& node) {
    return node.cpu_capacity + node.memory_capacity;
}

std::string FindAffinityNode(const ScheduledTask& task,
                              const std::vector<NodeInfo>& nodes) {
    (void)task;
    
    if (nodes.empty()) return "";
    
    // Find node with best affinity (simplified)
    return nodes[0].node_id;
}

} // namespace DistributedUtils

} // namespace Scheduler
