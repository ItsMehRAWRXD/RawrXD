// AdaptiveScheduler.cpp
// Phase C.2 Batch 1/5 — Pattern-Aware Scheduler Core Implementation

#include "AdaptiveScheduler.hpp"
#include <algorithm>
#include <math>
#include <sstream>
#include <iomanip>

namespace Scheduler {

// ============================================================================
// TaskPriority Implementation
// ============================================================================

void TaskPriority::CalculateTotal(const AdaptiveSchedulerConfig& config) {
    // Calculate weighted components
    double stability_component = stability_factor * config.stability_weight;
    double confidence_component = confidence_factor * config.confidence_weight;
    double significance_component = significance_factor * config.significance_weight;
    double exploration_component = exploration_weight * config.exploration_weight;
    
    // Combine into total priority
    total_priority = (stability_component + confidence_component + 
                     significance_component + exploration_component);
    
    // Normalize to 0-1 range
    total_priority = std::max(0.0, std::min(1.0, total_priority));
    
    // Derive execution and resource weights
    execution_weight = total_priority;
    resource_weight = total_priority * (1.0 + significance_component);
    resource_weight = std::min(1.0, resource_weight);
}

// ============================================================================
// PatternPriorityEngine Implementation
// ============================================================================

PatternPriorityEngine::PatternPriorityEngine(const AdaptiveSchedulerConfig& config)
    : config_(config) {}

TaskPriority PatternPriorityEngine::CalculatePriority(
    const Emergent::PatternSignature& pattern,
    const SchedulerMetrics& metrics) {
    
    TaskPriority priority;
    
    // Calculate factors from pattern
    priority.stability_factor = CalculateStabilityFactor(
        pattern.metrics.count("stability") ? pattern.metrics.at("stability") : 0.5);
    priority.confidence_factor = CalculateConfidenceFactor(pattern.confidence);
    priority.significance_factor = CalculateSignificanceFactor(
        pattern.metrics.count("significance") ? pattern.metrics.at("significance") : 0.5);
    priority.exploration_weight = CalculateExplorationFactor(pattern.id);
    
    // Calculate total priority
    priority.CalculateTotal(config_);
    
    return priority;
}

TaskPriority PatternPriorityEngine::CalculatePriority(
    const Emergent::HarmonicAttractor& attractor,
    const SchedulerMetrics& metrics) {
    
    TaskPriority priority;
    priority.stability_factor = attractor.stability_score;
    priority.confidence_factor = attractor.convergence_rate;
    priority.significance_factor = attractor.amplitude;
    priority.exploration_weight = CalculateExplorationFactor(attractor.id);
    
    priority.CalculateTotal(config_);
    return priority;
}

TaskPriority PatternPriorityEngine::CalculatePriority(
    const Emergent::SwarmCluster& cluster,
    const SchedulerMetrics& metrics) {
    
    TaskPriority priority;
    priority.stability_factor = cluster.cohesion_score;
    priority.confidence_factor = cluster.performance_score;
    priority.significance_factor = static_cast<double>(cluster.agent_ids.size()) / 10.0;
    priority.significance_factor = std::min(1.0, priority.significance_factor);
    priority.exploration_weight = CalculateExplorationFactor(cluster.id);
    
    priority.CalculateTotal(config_);
    return priority;
}

TaskPriority PatternPriorityEngine::CalculatePriority(
    const Emergent::GraphMotif& motif,
    const SchedulerMetrics& metrics) {
    
    TaskPriority priority;
    priority.stability_factor = 0.7; // Motifs are relatively stable
    priority.confidence_factor = motif.significance_score;
    priority.significance_factor = static_cast<double>(motif.frequency) / 10.0;
    priority.significance_factor = std::min(1.0, priority.significance_factor);
    priority.exploration_weight = CalculateExplorationFactor(motif.id);
    
    priority.CalculateTotal(config_);
    return priority;
}

TaskPriority PatternPriorityEngine::CalculatePriority(
    const Emergent::StabilityBasin& basin,
    const SchedulerMetrics& metrics) {
    
    TaskPriority priority;
    priority.stability_factor = basin.attractor_strength;
    priority.confidence_factor = 1.0 - basin.escape_probability;
    priority.significance_factor = basin.basin_volume / 100.0;
    priority.significance_factor = std::min(1.0, priority.significance_factor);
    priority.exploration_weight = CalculateExplorationFactor(basin.id);
    
    priority.CalculateTotal(config_);
    return priority;
}

std::map<std::string, TaskPriority> PatternPriorityEngine::CalculatePriorities(
    const Emergent::EmergentPatternReport& report,
    const SchedulerMetrics& metrics) {
    
    std::map<std::string, TaskPriority> priorities;
    
    // Process harmonic attractors
    for (const auto& attractor : report.harmonic_attractors) {
        priorities[attractor.id] = CalculatePriority(attractor, metrics);
    }
    
    // Process swarm clusters
    for (const auto& cluster : report.swarm_clusters) {
        priorities[cluster.id] = CalculatePriority(cluster, metrics);
    }
    
    // Process graph motifs
    for (const auto& motif : report.graph_motifs) {
        priorities[motif.id] = CalculatePriority(motif, metrics);
    }
    
    // Process stability basins
    for (const auto& basin : report.stability_basins) {
        priorities[basin.id] = CalculatePriority(basin, metrics);
    }
    
    return priorities;
}

void PatternPriorityEngine::UpdateWeights(
    const std::map<std::string, double>& task_performance) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Update historical performance
    for (const auto& [task_id, performance] : task_performance) {
        task_history_[task_id].push_back(performance);
        
        // Keep only recent history
        while (task_history_[task_id].size() > 100) {
            task_history_[task_id].erase(task_history_[task_id].begin());
        }
    }
    
    // Adjust weights based on historical performance
    // (Simplified: in real implementation, would use ML or optimization)
}

AdaptiveSchedulerConfig PatternPriorityEngine::GetConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

void PatternPriorityEngine::SetConfig(const AdaptiveSchedulerConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
}

double PatternPriorityEngine::CalculateStabilityFactor(double stability) {
    // Higher stability = higher factor
    return std::min(1.0, stability * 1.2);
}

double PatternPriorityEngine::CalculateConfidenceFactor(double confidence) {
    // Direct mapping with slight boost
    return std::min(1.0, confidence * 1.1);
}

double PatternPriorityEngine::CalculateSignificanceFactor(double significance) {
    // Significance has diminishing returns
    return std::sqrt(significance);
}

double PatternPriorityEngine::CalculateExplorationFactor(const std::string& pattern_id) {
    // Check if we've seen this pattern before
    auto it = task_history_.find(pattern_id);
    if (it == task_history_.end() || it->second.empty()) {
        // New pattern - high exploration
        return config_.exploration_weight * 2.0;
    }
    
    // Known pattern - reduce exploration based on history
    double history_size = static_cast<double>(it->second.size());
    double decay = std::exp(-history_size / 10.0);
    return config_.exploration_weight * decay;
}

// ============================================================================
// WorkerPoolManager Implementation
// ============================================================================

WorkerPoolManager::WorkerPoolManager(const AdaptiveSchedulerConfig& config)
    : config_(config), next_worker_id_(1), scale_up_count_(0), scale_down_count_(0) {}

void WorkerPoolManager::InitializeWorkers(uint32_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t worker_id = next_worker_id_++;
        WorkerAssignment assignment;
        assignment.worker_id = worker_id;
        assignment.assigned_load = 0.0;
        assignment.historical_tps = 0.0;
        assignment.reliability_score = 0.5;
        
        workers_[worker_id] = assignment;
        worker_available_[worker_id] = true;
    }
}

void WorkerPoolManager::ScaleWorkers(uint32_t target_count) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint32_t current_count = static_cast<uint32_t>(workers_.size());
    
    if (target_count > current_count) {
        // Scale up
        for (uint32_t i = current_count; i < target_count; ++i) {
            uint32_t worker_id = next_worker_id_++;
            WorkerAssignment assignment;
            assignment.worker_id = worker_id;
            workers_[worker_id] = assignment;
            worker_available_[worker_id] = true;
        }
        scale_up_count_++;
    } else if (target_count < current_count) {
        // Scale down - mark excess workers as unavailable
        uint32_t to_remove = current_count - target_count;
        for (auto& [id, available] : worker_available_) {
            if (available && to_remove > 0) {
                available = false;
                to_remove--;
            }
        }
        scale_down_count_++;
    }
    
    last_scale_time_ = std::chrono::steady_clock::now();
}

void WorkerPoolManager::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    workers_.clear();
    worker_available_.clear();
}

std::vector<uint32_t> WorkerPoolManager::AssignWorkers(const ScheduledTask& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<uint32_t> assigned;
    
    // Calculate number of workers based on priority
    uint32_t num_workers = SchedulerUtils::CalculateWorkerAllocation(
        task.priority.total_priority,
        task.min_workers,
        task.max_workers,
        config_.worker_scale_factor);
    
    // Find available workers
    for (auto& [worker_id, available] : worker_available_) {
        if (available && assigned.size() < num_workers) {
            available = false;
            assigned.push_back(worker_id);
            
            // Update assignment
            workers_[worker_id].task_id = task.task_id;
            workers_[worker_id].assignment_time = std::chrono::steady_clock::now();
        }
    }
    
    return assigned;
}

void WorkerPoolManager::ReleaseWorkers(uint64_t task_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [worker_id, assignment] : workers_) {
        if (assignment.task_id == task_id) {
            assignment.task_id = 0;
            assignment.assigned_load = 0.0;
            worker_available_[worker_id] = true;
        }
    }
}

void WorkerPoolManager::UpdateWorkerPerformance(uint32_t worker_id, double tps, bool success) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = workers_.find(worker_id);
    if (it != workers_.end()) {
        // Update historical TPS with exponential moving average
        if (it->second.historical_tps == 0.0) {
            it->second.historical_tps = tps;
        } else {
            it->second.historical_tps = 0.7 * it->second.historical_tps + 0.3 * tps;
        }
        
        // Update reliability score
        if (success) {
            it->second.successful_tasks++;
            it->second.reliability_score = std::min(1.0, it->second.reliability_score + 0.05);
        } else {
            it->second.failed_tasks++;
            it->second.reliability_score = std::max(0.0, it->second.reliability_score - 0.1);
        }
    }
}

uint32_t WorkerPoolManager::GetAvailableWorkers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint32_t count = 0;
    for (const auto& [id, available] : worker_available_) {
        if (available) count++;
    }
    return count;
}

uint32_t WorkerPoolManager::GetTotalWorkers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<uint32_t>(workers_.size());
}

double WorkerPoolManager::GetWorkerUtilization() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (workers_.empty()) return 0.0;
    
    uint32_t busy = 0;
    for (const auto& [id, assignment] : workers_) {
        if (assignment.task_id != 0) busy++;
    }
    
    return static_cast<double>(busy) / workers_.size();
}

std::vector<WorkerAssignment> WorkerPoolManager::GetWorkerAssignments() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<WorkerAssignment> assignments;
    for (const auto& [id, assignment] : workers_) {
        assignments.push_back(assignment);
    }
    return assignments;
}

void WorkerPoolManager::EvaluateScalingNeeds(const SchedulerMetrics& metrics) {
    double utilization = metrics.worker_utilization.load();
    
    if (utilization > 0.8 && GetTotalWorkers() < config_.max_workers) {
        // High utilization - scale up
        uint32_t new_count = std::min(config_.max_workers, GetTotalWorkers() + 2);
        ScaleWorkers(new_count);
    } else if (utilization < 0.3 && GetTotalWorkers() > config_.min_workers) {
        // Low utilization - scale down
        uint32_t new_count = std::max(config_.min_workers, GetTotalWorkers() - 1);
        ScaleWorkers(new_count);
    }
}

bool WorkerPoolManager::ShouldScaleUp() const {
    return GetWorkerUtilization() > 0.8 && GetTotalWorkers() < config_.max_workers;
}

bool WorkerPoolManager::ShouldScaleDown() const {
    return GetWorkerUtilization() < 0.3 && GetTotalWorkers() > config_.min_workers;
}

// ============================================================================
// ExplorationEngine Implementation
// ============================================================================

ExplorationEngine::ExplorationEngine(const AdaptiveSchedulerConfig& config)
    : config_(config), current_exploration_rate_(config.exploration_rate) {}

bool ExplorationEngine::ShouldExplore(const Emergent::PatternSignature& pattern) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    double rate = GetExplorationRateForPattern(pattern.id);
    
    // High stability patterns should be exploited
    if (pattern.confidence > config_.convergence_threshold) {
        rate *= 0.5; // Reduce exploration for stable patterns
    }
    
    // Low confidence patterns should be explored
    if (pattern.confidence < config_.instability_threshold) {
        rate *= 2.0; // Increase exploration for unstable patterns
    }
    
    // Random decision
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    
    return dis(gen) < rate;
}

bool ExplorationEngine::ShouldExploit(const Emergent::PatternSignature& pattern) {
    return !ShouldExplore(pattern);
}

double ExplorationEngine::GetExplorationRate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_exploration_rate_;
}

double ExplorationEngine::GetExplorationRateForPattern(const std::string& pattern_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pattern_exploration_rates_.find(pattern_id);
    if (it != pattern_exploration_rates_.end()) {
        return it->second;
    }
    
    // New pattern - use global rate
    return current_exploration_rate_;
}

void ExplorationEngine::ReportSuccess(const std::string& pattern_id, double tps) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    pattern_success_count_[pattern_id]++;
    pattern_trial_count_[pattern_id]++;
    
    // Reduce exploration for successful patterns
    auto it = pattern_exploration_rates_.find(pattern_id);
    if (it == pattern_exploration_rates_.end()) {
        pattern_exploration_rates_[pattern_id] = current_exploration_rate_;
    } else {
        it->second *= config_.exploration_decay;
        it->second = std::max(config_.min_exploration_rate, it->second);
    }
}

void ExplorationEngine::ReportFailure(const std::string& pattern_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    pattern_trial_count_[pattern_id]++;
    
    // Increase exploration for failed patterns (try different approach)
    auto it = pattern_exploration_rates_.find(pattern_id);
    if (it == pattern_exploration_rates_.end()) {
        pattern_exploration_rates_[pattern_id] = std::min(1.0, current_exploration_rate_ * 1.5);
    } else {
        it->second = std::min(1.0, it->second * 1.2);
    }
}

void ExplorationEngine::ReportConvergence(const std::string& pattern_id, double convergence) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Adjust exploration based on convergence
    auto it = pattern_exploration_rates_.find(pattern_id);
    if (it != pattern_exploration_rates_.end()) {
        if (convergence > config_.convergence_threshold) {
            // High convergence - reduce exploration
            it->second *= 0.9;
        } else if (convergence < config_.instability_threshold) {
            // Low convergence - increase exploration
            it->second = std::min(1.0, it->second * 1.1);
        }
        
        it->second = std::max(config_.min_exploration_rate, it->second);
    }
}

std::vector<ScheduledTask> ExplorationEngine::SpawnExplorationTrials(
    const ScheduledTask& base_task,
    uint32_t trial_count) {
    
    std::vector<ScheduledTask> trials;
    
    for (uint32_t i = 0; i < trial_count; ++i) {
        ScheduledTask trial = base_task;
        trial.task_id = base_task.task_id + i + 1; // Unique ID
        trial.priority.exploration_weight = 1.0; // High exploration
        trial.priority.CalculateTotal(config_);
        
        // Viate parameters slightly
        trial.min_workers = std::max(1u, base_task.min_workers + (i % 2));
        trial.max_workers = base_task.max_workers + (i % 3);
        
        trials.push_back(trial);
    }
    
    return trials;
}

void ExplorationEngine::UpdateExplorationRate() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
        now - last_update_).count();
    
    if (elapsed > 0) {
        // Decay exploration rate over time
        current_exploration_rate_ *= std::pow(config_.exploration_decay, elapsed);
        current_exploration_rate_ = std::max(config_.min_exploration_rate, 
                                            current_exploration_rate_);
        last_update_ = now;
    }
}

void ExplorationEngine::ResetExplorationRate() {
    std::lock_guard<std::mutex> lock(mutex_);
    current_exploration_rate_ = config_.exploration_rate;
    pattern_exploration_rates_.clear();
}

// ============================================================================
// SEGSchedulerIntegration Implementation
// ============================================================================

void SEGSchedulerIntegration::UpdateEdgeWeights(
    SEG::SovereignExecutionGraph& graph,
    const std::map<std::pair<uint64_t, uint64_t>, double>& success_rates,
    double learning_rate) {
    
    // Update edge weights based on observed success rates
    for (const auto& [edge, success_rate] : success_rates) {
        // Would update actual graph edge weights
        // This is a simplified implementation
        (void)graph;
        (void)edge;
        (void)success_rate;
        (void)learning_rate;
    }
}

std::vector<uint64_t> SEGSchedulerIntegration::GetRecommendedPath(
    const SEG::SovereignExecutionGraph& graph,
    uint64_t start_node,
    uint64_t end_node) {
    
    // Would implement Dijkstra or A* with learned weights
    // Simplified: return direct path
    (void)graph;
    (void)start_node;
    (void)end_node;
    
    return {start_node, end_node};
}

double SEGSchedulerIntegration::CalculatePathUtility(
    const SEG::SovereignExecutionGraph& graph,
    const std::vector<uint64_t>& path,
    const SchedulerMetrics& metrics) {
    
    // Calculate utility based on path characteristics
    double convergence = metrics.average_convergence.load();
    double throughput = metrics.average_tps.load();
    double reliability = metrics.success_rate.load();
    double resource_cost = static_cast<double>(path.size());
    
    return SchedulerUtils::CalculateUtility(convergence, throughput, 
                                            reliability, resource_cost);
}

void SEGSchedulerIntegration::ApplySchedulingDecision(
    SEG::SovereignExecutionGraph& graph,
    const SchedulingDecision& decision) {
    
    // Apply scheduler decision to graph
    // Would update node priorities, edge weights, etc.
    (void)graph;
    (void)decision;
}

// ============================================================================
// SchedulerUtils Implementation
// ============================================================================

double SchedulerUtils::CalculateUtility(double convergence, double throughput,
                                         double reliability, double resource_cost) {
    // Utility = (convergence * throughput * reliability) / resource_cost
    double numerator = convergence * throughput * reliability;
    double denominator = std::max(1.0, resource_cost);
    
    return numerator / denominator;
}

uint32_t SchedulerUtils::CalculateWorkerAllocation(double priority,
                                                    uint32_t min_workers,
                                                    uint32_t max_workers,
                                                    double scale_factor) {
    // Calculate workers based on priority
    double workers = min_workers * std::pow(scale_factor, priority * 2.0);
    
    // Clamp to valid range
    uint32_t result = static_cast<uint32_t>(workers);
    result = std::max(min_workers, result);
    result = std::min(max_workers, result);
    
    return result;
}

double SchedulerUtils::PredictTPS(const std::vector<double>& historical_tps,
                                 const Emergent::PatternSignature& pattern) {
    if (historical_tps.empty()) {
        // No history - use pattern-based estimate
        return pattern.confidence * 100.0; // Default estimate
    }
    
    // Use exponential moving average
    return ExponentialMovingAverage(historical_tps, 0.3);
}

double SchedulerUtils::PredictConvergence(const std::vector<double>& historical_convergence,
                                         const Emergent::PatternSignature& pattern) {
    if (historical_convergence.empty()) {
        return pattern.confidence;
    }
    
    return ExponentialMovingAverage(historical_convergence, 0.3);
}

double SchedulerUtils::ExponentialMovingAverage(const std::vector<double>& values,
                                               double alpha) {
    if (values.empty()) return 0.0;
    
    double ema = values[0];
    for (size_t i = 1; i < values.size(); ++i) {
        ema = alpha * values[i] + (1.0 - alpha) * ema;
    }
    
    return ema;
}

double SchedulerUtils::ConfidenceInterval(const std::vector<double>& values,
                                         double confidence) {
    if (values.size() < 2) return 0.0;
    
    // Calculate mean
    double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    
    // Calculate standard deviation
    double variance = 0.0;
    for (double v : values) {
        variance += std::pow(v - mean, 2);
    }
    variance /= values.size();
    double stddev = std::sqrt(variance);
    
    // Simplified confidence interval (assuming normal distribution)
    double z_score = (confidence == 0.95) ? 1.96 : 1.0;
    return z_score * stddev / std::sqrt(values.size());
}

// ============================================================================
// AdaptiveScheduler::Impl Implementation
// ============================================================================

class AdaptiveScheduler::Impl {
public:
    Impl(const AdaptiveSchedulerConfig& config)
        : config_(config)
        , priority_engine_(config)
        , worker_pool_(config)
        , exploration_engine_(config)
        , next_task_id_(1)
        , running_(false)
        , shutdown_(false) {
        metrics_.start_time = std::chrono::steady_clock::now();
    }
    
    ~Impl() {
        Shutdown();
    }
    
    void Initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Initialize worker pool
        worker_pool_.InitializeWorkers(config_.default_workers);
        
        // Initialize task queues
        pending_tasks_.clear();
        running_tasks_.clear();
        completed_tasks_.clear();
        
        // Reset metrics
        metrics_ = SchedulerMetrics{};
        metrics_.start_time = std::chrono::steady_clock::now();
        
        initialized_ = true;
    }
    
    void Start() {
        if (!initialized_) {
            Initialize();
        }
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (running_) {
            return; // Already running
        }
        
        running_ = true;
        shutdown_ = false;
        
        // Start scheduling thread
        scheduler_thread_ = std::thread(&Impl::SchedulingLoop, this);
        
        // Start metrics collection thread
        metrics_thread_ = std::thread(&Impl::MetricsLoop, this);
    }
    
    void Stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            running_ = false;
        }
        
        cv_.notify_all();
        
        // Wait for threads to finish
        if (scheduler_thread_.joinable()) {
            scheduler_thread_.join();
        }
        if (metrics_thread_.joinable()) {
            metrics_thread_.join();
        }
    }
    
    void Shutdown() {
        Stop();
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        worker_pool_.Shutdown();
        
        // Clear all tasks
        pending_tasks_.clear();
        running_tasks_.clear();
        completed_tasks_.clear();
        
        initialized_ = false;
    }
    
    uint64_t SubmitTask(const ScheduledTask& task) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        uint64_t task_id = next_task_id_++;
        
        ScheduledTask new_task = task;
        new_task.task_id = task_id;
        new_task.submit_time = std::chrono::steady_clock::now();
        new_task.status = ScheduledTask::Status::PENDING;
        
        // Calculate priority if not set
        if (new_task.priority.total_priority == 0.0) {
            new_task.priority.total_priority = 0.5;
            new_task.priority.CalculateTotal(config_);
        }
        
        pending_tasks_[task_id] = new_task;
        metrics_.tasks_submitted++;
        
        // Notify scheduler
        cv_.notify_one();
        
        return task_id;
    }
    
    uint64_t SubmitTaskFromPattern(const Emergent::PatternSignature& pattern) {
        // Calculate priority from pattern
        TaskPriority priority = priority_engine_.CalculatePriority(pattern, metrics_);
        
        ScheduledTask task;
        task.pattern_id = pattern.id;
        task.pattern_type = pattern.type;
        task.priority = priority;
        task.min_workers = config_.min_workers;
        task.max_workers = config_.max_workers;
        
        return SubmitTask(task);
    }
    
    void CancelTask(uint64_t task_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check pending tasks
        auto it = pending_tasks_.find(task_id);
        if (it != pending_tasks_.end()) {
            it->second.status = ScheduledTask::Status::CANCELLED;
            completed_tasks_[task_id] = it->second;
            pending_tasks_.erase(it);
            return;
        }
        
        // Check running tasks
        it = running_tasks_.find(task_id);
        if (it != running_tasks_.end()) {
            // Release workers
            worker_pool_.ReleaseWorkers(task_id);
            
            it->second.status = ScheduledTask::Status::CANCELLED;
            completed_tasks_[task_id] = it->second;
            running_tasks_.erase(it);
            
            metrics_.tasks_running--;
        }
    }
    
    void FeedPatterns(const Emergent::EmergentPatternReport& report) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Calculate priorities for all patterns
        auto priorities = priority_engine_.CalculatePriorities(report, metrics_);
        
        // Store for scheduling decisions
        for (const auto& [pattern_id, priority] : priorities) {
            pattern_priorities_[pattern_id] = priority;
        }
        
        // Update exploration rates based on patterns
        for (const auto& attractor : report.harmonic_attractors) {
            exploration_engine_.ReportConvergence(attractor.id, attractor.convergence_rate);
        }
    }
    
    void FeedPattern(const Emergent::PatternSignature& pattern) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        TaskPriority priority = priority_engine_.CalculatePriority(pattern, metrics_);
        pattern_priorities_[pattern.id] = priority;
        
        exploration_engine_.ReportConvergence(pattern.id, pattern.confidence);
    }
    
    void ReportTaskCompletion(uint64_t task_id, double tps, double convergence, bool success) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = running_tasks_.find(task_id);
        if (it == running_tasks_.end()) {
            return;
        }
        
        ScheduledTask& task = it->second;
        task.end_time = std::chrono::steady_clock::now();
        task.actual_tps = tps;
        task.convergence_rate = convergence;
        task.success = success;
        task.status = ScheduledTask::Status::COMPLETED;
        
        // Release workers
        worker_pool_.ReleaseWorkers(task_id);
        
        // Update metrics
        metrics_.tasks_running--;
        metrics_.tasks_completed++;
        
        // Update success rate
        uint64_t total = metrics_.tasks_completed.load() + metrics_.tasks_failed.load();
        if (total > 0) {
            double current_rate = metrics_.success_rate.load();
            metrics_.success_rate = current_rate + (success ? 1.0 : 0.0 - current_rate) / total;
        }
        
        // Update exploration engine
        if (success) {
            exploration_engine_.ReportSuccess(task.pattern_id, tps);
        }
        
        // Update priority engine
        std::map<std::string, double> performance;
        performance[task.pattern_id] = tps;
        priority_engine_.UpdateWeights(performance);
        
        // Move to completed
        completed_tasks_[task_id] = task;
        running_tasks_.erase(it);
        
        // Update worker performance
        auto decision_it = decisions_.find(task_id);
        if (decision_it != decisions_.end()) {
            for (uint32_t worker_id : decision_it->second.assigned_workers) {
                worker_pool_.UpdateWorkerPerformance(worker_id, tps, success);
            }
        }
    }
    
    void ReportTaskFailure(uint64_t task_id, const std::string& reason) {
        (void)reason; // Could log the reason
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = running_tasks_.find(task_id);
        if (it == running_tasks_.end()) {
            return;
        }
        
        ScheduledTask& task = it->second;
        task.end_time = std::chrono::steady_clock::now();
        task.success = false;
        task.status = ScheduledTask::Status::FAILED;
        
        // Release workers
        worker_pool_.ReleaseWorkers(task_id);
        
        // Update metrics
        metrics_.tasks_running--;
        metrics_.tasks_failed++;
        
        // Update success rate
        uint64_t total = metrics_.tasks_completed.load() + metrics_.tasks_failed.load();
        if (total > 0) {
            double current_rate = metrics_.success_rate.load();
            metrics_.success_rate = current_rate * (total - 1) / total;
        }
        
        // Update exploration engine
        exploration_engine_.ReportFailure(task.pattern_id);
        
        // Move to completed
        completed_tasks_[task_id] = task;
        running_tasks_.erase(it);
    }
    
    std::vector<ScheduledTask> GetPendingTasks() const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::vector<ScheduledTask> tasks;
        for (const auto& [id, task] : pending_tasks_) {
            tasks.push_back(task);
        }
        return tasks;
    }
    
    std::vector<ScheduledTask> GetRunningTasks() const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::vector<ScheduledTask> tasks;
        for (const auto& [id, task] : running_tasks_) {
            tasks.push_back(task);
        }
        return tasks;
    }
    
    std::vector<ScheduledTask> GetCompletedTasks() const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::vector<ScheduledTask> tasks;
        for (const auto& [id, task] : completed_tasks_) {
            tasks.push_back(task);
        }
        return tasks;
    }
    
    SchedulingDecision GetLastDecision(uint64_t task_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = decisions_.find(task_id);
        if (it != decisions_.end()) {
            return it->second;
        }
        
        return SchedulingDecision{};
    }
    
    TaskPriority GetTaskPriority(uint64_t task_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check pending
        auto it = pending_tasks_.find(task_id);
        if (it != pending_tasks_.end()) {
            return it->second.priority;
        }
        
        // Check running
        it = running_tasks_.find(task_id);
        if (it != running_tasks_.end()) {
            return it->second.priority;
        }
        
        // Check completed
        it = completed_tasks_.find(task_id);
        if (it != completed_tasks_.end()) {
            return it->second.priority;
        }
        
        return TaskPriority{};
    }
    
    SchedulerMetrics GetMetrics() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return metrics_;
    }
    
    SchedulerSnapshot GetSnapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        SchedulerSnapshot snapshot;
        snapshot.timestamp = std::chrono::steady_clock::now();
        snapshot.pending_count = pending_tasks_.size();
        snapshot.running_count = running_tasks_.size();
        snapshot.completed_count = completed_tasks_.size();
        snapshot.worker_utilization = worker_pool_.GetWorkerUtilization();
        snapshot.average_tps = metrics_.average_tps.load();
        snapshot.success_rate = metrics_.success_rate.load();
        snapshot.exploration_ratio = metrics_.GetExplorationRatio();
        
        return snapshot;
    }
    
    void SetConfig(const AdaptiveSchedulerConfig& config) {
        std::lock_guard<std::mutex> lock(mutex_);
        config_ = config;
        priority_engine_.SetConfig(config);
    }
    
    AdaptiveSchedulerConfig GetConfig() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return config_;
    }
    
    void Reset() {
        Shutdown();
        Initialize();
    }
    
    void SaveState(const std::string& path) {
        // Simplified state save - in production would serialize to file
        (void)path;
    }
    
    void LoadState(const std::string& path) {
        // Simplified state load - in production would deserialize from file
        (void)path;
    }
    
private:
    void SchedulingLoop() {
        while (running_) {
            std::unique_lock<std::mutex> lock(mutex_);
            
            // Wait for work or timeout
            cv_.wait_for(lock, config_.scheduling_interval, [this] {
                return !pending_tasks_.empty() || !running_;
            });
            
            if (!running_) {
                break;
            }
            
            // Process pending tasks
            ProcessPendingTasks();
            
            // Evaluate scaling needs
            worker_pool_.EvaluateScalingNeeds(metrics_);
            
            // Update exploration rate
            exploration_engine_.UpdateExplorationRate();
        }
    }
    
    void ProcessPendingTasks() {
        // Sort pending tasks by priority
        std::vector<std::pair<uint64_t, ScheduledTask>> sorted_tasks;
        for (const auto& [id, task] : pending_tasks_) {
            sorted_tasks.push_back({id, task});
        }
        
        std::sort(sorted_tasks.begin(), sorted_tasks.end(),
            [](const auto& a, const auto& b) {
                return a.second.priority.total_priority > b.second.priority.total_priority;
            });
        
        // Try to schedule tasks
        for (auto& [task_id, task] : sorted_tasks) {
            if (!running_) break;
            
            // Check if we have available workers
            if (worker_pool_.GetAvailableWorkers() < task.min_workers) {
                continue;
            }
            
            // Make scheduling decision
            SchedulingDecision decision = MakeSchedulingDecision(task);
            
            if (decision.assigned_workers.empty()) {
                continue;
            }
            
            // Move task to running
            task.status = ScheduledTask::Status::RUNNING;
            task.start_time = std::chrono::steady_clock::now();
            running_tasks_[task_id] = task;
            pending_tasks_.erase(task_id);
            
            metrics_.tasks_running++;
            
            // Store decision
            decisions_[task_id] = decision;
            
            // Update exploration/exploitation counters
            if (decision.exploration_bonus > 0.0) {
                metrics_.exploration_tasks++;
            } else {
                metrics_.exploitation_tasks++;
            }
        }
    }
    
    SchedulingDecision MakeSchedulingDecision(ScheduledTask& task) {
        SchedulingDecision decision;
        decision.task_id = task.task_id;
        decision.priority = task.priority;
        decision.pattern_id = task.pattern_id;
        
        // Check if we should explore
        Emergent::PatternSignature pattern;
        pattern.id = task.pattern_id;
        pattern.confidence = task.priority.confidence_factor;
        
        bool explore = exploration_engine_.ShouldExplore(pattern);
        
        if (explore) {
            // Spawn exploration trials
            decision.exploration_bonus = config_.exploration_weight;
            task.priority.exploration_weight = config_.exploration_weight;
            task.priority.CalculateTotal(config_);
            decision.priority = task.priority;
        }
        
        // Assign workers
        decision.assigned_workers = worker_pool_.AssignWorkers(task);
        
        if (decision.assigned_workers.empty()) {
            return decision; // Failed to assign
        }
        
        // Calculate predicted metrics
        decision.predicted_tps = CalculatePredictedTPS(task);
        decision.predicted_convergence = task.priority.confidence_factor;
        decision.predicted_success_rate = metrics_.success_rate.load();
        
        // Calculate utility
        decision.utility_score = SchedulerUtils::CalculateUtility(
            decision.predicted_convergence,
            decision.predicted_tps,
            decision.predicted_success_rate,
            static_cast<double>(decision.assigned_workers.size())
        );
        
        // Get pattern stability if available
        auto it = pattern_priorities_.find(task.pattern_id);
        if (it != pattern_priorities_.end()) {
            decision.pattern_stability = it->second.stability_factor;
        }
        
        return decision;
    }
    
    double CalculatePredictedTPS(const ScheduledTask& task) {
        // Use historical TPS if available
        if (task.pattern_id.empty()) {
            return metrics_.average_tps.load();
        }
        
        // Look up pattern-based prediction
        auto it = pattern_priorities_.find(task.pattern_id);
        if (it != pattern_priorities_.end()) {
            return it->second.total_priority * 200.0; // Scale to TPS
        }
        
        return metrics_.average_tps.load();
    }
    
    void MetricsLoop() {
        while (running_) {
            std::this_thread::sleep_for(config_.metrics_window);
            
            if (!running_) {
                break;
            }
            
            std::lock_guard<std::mutex> lock(mutex_);
            
            // Calculate average TPS from completed tasks
            double total_tps = 0.0;
            uint32_t count = 0;
            
            for (const auto& [id, task] : completed_tasks_) {
                if (task.status == ScheduledTask::Status::COMPLETED && task.success) {
                    total_tps += task.actual_tps;
                    count++;
                }
            }
            
            if (count > 0) {
                metrics_.average_tps = total_tps / count;
            }
            
            // Update worker utilization
            metrics_.worker_utilization = worker_pool_.GetWorkerUtilization();
            metrics_.active_workers = worker_pool_.GetTotalWorkers();
        }
    }
    
    // Configuration
    AdaptiveSchedulerConfig config_;
    
    // Component engines
    PatternPriorityEngine priority_engine_;
    WorkerPoolManager worker_pool_;
    ExplorationEngine exploration_engine_;
    
    // Task storage
    std::map<uint64_t, ScheduledTask> pending_tasks_;
    std::map<uint64_t, ScheduledTask> running_tasks_;
    std::map<uint64_t, ScheduledTask> completed_tasks_;
    std::map<uint64_t, SchedulingDecision> decisions_;
    std::map<std::string, TaskPriority> pattern_priorities_;
    
    // State
    std::atomic<uint64_t> next_task_id_;
    std::atomic<bool> running_;
    std::atomic<bool> shutdown_;
    std::atomic<bool> initialized_{false};
    
    // Metrics
    SchedulerMetrics metrics_;
    
    // Threading
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::thread scheduler_thread_;
    std::thread metrics_thread_;
};

// ============================================================================
// AdaptiveScheduler Public Interface
// ============================================================================

AdaptiveScheduler::AdaptiveScheduler(const AdaptiveSchedulerConfig& config)
    : pImpl(std::make_unique<Impl>(config)) {}

AdaptiveScheduler::~AdaptiveScheduler() = default;

void AdaptiveScheduler::Initialize() { pImpl->Initialize(); }
void AdaptiveScheduler::Start() { pImpl->Start(); }
void AdaptiveScheduler::Stop() { pImpl->Stop(); }
void AdaptiveScheduler::Shutdown() { pImpl->Shutdown(); }

uint64_t AdaptiveScheduler::SubmitTask(const ScheduledTask& task) {
    return pImpl->SubmitTask(task);
}

uint64_t AdaptiveScheduler::SubmitTaskFromPattern(const Emergent::PatternSignature& pattern) {
    return pImpl->SubmitTaskFromPattern(pattern);
}

void AdaptiveScheduler::CancelTask(uint64_t task_id) { pImpl->CancelTask(task_id); }

void AdaptiveScheduler::FeedPatterns(const Emergent::EmergentPatternReport& report) {
    pImpl->FeedPatterns(report);
}

void AdaptiveScheduler::FeedPattern(const Emergent::PatternSignature& pattern) {
    pImpl->FeedPattern(pattern);
}

void AdaptiveScheduler::ReportTaskCompletion(uint64_t task_id, double tps, double convergence, bool success) {
    pImpl->ReportTaskCompletion(task_id, tps, convergence, success);
}

void AdaptiveScheduler::ReportTaskFailure(uint64_t task_id, const std::string& reason) {
    pImpl->ReportTaskFailure(task_id, reason);
}

std::vector<ScheduledTask> AdaptiveScheduler::GetPendingTasks() const {
    return pImpl->GetPendingTasks();
}

std::vector<ScheduledTask> AdaptiveScheduler::GetRunningTasks() const {
    return pImpl->GetRunningTasks();
}

std::vector<ScheduledTask> AdaptiveScheduler::GetCompletedTasks() const {
    return pImpl->GetCompletedTasks();
}

SchedulingDecision AdaptiveScheduler::GetLastDecision(uint64_t task_id) const {
    return pImpl->GetLastDecision(task_id);
}

TaskPriority AdaptiveScheduler::GetTaskPriority(uint64_t task_id) const {
    return pImpl->GetTaskPriority(task_id);
}

SchedulerMetrics AdaptiveScheduler::GetMetrics() const {
    return pImpl->GetMetrics();
}

SchedulerSnapshot AdaptiveScheduler::GetSnapshot() const {
    return pImpl->GetSnapshot();
}

void AdaptiveScheduler::SetConfig(const AdaptiveSchedulerConfig& config) {
    pImpl->SetConfig(config);
}

AdaptiveSchedulerConfig AdaptiveScheduler::GetConfig() const {
    return pImpl->GetConfig();
}

void AdaptiveScheduler::Reset() { pImpl->Reset(); }
void AdaptiveScheduler::SaveState(const std::string& path) { pImpl->SaveState(path); }
void AdaptiveScheduler::LoadState(const std::string& path) { pImpl->LoadState(path); }

} // namespace Scheduler
