// AdaptiveScheduler.hpp
// Phase C.2 Batch 1/5 — Pattern-Aware Scheduler Core
// Consumes emergent patterns to drive execution behavior changes

#ifndef ADAPTIVE_SCHEDULER_HPP
#define ADAPTIVE_SCHEDULER_HPP

#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <queue>
#include <thread>
#include "../emergent/EmergentPatterns.hpp"
#include "SchedulerPolicy.hpp"
#include "SchedulerMetrics.hpp"

namespace Scheduler {

// Forward declarations
class AdaptiveScheduler;
class WorkerPool;
class TaskRouter;
class ExplorationEngine;

// ============================================================================
// Scheduler Configuration
// ============================================================================

struct AdaptiveSchedulerConfig {
    // Pattern weights for priority calculation
    double stability_weight = 0.35;      // Weight for pattern stability
    double confidence_weight = 0.30;     // Weight for pattern confidence
    double significance_weight = 0.20;   // Weight for pattern significance
    double exploration_weight = 0.15;   // Weight for exploration bonus
    
    // Resource allocation
    uint32_t min_workers = 2;
    uint32_t max_workers = 16;
    uint32_t default_workers = 4;
    double worker_scale_factor = 1.5;    // Workers = base * factor^priority
    
    // Exploration vs Exploitation
    double exploration_rate = 0.10;       // Base exploration probability
    double exploration_decay = 0.995;     // Decay per successful execution
    double min_exploration_rate = 0.01;  // Floor for exploration
    
    // Dynamic weights
    double convergence_threshold = 0.80; // Switch to exploitation above this
    double instability_threshold = 0.30; // Increase exploration below this
    
    // Timing
    std::chrono::milliseconds scheduling_interval{100};
    std::chrono::milliseconds metrics_window{5000};
    
    // SEG integration
    bool enable_dynamic_weights = true;
    double edge_weight_learning_rate = 0.1;
    double edge_weight_decay = 0.99;
};

// ============================================================================
// Task Priority
// ============================================================================

struct TaskPriority {
    double execution_weight;    // Base execution priority (0-1)
    double resource_weight;     // Resource allocation weight (0-1)
    double exploration_weight;  // Exploration bonus (0-1)
    double total_priority;      // Combined priority score
    
    // Pattern-derived factors
    double stability_factor;
    double confidence_factor;
    double significance_factor;
    
    TaskPriority() 
        : execution_weight(0.5), resource_weight(0.5), exploration_weight(0.0),
          total_priority(0.5), stability_factor(0.5), confidence_factor(0.5),
          significance_factor(0.5) {}
    
    void CalculateTotal(const AdaptiveSchedulerConfig& config);
};

// ============================================================================
// Scheduled Task
// ============================================================================

struct ScheduledTask {
    uint64_t task_id;
    std::string task_type;
    TaskPriority priority;
    
    // Pattern association
    std::string pattern_id;
    Emergent::PatternType pattern_type;
    
    // Resource requirements
    uint32_t min_workers;
    uint32_t max_workers;
    uint64_t estimated_tokens;
    
    // Execution tracking
    std::chrono::steady_clock::time_point submit_time;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    
    // Status
    enum class Status { PENDING, RUNNING, COMPLETED, FAILED, CANCELLED };
    Status status;
    
    // Results
    double actual_tps;
    double convergence_rate;
    bool success;
    
    ScheduledTask() 
        : task_id(0), min_workers(1), max_workers(4), estimated_tokens(100),
          status(Status::PENDING), actual_tps(0.0), convergence_rate(0.0),
          success(false) {}
};

// ============================================================================
// Worker Assignment
// ============================================================================

struct WorkerAssignment {
    uint32_t worker_id;
    uint64_t task_id;
    double assigned_load;
    std::chrono::steady_clock::time_point assignment_time;
    
    // Performance tracking
    double historical_tps;
    double reliability_score;
    uint32_t successful_tasks;
    uint32_t failed_tasks;
    
    WorkerAssignment() 
        : worker_id(0), task_id(0), assigned_load(0.0), historical_tps(0.0),
          reliability_score(0.5), successful_tasks(0), failed_tasks(0) {}
};

// ============================================================================
// Scheduling Decision
// ============================================================================

struct SchedulingDecision {
    uint64_t task_id;
    std::vector<uint32_t> assigned_workers;
    TaskPriority priority;
    
    // Decision rationale
    std::string pattern_id;
    double pattern_stability;
    double exploration_bonus;
    
    // Predicted metrics
    double predicted_tps;
    double predicted_convergence;
    double predicted_success_rate;
    
    // Utility calculation
    double utility_score;
    std::map<std::string, double> utility_components;
    
    SchedulingDecision() 
        : task_id(0), pattern_stability(0.0), exploration_bonus(0.0),
          predicted_tps(0.0), predicted_convergence(0.0),
          predicted_success_rate(0.0), utility_score(0.0) {}
};

// ============================================================================
// Pattern-Driven Priority Engine
// ============================================================================

class PatternPriorityEngine {
public:
    PatternPriorityEngine(const AdaptiveSchedulerConfig& config);
    
    // Calculate priority from emergent pattern
    TaskPriority CalculatePriority(
        const Emergent::PatternSignature& pattern,
        const SchedulerMetrics& metrics);
    
    TaskPriority CalculatePriority(
        const Emergent::HarmonicAttractor& attractor,
        const SchedulerMetrics& metrics);
    
    TaskPriority CalculatePriority(
        const Emergent::SwarmCluster& cluster,
        const SchedulerMetrics& metrics);
    
    TaskPriority CalculatePriority(
        const Emergent::GraphMotif& motif,
        const SchedulerMetrics& metrics);
    
    TaskPriority CalculatePriority(
        const Emergent::StabilityBasin& basin,
        const SchedulerMetrics& metrics);
    
    // Batch processing
    std::map<std::string, TaskPriority> CalculatePriorities(
        const Emergent::EmergentPatternReport& report,
        const SchedulerMetrics& metrics);
    
    // Update weights based on historical performance
    void UpdateWeights(const std::map<std::string, double>& task_performance);
    
    // Get current configuration
    AdaptiveSchedulerConfig GetConfig() const;
    void SetConfig(const AdaptiveSchedulerConfig& config);
    
private:
    AdaptiveSchedulerConfig config_;
    mutable std::mutex mutex_;
    
    // Historical performance tracking
    std::map<std::string, std::vector<double>> task_history_;
    
    double CalculateStabilityFactor(double stability);
    double CalculateConfidenceFactor(double confidence);
    double CalculateSignificanceFactor(double significance);
    double CalculateExplorationFactor(const std::string& pattern_id);
};

// ============================================================================
// Worker Pool Manager
// ============================================================================

class WorkerPoolManager {
public:
    WorkerPoolManager(const AdaptiveSchedulerConfig& config);
    
    // Worker lifecycle
    void InitializeWorkers(uint32_t count);
    void ScaleWorkers(uint32_t target_count);
    void Shutdown();
    
    // Assignment
    std::vector<uint32_t> AssignWorkers(const ScheduledTask& task);
    void ReleaseWorkers(uint64_t task_id);
    void UpdateWorkerPerformance(uint32_t worker_id, double tps, bool success);
    
    // Query
    uint32_t GetAvailableWorkers() const;
    uint32_t GetTotalWorkers() const;
    double GetWorkerUtilization() const;
    std::vector<WorkerAssignment> GetWorkerAssignments() const;
    
    // Auto-scaling
    void EvaluateScalingNeeds(const SchedulerMetrics& metrics);
    bool ShouldScaleUp() const;
    bool ShouldScaleDown() const;
    
private:
    AdaptiveSchedulerConfig config_;
    mutable std::mutex mutex_;
    
    std::map<uint32_t, WorkerAssignment> workers_;
    std::map<uint32_t, bool> worker_available_;
    uint32_t next_worker_id_;
    
    // Scaling state
    std::chrono::steady_clock::time_point last_scale_time_;
    uint32_t scale_up_count_;
    uint32_t scale_down_count_;
};

// ============================================================================
// Exploration vs Exploitation Engine
// ============================================================================

class ExplorationEngine {
public:
    ExplorationEngine(const AdaptiveSchedulerConfig& config);
    
    // Decision making
    bool ShouldExplore(const Emergent::PatternSignature& pattern);
    bool ShouldExploit(const Emergent::PatternSignature& pattern);
    
    // Get exploration parameters
    double GetExplorationRate() const;
    double GetExplorationRateForPattern(const std::string& pattern_id) const;
    
    // Update based on results
    void ReportSuccess(const std::string& pattern_id, double tps);
    void ReportFailure(const std::string& pattern_id);
    void ReportConvergence(const std::string& pattern_id, double convergence);
    
    // Parallel trial spawning
    std::vector<ScheduledTask> SpawnExplorationTrials(
        const ScheduledTask& base_task,
        uint32_t trial_count);
    
    // Adaptive decay
    void UpdateExplorationRate();
    void ResetExplorationRate();
    
private:
    AdaptiveSchedulerConfig config_;
    mutable std::mutex mutex_;
    
    double current_exploration_rate_;
    std::map<std::string, double> pattern_exploration_rates_;
    std::map<std::string, uint32_t> pattern_success_count_;
    std::map<std::string, uint32_t> pattern_trial_count_;
    
    std::chrono::steady_clock::time_point last_update_;
};

// ============================================================================
// SEG Integration
// ============================================================================

class SEGSchedulerIntegration {
public:
    // Dynamic edge weight adjustment
    static void UpdateEdgeWeights(
        SEG::SovereignExecutionGraph& graph,
        const std::map<std::pair<uint64_t, uint64_t>, double>& success_rates,
        double learning_rate);
    
    // Get recommended execution path
    static std::vector<uint64_t> GetRecommendedPath(
        const SEG::SovereignExecutionGraph& graph,
        uint64_t start_node,
        uint64_t end_node);
    
    // Calculate path utility
    static double CalculatePathUtility(
        const SEG::SovereignExecutionGraph& graph,
        const std::vector<uint64_t>& path,
        const SchedulerMetrics& metrics);
    
    // Export scheduling decisions to SEG
    static void ApplySchedulingDecision(
        SEG::SovereignExecutionGraph& graph,
        const SchedulingDecision& decision);
};

// ============================================================================
// Main Adaptive Scheduler
// ============================================================================

class AdaptiveScheduler {
public:
    AdaptiveScheduler(const AdaptiveSchedulerConfig& config = AdaptiveSchedulerConfig{});
    ~AdaptiveScheduler();
    
    // Lifecycle
    void Initialize();
    void Start();
    void Stop();
    void Shutdown();
    
    // Task submission
    uint64_t SubmitTask(const ScheduledTask& task);
    uint64_t SubmitTaskFromPattern(const Emergent::PatternSignature& pattern);
    void CancelTask(uint64_t task_id);
    
    // Pattern-driven scheduling
    void FeedPatterns(const Emergent::EmergentPatternReport& report);
    void FeedPattern(const Emergent::PatternSignature& pattern);
    
    // Execution feedback
    void ReportTaskCompletion(uint64_t task_id, double tps, double convergence, bool success);
    void ReportTaskFailure(uint64_t task_id, const std::string& reason);
    
    // Query interface
    std::vector<ScheduledTask> GetPendingTasks() const;
    std::vector<ScheduledTask> GetRunningTasks() const;
    std::vector<ScheduledTask> GetCompletedTasks() const;
    
    SchedulingDecision GetLastDecision(uint64_t task_id) const;
    TaskPriority GetTaskPriority(uint64_t task_id) const;
    
    // Metrics
    SchedulerMetrics GetMetrics() const;
    SchedulerSnapshot GetSnapshot() const;
    
    // Configuration
    void SetConfig(const AdaptiveSchedulerConfig& config);
    AdaptiveSchedulerConfig GetConfig() const;
    
    // State management
    void Reset();
    void SaveState(const std::string& path);
    void LoadState(const std::string& path);
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace SchedulerUtils {
    // Utility calculation
    double CalculateUtility(
        double convergence,
        double throughput,
        double reliability,
        double resource_cost);
    
    // Resource allocation
    uint32_t CalculateWorkerAllocation(
        double priority,
        uint32_t min_workers,
        uint32_t max_workers,
        double scale_factor);
    
    // Performance prediction
    double PredictTPS(
        const std::vector<double>& historical_tps,
        const Emergent::PatternSignature& pattern);
    
    double PredictConvergence(
        const std::vector<double>& historical_convergence,
        const Emergent::PatternSignature& pattern);
    
    // Statistical utilities
    double ExponentialMovingAverage(
        const std::vector<double>& values,
        double alpha = 0.3);
    
    double ConfidenceInterval(
        const std::vector<double>& values,
        double confidence = 0.95);
}

} // namespace Scheduler

#endif // ADAPTIVE_SCHEDULER_HPP
