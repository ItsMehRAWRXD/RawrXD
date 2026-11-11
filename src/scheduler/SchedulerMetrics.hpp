// SchedulerMetrics.hpp
// Phase C.2 — Scheduler Metrics and Telemetry

#ifndef SCHEDULER_METRICS_HPP
#define SCHEDULER_METRICS_HPP

#include <chrono>
#include <map>
#include <vector>
#include <atomic>

namespace Scheduler {

// Real-time metrics
struct SchedulerMetrics {
    // Task counts
    std::atomic<uint64_t> tasks_submitted{0};
    std::atomic<uint64_t> tasks_running{0};
    std::atomic<uint64_t> tasks_completed{0};
    std::atomic<uint64_t> tasks_failed{0};
    std::atomic<uint64_t> tasks_cancelled{0};
    
    // Performance metrics
    std::atomic<double> average_tps{0.0};
    std::atomic<double> average_convergence{0.0};
    std::atomic<double> average_latency_ms{0.0};
    std::atomic<double> success_rate{0.0};
    
    // Resource metrics
    std::atomic<uint32_t> active_workers{0};
    std::atomic<uint32_t> available_workers{0};
    std::atomic<double> worker_utilization{0.0};
    std::atomic<double> memory_usage_mb{0.0};
    
    // Pattern metrics
    std::atomic<uint32_t> patterns_detected{0};
    std::atomic<uint32_t> patterns_utilized{0};
    std::atomic<double> pattern_confidence_avg{0.0};
    
    // Exploration metrics
    std::atomic<uint64_t> exploration_tasks{0};
    std::atomic<uint64_t> exploitation_tasks{0};
    std::atomic<double> exploration_rate{0.1};
    
    // Timing
    std::chrono::steady_clock::time_point last_update;
    std::chrono::steady_clock::time_point start_time;
    
    SchedulerMetrics() : last_update(std::chrono::steady_clock::now()),
                         start_time(std::chrono::steady_clock::now()) {}
    
    // Calculate derived metrics
    double GetThroughput() const;
    double GetEfficiency() const;
    double GetExplorationRatio() const;
};

// Metrics snapshot for export
struct SchedulerSnapshot {
    std::chrono::steady_clock::time_point timestamp;
    SchedulerMetrics metrics;
    std::map<std::string, double> custom_metrics;
    std::vector<std::string> active_patterns;
    std::map<uint64_t, SchedulingDecision> recent_decisions;
};

// Metrics collector
class MetricsCollector {
public:
    void RecordTaskSubmission(uint64_t task_id);
    void RecordTaskStart(uint64_t task_id);
    void RecordTaskCompletion(uint64_t task_id, double tps, double convergence);
    void RecordTaskFailure(uint64_t task_id, const std::string& reason);
    void RecordPatternUtilization(const std::string& pattern_id);
    void RecordWorkerAssignment(uint32_t worker_id, uint64_t task_id);
    
    SchedulerMetrics GetCurrentMetrics() const;
    SchedulerSnapshot GetSnapshot() const;
    std::vector<SchedulerSnapshot> GetHistory(uint32_t count) const;
    
    void Reset();
    void ExportToFile(const std::string& path) const;
    
private:
    mutable std::mutex mutex_;
    SchedulerMetrics current_metrics_;
    std::vector<SchedulerSnapshot> history_;
    static constexpr uint32_t MAX_HISTORY = 1000;
};

} // namespace Scheduler

#endif // SCHEDULER_METRICS_HPP
