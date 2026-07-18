// SchedulerMetrics.cpp
// Phase C.2 — Scheduler Metrics Implementation

#include "SchedulerMetrics.hpp"
#include <sstream>
#include <iomanip>

namespace Scheduler {

// ============================================================================
// SchedulerMetrics Implementation
// ============================================================================

double SchedulerMetrics::GetThroughput() const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - start_time).count();
    
    if (elapsed <= 0) {
        return 0.0;
    }
    
    uint64_t completed = tasks_completed.load();
    return static_cast<double>(completed) / elapsed;
}

double SchedulerMetrics::GetExplorationRatio() const {
    uint64_t exploration = exploration_tasks.load();
    uint64_t exploitation = exploitation_tasks.load();
    uint64_t total = exploration + exploitation;
    
    if (total == 0) {
        return 0.0;
    }
    
    return static_cast<double>(exploration) / total;
}

SchedulerSnapshot SchedulerMetrics::GetSnapshot() const {
    SchedulerSnapshot snapshot;
    snapshot.timestamp = std::chrono::steady_clock::now();
    snapshot.tasks_submitted = tasks_submitted.load();
    snapshot.tasks_running = tasks_running.load();
    snapshot.tasks_completed = tasks_completed.load();
    snapshot.tasks_failed = tasks_failed.load();
    snapshot.average_tps = average_tps.load();
    snapshot.average_latency = average_latency.load();
    snapshot.average_convergence = average_convergence.load();
    snapshot.worker_utilization = worker_utilization.load();
    snapshot.active_workers = active_workers.load();
    snapshot.exploration_ratio = GetExplorationRatio();
    snapshot.success_rate = success_rate.load();
    
    return snapshot;
}

void SchedulerMetrics::Reset() {
    tasks_submitted = 0;
    tasks_running = 0;
    tasks_completed = 0;
    tasks_failed = 0;
    average_tps = 0.0;
    average_latency = 0.0;
    average_convergence = 0.0;
    worker_utilization = 0.0;
    active_workers = 0;
    exploration_tasks = 0;
    exploitation_tasks = 0;
    success_rate = 0.0;
    start_time = std::chrono::steady_clock::now();
}

// ============================================================================
// SchedulerSnapshot Implementation
// ============================================================================

std::string SchedulerSnapshot::ToString() const {
    std::ostringstream oss;
    
    auto time_t = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + 
        (timestamp - std::chrono::steady_clock::now()));
    
    oss << "Scheduler Snapshot @ " << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "\n";
    oss << "========================================\n";
    oss << "Tasks: " << tasks_submitted << " submitted, " 
       << tasks_running << " running, "
       << tasks_completed << " completed, "
       << tasks_failed << " failed\n";
    oss << "Performance: " << std::fixed << std::setprecision(2)
       << average_tps << " TPS, "
       << average_latency << " ms latency, "
       << average_convergence * 100.0 << "% convergence\n";
    oss << "Workers: " << active_workers << " active, "
       << worker_utilization * 100.0 << "% utilization\n";
    oss << "Exploration: " << exploration_ratio * 100.0 << "%, "
       << "Success: " << success_rate * 100.0 << "%\n";
    
    return oss.str();
}

std::map<std::string, double> SchedulerSnapshot::ToMap() const {
    std::map<std::string, double> metrics;
    
    metrics["tasks_submitted"] = static_cast<double>(tasks_submitted);
    metrics["tasks_running"] = static_cast<double>(tasks_running);
    metrics["tasks_completed"] = static_cast<double>(tasks_completed);
    metrics["tasks_failed"] = static_cast<double>(tasks_failed);
    metrics["average_tps"] = average_tps;
    metrics["average_latency"] = average_latency;
    metrics["average_convergence"] = average_convergence;
    metrics["worker_utilization"] = worker_utilization;
    metrics["active_workers"] = static_cast<double>(active_workers);
    metrics["exploration_ratio"] = exploration_ratio;
    metrics["success_rate"] = success_rate;
    
    return metrics;
}

// ============================================================================
// MetricsCollector Implementation
// ============================================================================

MetricsCollector::MetricsCollector(std::chrono::milliseconds window_size)
    : window_size_(window_size)
    , collection_active_(false) {}

void MetricsCollector::StartCollection() {
    std::lock_guard<std::mutex> lock(mutex_);
    collection_active_ = true;
    
    // Start collection thread
    collection_thread_ = std::thread(&MetricsCollector::CollectionLoop, this);
}

void MetricsCollector::StopCollection() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        collection_active_ = false;
    }
    
    cv_.notify_all();
    
    if (collection_thread_.joinable()) {
        collection_thread_.join();
    }
}

void MetricsCollector::RecordTaskSubmission(uint64_t task_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    TaskMetricRecord record;
    record.task_id = task_id;
    record.submit_time = std::chrono::steady_clock::now();
    record.status = TaskMetricRecord::Status::PENDING;
    
    task_records_[task_id] = record;
    
    // Update window
    UpdateWindow();
}

void MetricsCollector::RecordTaskStart(uint64_t task_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = task_records_.find(task_id);
    if (it != task_records_.end()) {
        it->second.start_time = std::chrono::steady_clock::now();
        it->second.status = TaskMetricRecord::Status::RUNNING;
    }
}

void MetricsCollector::RecordTaskCompletion(
    uint64_t task_id, 
    double tps, 
    double convergence,
    bool success) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = task_records_.find(task_id);
    if (it != task_records_.end()) {
        it->second.end_time = std::chrono::steady_clock::now();
        it->second.tps = tps;
        it->second.convergence = convergence;
        it->second.success = success;
        it->second.status = success 
            ? TaskMetricRecord::Status::COMPLETED 
            : TaskMetricRecord::Status::FAILED;
        
        // Calculate latency
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            it->second.end_time - it->second.start_time);
        it->second.latency_ms = static_cast<double>(duration.count());
    }
    
    UpdateWindow();
}

SchedulerMetrics MetricsCollector::GetAggregatedMetrics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    SchedulerMetrics metrics;
    metrics.start_time = window_start_;
    
    uint64_t completed_count = 0;
    uint64_t failed_count = 0;
    double total_tps = 0.0;
    double total_latency = 0.0;
    double total_convergence = 0.0;
    
    for (const auto& [id, record] : task_records_) {
        switch (record.status) {
            case TaskMetricRecord::Status::PENDING:
                metrics.tasks_submitted++;
                break;
            case TaskMetricRecord::Status::RUNNING:
                metrics.tasks_submitted++;
                metrics.tasks_running++;
                break;
            case TaskMetricRecord::Status::COMPLETED:
                metrics.tasks_submitted++;
                metrics.tasks_completed++;
                completed_count++;
                total_tps += record.tps;
                total_latency += record.latency_ms;
                total_convergence += record.convergence;
                break;
            case TaskMetricRecord::Status::FAILED:
                metrics.tasks_submitted++;
                metrics.tasks_failed++;
                failed_count++;
                break;
        }
    }
    
    // Calculate averages
    if (completed_count > 0) {
        metrics.average_tps = total_tps / completed_count;
        metrics.average_latency = total_latency / completed_count;
        metrics.average_convergence = total_convergence / completed_count;
    }
    
    // Calculate success rate
    uint64_t total_finished = completed_count + failed_count;
    if (total_finished > 0) {
        metrics.success_rate = static_cast<double>(completed_count) / total_finished;
    }
    
    return metrics;
}

std::vector<TaskMetricRecord> MetricsCollector::GetTaskHistory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<TaskMetricRecord> history;
    for (const auto& [id, record] : task_records_) {
        history.push_back(record);
    }
    
    return history;
}

void MetricsCollector::ExportToCSV(const std::string& filename) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ofstream file(filename);
    if (!file.is_open()) {
        return;
    }
    
    // Header
    file << "task_id,submit_time_ms,start_time_ms,end_time_ms,latency_ms,"
         << "tps,convergence,success,status\n";
    
    // Data
    for (const auto& [id, record] : task_records_) {
        auto submit_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            record.submit_time.time_since_epoch()).count();
        auto start_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            record.start_time.time_since_epoch()).count();
        auto end_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            record.end_time.time_since_epoch()).count();
        
        file <> id << ","
             << submit_ms << ","
             << start_ms << ","
             << end_ms << ","
             << record.latency_ms << ","
             << record.tps << ","
             << record.convergence << ","
             << (record.success ? 1 : 0) << ","
             << static_cast<int>(record.status) << "\n";
    }
}

void MetricsCollector::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    task_records_.clear();
    window_start_ = std::chrono::steady_clock::now();
}

void MetricsCollector::CollectionLoop() {
    while (collection_active_) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        cv_.wait_for(lock, window_size_, [this] {
            return !collection_active_;
        });
        
        if (!collection_active_) {
            break;
        }
        
        // Update window (remove old records)
        UpdateWindow();
    }
}

void MetricsCollector::UpdateWindow() {
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - window_size_;
    
    // Remove records outside the window
    for (auto it = task_records_.begin(); it != task_records_.end();) {
        if (it->second.end_time != std::chrono::steady_clock::time_point{} &&
            it->second.end_time < cutoff) {
            it = task_records_.erase(it);
        } else {
            ++it;
        }
    }
    
    // Update window start
    if (task_records_.empty()) {
        window_start_ = now;
    } else {
        window_start_ = cutoff;
    }
}

} // namespace Scheduler
