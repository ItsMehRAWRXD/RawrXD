// coordinator.cpp
// Batch 14: Distributed Benchmark Coordinator
//
// Central coordinator for multi-node benchmark execution
// Features: Job distribution, result aggregation, fault tolerance

#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <queue>
#include <thread>
#include <condition_variable>
#include <chrono>

namespace Benchmark {
namespace Distributed {

// Job status
enum class JobStatus {
    PENDING,
    SCHEDULED,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED
};

// Distributed job
struct DistributedJob {
    std::string job_id;
    std::string benchmark_id;
    std::string config_json;
    int priority;
    int64_t created_at;
    int64_t started_at;
    int64_t completed_at;
    JobStatus status;
    std::string assigned_node;
    std::string result_json;
    std::string error_message;
    int retry_count;
    int max_retries;
};

// Node information
struct NodeInfo {
    std::string node_id;
    std::string hostname;
    std::string address;
    int port;
    int64_t registered_at;
    int64_t last_heartbeat;
    int capacity;           // Max concurrent jobs
    int current_load;       // Current running jobs
    std::vector<std::string> capabilities;
    bool active;
    double cpu_usage;
    double memory_usage;
    std::string version;
};

// Coordinator configuration
struct CoordinatorConfig {
    std::string bind_address = "0.0.0.0";
    int port = 9090;
    int heartbeat_interval_ms = 30000;
    int node_timeout_ms = 60000;
    int max_retries = 3;
    bool enable_fault_tolerance = true;
    std::string results_directory = "./distributed_results";
};

// Distributed coordinator
class Coordinator {
public:
    explicit Coordinator(const CoordinatorConfig& config = CoordinatorConfig())
        : config_(config), running_(false), next_job_id_(1) {}

    ~Coordinator() {
        Stop();
    }

    // Start coordinator
    bool Start() {
        if (running_) return true;

        running_ = true;

        // Start network listener
        listener_thread_ = std::thread(&Coordinator::ListenerLoop, this);

        // Start heartbeat monitor
        heartbeat_thread_ = std::thread(&Coordinator::HeartbeatMonitor, this);

        // Start job scheduler
        scheduler_thread_ = std::thread(&Coordinator::SchedulerLoop, this);

        return true;
    }

    // Stop coordinator
    void Stop() {
        running_ = false;
        cv_.notify_all();

        if (listener_thread_.joinable()) listener_thread_.join();
        if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
        if (scheduler_thread_.joinable()) scheduler_thread_.join();
    }

    // Submit new distributed job
    std::string SubmitJob(const std::string& benchmark_id,
                          const std::string& config_json,
                          int priority = 5) {
        DistributedJob job;
        job.job_id = GenerateJobID();
        job.benchmark_id = benchmark_id;
        job.config_json = config_json;
        job.priority = priority;
        job.created_at = GetTimestamp();
        job.status = JobStatus::PENDING;
        job.retry_count = 0;
        job.max_retries = config_.max_retries;

        {
            std::lock_guard<std::mutex> lock(jobs_mutex_);
            pending_jobs_.push(job);
            jobs_[job.job_id] = job;
        }

        cv_.notify_one();
        return job.job_id;
    }

    // Register worker node
    bool RegisterNode(const NodeInfo& node) {
        std::lock_guard<std::mutex> lock(nodes_mutex_);

        nodes_[node.node_id] = node;
        return true;
    }

    // Unregister worker node
    bool UnregisterNode(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(nodes_mutex_);

        auto it = nodes_.find(node_id);
        if (it != nodes_.end()) {
            // Reassign any running jobs
            ReassignNodeJobs(node_id);
            nodes_.erase(it);
            return true;
        }
        return false;
    }

    // Update node heartbeat
    bool Heartbeat(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(nodes_mutex_);

        auto it = nodes_.find(node_id);
        if (it != nodes_.end()) {
            it->second.last_heartbeat = GetTimestamp();
            return true;
        }
        return false;
    }

    // Report job completion
    bool ReportCompletion(const std::string& job_id,
                          const std::string& result_json,
                          bool success,
                          const std::string& error = "") {
        std::lock_guard<std::mutex> lock(jobs_mutex_);

        auto it = jobs_.find(job_id);
        if (it == jobs_.end()) return false;

        DistributedJob& job = it->second;
        job.completed_at = GetTimestamp();
        job.result_json = result_json;
        job.error_message = error;
        job.status = success ? JobStatus::COMPLETED : JobStatus::FAILED;

        // Update node load
        if (!job.assigned_node.empty()) {
            std::lock_guard<std::mutex> node_lock(nodes_mutex_);
            auto node_it = nodes_.find(job.assigned_node);
            if (node_it != nodes_.end()) {
                node_it->second.current_load--;
            }
        }

        // Save result
        SaveJobResult(job);

        return true;
    }

    // Get job status
    std::optional<DistributedJob> GetJobStatus(const std::string& job_id) {
        std::lock_guard<std::mutex> lock(jobs_mutex_);

        auto it = jobs_.find(job_id);
        if (it != jobs_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Get active nodes
    std::vector<NodeInfo> GetActiveNodes() {
        std::lock_guard<std::mutex> lock(nodes_mutex_);

        std::vector<NodeInfo> active;
        for (const auto& [id, node] : nodes_) {
            if (IsNodeActive(node)) {
                active.push_back(node);
            }
        }
        return active;
    }

    // Get cluster statistics
    struct ClusterStats {
        int total_nodes;
        int active_nodes;
        int total_jobs;
        int pending_jobs;
        int running_jobs;
        int completed_jobs;
        int failed_jobs;
        double avg_cpu_usage;
        double avg_memory_usage;
    };

    ClusterStats GetStats() {
        ClusterStats stats = {};

        {
            std::lock_guard<std::mutex> lock(nodes_mutex_);
            stats.total_nodes = nodes_.size();

            double total_cpu = 0.0, total_mem = 0.0;
            for (const auto& [id, node] : nodes_) {
                if (IsNodeActive(node)) {
                    stats.active_nodes++;
                    total_cpu += node.cpu_usage;
                    total_mem += node.memory_usage;
                }
            }

            if (stats.active_nodes > 0) {
                stats.avg_cpu_usage = total_cpu / stats.active_nodes;
                stats.avg_memory_usage = total_mem / stats.active_nodes;
            }
        }

        {
            std::lock_guard<std::mutex> lock(jobs_mutex_);
            stats.total_jobs = jobs_.size();

            for (const auto& [id, job] : jobs_) {
                switch (job.status) {
                    case JobStatus::PENDING: stats.pending_jobs++; break;
                    case JobStatus::RUNNING: stats.running_jobs++; break;
                    case JobStatus::COMPLETED: stats.completed_jobs++; break;
                    case JobStatus::FAILED: stats.failed_jobs++; break;
                    default: break;
                }
            }
        }

        return stats;
    }

    // Cancel job
    bool CancelJob(const std::string& job_id) {
        std::lock_guard<std::mutex> lock(jobs_mutex_);

        auto it = jobs_.find(job_id);
        if (it == jobs_.end()) return false;

        if (it->second.status == JobStatus::PENDING) {
            it->second.status = JobStatus::CANCELLED;
            return true;
        }

        // If running, send cancel to node
        if (it->second.status == JobStatus::RUNNING) {
            // In production: Send cancel command to worker
            it->second.status = JobStatus::CANCELLED;
            return true;
        }

        return false;
    }

private:
    CoordinatorConfig config_;
    std::atomic<bool> running_;
    std::atomic<int> next_job_id_;

    std::map<std::string, DistributedJob> jobs_;
    std::priority_queue<DistributedJob, std::vector<DistributedJob>,
        std::function<bool(const DistributedJob&, const DistributedJob&)>> pending_jobs_;
    mutable std::mutex jobs_mutex_;

    std::map<std::string, NodeInfo> nodes_;
    mutable std::mutex nodes_mutex_;

    std::thread listener_thread_;
    std::thread heartbeat_thread_;
    std::thread scheduler_thread_;
    std::condition_variable cv_;

    void ListenerLoop() {
        // In production: TCP/HTTP server for node communication
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    void HeartbeatMonitor() {
        while (running_) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.heartbeat_interval_ms));

            if (!running_) break;

            CheckNodeHealth();
        }
    }

    void SchedulerLoop() {
        while (running_) {
            std::unique_lock<std::mutex> lock(jobs_mutex_);
            cv_.wait(lock, [this] { return !pending_jobs_.empty() || !running_; });

            if (!running_) break;

            // Schedule pending jobs
            while (!pending_jobs_.empty()) {
                DistributedJob job = pending_jobs_.top();
                pending_jobs_.pop();

                lock.unlock();

                if (ScheduleJob(job)) {
                    lock.lock();
                    jobs_[job.job_id].status = JobStatus::SCHEDULED;
                } else {
                    // Re-queue if no nodes available
                    lock.lock();
                    if (job.status == JobStatus::PENDING) {
                        pending_jobs_.push(job);
                    }
                    break;
                }

                lock.lock();
            }
        }
    }

    bool ScheduleJob(DistributedJob& job) {
        std::lock_guard<std::mutex> lock(nodes_mutex_);

        // Find best node (least loaded, active)
        std::string best_node;
        int best_load = INT_MAX;

        for (auto& [id, node] : nodes_) {
            if (!IsNodeActive(node)) continue;
            if (node.current_load >= node.capacity) continue;

            // Check capabilities
            // In production: Match benchmark requirements with node capabilities

            if (node.current_load < best_load) {
                best_load = node.current_load;
                best_node = id;
            }
        }

        if (best_node.empty()) {
            return false;
        }

        // Assign job to node
        job.assigned_node = best_node;
        job.started_at = GetTimestamp();
        job.status = JobStatus::RUNNING;

        nodes_[best_node].current_load++;

        // Send job to node
        SendJobToNode(job, best_node);

        return true;
    }

    void CheckNodeHealth() {
        std::lock_guard<std::mutex> lock(nodes_mutex_);

        auto now = GetTimestamp();

        for (auto& [id, node] : nodes_) {
            if (now - node.last_heartbeat > config_.node_timeout_ms / 1000) {
                // Node timed out
                node.active = false;

                if (config_.enable_fault_tolerance) {
                    ReassignNodeJobs(id);
                }
            }
        }
    }

    void ReassignNodeJobs(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(jobs_mutex_);

        for (auto& [id, job] : jobs_) {
            if (job.assigned_node == node_id &&
                job.status == JobStatus::RUNNING) {
                // Mark for retry
                if (job.retry_count < job.max_retries) {
                    job.retry_count++;
                    job.status = JobStatus::PENDING;
                    job.assigned_node.clear();
                    pending_jobs_.push(job);
                } else {
                    job.status = JobStatus::FAILED;
                    job.error_message = "Node timeout after " +
                                       std::to_string(job.max_retries) + " retries";
                }
            }
        }

        cv_.notify_one();
    }

    void SendJobToNode(const DistributedJob& job, const std::string& node_id) {
        // In production: Send via TCP/HTTP to worker node
    }

    void SaveJobResult(const DistributedJob& job) {
        // In production: Save to database or file
    }

    bool IsNodeActive(const NodeInfo& node) const {
        return node.active &&
               (GetTimestamp() - node.last_heartbeat) < config_.node_timeout_ms / 1000;
    }

    std::string GenerateJobID() {
        return "job_" + std::to_string(GetTimestamp()) + "_" +
               std::to_string(next_job_id_++);
    }

    int64_t GetTimestamp() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

} // namespace Distributed
} // namespace Benchmark
