// worker_node.cpp
// Batch 14: Distributed Worker Node
//
// Worker node that executes benchmarks on behalf of coordinator
// Features: Heartbeat, job execution, local caching, graceful shutdown

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>
#include <chrono>
#include <functional>

namespace Benchmark {
namespace Distributed {

// Worker configuration
struct WorkerConfig {
    std::string coordinator_address = "localhost:9090";
    std::string node_id;
    std::string hostname;
    int port = 9091;
    int capacity = 4;              // Max concurrent benchmarks
    int heartbeat_interval_ms = 30000;
    std::string results_cache_dir = "./worker_cache";
    std::vector<std::string> capabilities;
    bool graceful_shutdown = true;
    int shutdown_timeout_ms = 30000;
};

// Job execution result
struct JobResult {
    std::string job_id;
    bool success;
    std::string result_json;
    std::string error_message;
    int64_t execution_time_ms;
    int64_t memory_peak_mb;
};

// Worker node
class WorkerNode {
public:
    explicit WorkerNode(const WorkerConfig& config = WorkerConfig())
        : config_(config), running_(false), current_load_(0) {
        if (config_.node_id.empty()) {
            config_.node_id = GenerateNodeID();
        }
        if (config_.hostname.empty()) {
            config_.hostname = GetHostname();
        }
    }

    ~WorkerNode() {
        Stop();
    }

    // Start worker
    bool Start() {
        if (running_) return true;

        running_ = true;

        // Register with coordinator
        if (!RegisterWithCoordinator()) {
            running_ = false;
            return false;
        }

        // Start heartbeat thread
        heartbeat_thread_ = std::thread(&WorkerNode::HeartbeatLoop, this);

        // Start job processor
        processor_thread_ = std::thread(&WorkerNode::ProcessorLoop, this);

        // Start result reporter
        reporter_thread_ = std::thread(&WorkerNode::ReporterLoop, this);

        return true;
    }

    // Stop worker
    void Stop() {
        if (!running_) return;

        running_ = false;
        cv_.notify_all();

        // Wait for current jobs to complete (graceful shutdown)
        if (config_.graceful_shutdown) {
            auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(config_.shutdown_timeout_ms);

            std::unique_lock<std::mutex> lock(jobs_mutex_);
            cv_.wait_until(lock, deadline, [this] {
                return current_load_ == 0;
            });
        }

        // Unregister from coordinator
        UnregisterFromCoordinator();

        if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
        if (processor_thread_.joinable()) processor_thread_.join();
        if (reporter_thread_.joinable()) reporter_thread_.join();
    }

    // Receive job from coordinator
    bool ReceiveJob(const DistributedJob& job) {
        if (!running_) return false;

        std::lock_guard<std::mutex> lock(jobs_mutex_);

        if (current_load_ >= config_.capacity) {
            return false;  // At capacity
        }

        pending_jobs_.push(job);
        cv_.notify_one();
        return true;
    }

    // Get node info
    NodeInfo GetNodeInfo() const {
        NodeInfo info;
        info.node_id = config_.node_id;
        info.hostname = config_.hostname;
        info.address = config_.hostname;
        info.port = config_.port;
        info.capacity = config_.capacity;
        info.current_load = current_load_.load();
        info.capabilities = config_.capabilities;
        info.active = running_;
        info.cpu_usage = GetCPUUsage();
        info.memory_usage = GetMemoryUsage();
        info.version = "1.0.0";
        return info;
    }

    // Get current status
    struct WorkerStatus {
        bool running;
        int current_load;
        int capacity;
        int pending_jobs;
        int completed_jobs;
        int failed_jobs;
        double cpu_usage;
        double memory_usage;
    };

    WorkerStatus GetStatus() const {
        WorkerStatus status;
        status.running = running_;
        status.current_load = current_load_.load();
        status.capacity = config_.capacity;
        status.cpu_usage = GetCPUUsage();
        status.memory_usage = GetMemoryUsage();

        std::lock_guard<std::mutex> lock(jobs_mutex_);
        status.pending_jobs = pending_jobs_.size();
        status.completed_jobs = completed_jobs_.size();
        status.failed_jobs = failed_jobs_.size();

        return status;
    }

    // Cancel running job
    bool CancelJob(const std::string& job_id) {
        std::lock_guard<std::mutex> lock(jobs_mutex_);

        // Check pending jobs
        std::queue<DistributedJob> temp;
        bool found = false;

        while (!pending_jobs_.empty()) {
            auto job = pending_jobs_.front();
            pending_jobs_.pop();

            if (job.job_id == job_id) {
                found = true;
                continue;  // Skip this job
            }
            temp.push(job);
        }

        pending_jobs_ = std::move(temp);

        // If running, signal cancellation
        if (running_jobs_.find(job_id) != running_jobs_.end()) {
            // In production: Signal cancellation to running benchmark
            found = true;
        }

        return found;
    }

private:
    WorkerConfig config_;
    std::atomic<bool> running_;
    std::atomic<int> current_load_;

    std::queue<DistributedJob> pending_jobs_;
    std::map<std::string, DistributedJob> running_jobs_;
    std::queue<JobResult> completed_jobs_;
    std::queue<JobResult> failed_jobs_;
    mutable std::mutex jobs_mutex_;
    std::condition_variable cv_;

    std::thread heartbeat_thread_;
    std::thread processor_thread_;
    std::thread reporter_thread_;

    void HeartbeatLoop() {
        while (running_) {
            SendHeartbeat();

            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.heartbeat_interval_ms));
        }
    }

    void ProcessorLoop() {
        while (running_) {
            std::unique_lock<std::mutex> lock(jobs_mutex_);
            cv_.wait(lock, [this] { return !pending_jobs_.empty() || !running_; });

            if (!running_) break;

            while (!pending_jobs_.empty() && current_load_ < config_.capacity) {
                DistributedJob job = pending_jobs_.front();
                pending_jobs_.pop();

                running_jobs_[job.job_id] = job;
                current_load_++;

                lock.unlock();

                // Execute job in separate thread
                std::thread executor([this, job]() {
                    ExecuteJob(job);
                });
                executor.detach();

                lock.lock();
            }
        }
    }

    void ReporterLoop() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            if (!running_) break;

            std::queue<JobResult> to_report;

            {
                std::lock_guard<std::mutex> lock(jobs_mutex_);
                std::swap(to_report, completed_jobs_);
            }

            while (!to_report.empty()) {
                ReportResult(to_report.front());
                to_report.pop();
            }
        }
    }

    void ExecuteJob(const DistributedJob& job) {
        auto start_time = std::chrono::steady_clock::now();
        int64_t memory_before = GetMemoryUsageMB();

        JobResult result;
        result.job_id = job.job_id;

        try {
            // Execute benchmark
            // In production: Call actual benchmark runner
            result.success = true;
            result.result_json = R"({"status": "completed", "tps": 45.2})";
            result.execution_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start_time).count();

        } catch (const std::exception& e) {
            result.success = false;
            result.error_message = e.what();
        }

        // Calculate memory usage
        int64_t memory_after = GetMemoryUsageMB();
        result.memory_peak_mb = memory_after - memory_before;

        // Update state
        {
            std::lock_guard<std::mutex> lock(jobs_mutex_);
            running_jobs_.erase(job.job_id);
            current_load_--;

            if (result.success) {
                completed_jobs_.push(result);
            } else {
                failed_jobs_.push(result);
            }
        }

        // Cache result locally
        CacheResult(result);
    }

    void ReportResult(const JobResult& result) {
        // In production: Send result to coordinator via HTTP/TCP
    }

    void CacheResult(const JobResult& result) {
        // In production: Save to local cache directory
    }

    bool RegisterWithCoordinator() {
        // In production: HTTP POST to coordinator
        return true;
    }

    void UnregisterFromCoordinator() {
        // In production: HTTP POST to coordinator
    }

    void SendHeartbeat() {
        // In production: HTTP POST to coordinator
    }

    std::string GenerateNodeID() {
        return "worker_" + std::to_string(GetTimestamp()) + "_" +
               std::to_string(rand() % 10000);
    }

    std::string GetHostname() {
        // In production: Get actual hostname
        return "localhost";
    }

    double GetCPUUsage() {
        // In production: Get actual CPU usage
        return 25.0;
    }

    double GetMemoryUsage() {
        // In production: Get actual memory usage
        return 50.0;
    }

    int64_t GetMemoryUsageMB() {
        // In production: Get actual memory usage
        return 1024;
    }

    int64_t GetTimestamp() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

// Worker node manager (for managing multiple local workers)
class WorkerManager {
public:
    // Start multiple workers
    void StartWorkers(int count, const WorkerConfig& base_config) {
        for (int i = 0; i < count; ++i) {
            WorkerConfig config = base_config;
            config.port = base_config.port + i;
            config.node_id = base_config.node_id + "_" + std::to_string(i);

            auto worker = std::make_unique<WorkerNode>(config);
            if (worker->Start()) {
                workers_.push_back(std::move(worker));
            }
        }
    }

    // Stop all workers
    void StopAll() {
        for (auto& worker : workers_) {
            worker->Stop();
        }
        workers_.clear();
    }

    // Get status of all workers
    std::vector<WorkerNode::WorkerStatus> GetAllStatus() const {
        std::vector<WorkerNode::WorkerStatus> statuses;
        for (const auto& worker : workers_) {
            statuses.push_back(worker->GetStatus());
        }
        return statuses;
    }

private:
    std::vector<std::unique_ptr<WorkerNode>> workers_;
};

} // namespace Distributed
} // namespace Benchmark
