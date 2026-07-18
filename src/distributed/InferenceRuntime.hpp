// RawrXD Inference Runtime - Distributed Inference Coordination
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "RawrXD_RPC.hpp"
#include <memory>
#include <mutex>
#include <unordered_map>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <unordered_set>
#include <thread>

namespace RawrXD {
namespace Distributed {

// ============================================================================
// Forward Declarations
// ============================================================================

class InferenceRuntime;
class InferenceRequest;
class InferenceResponse;

// ============================================================================
// Request State
// ============================================================================

enum class RequestState {
    PENDING = 0,      // Waiting in queue
    ASSIGNED = 1,     // Assigned to worker
    RUNNING = 2,      // Actively executing
    STREAMING = 3,    // Streaming tokens
    COMPLETED = 4,    // Finished successfully
    CANCELLED = 5,    // Cancelled by client
    FAILED = 6,       // Execution failed
    TIMEOUT = 7       // Timed out
};

const char* RequestStateToString(RequestState state);

// ============================================================================
// Inference Request
// ============================================================================

struct InferenceRequest {
    uint64_t request_id;
    uint64_t client_node_id;
    
    // Model parameters
    uint32_t model_id;
    uint32_t batch_size;
    uint32_t seq_length;
    uint32_t max_tokens;
    uint32_t expert_mask;
    uint16_t priority;
    uint16_t flags;
    
    // Input data
    std::vector<uint32_t> input_tokens;
    
    // State
    std::atomic<RequestState> state{RequestState::PENDING};
    
    // Timing
    std::chrono::steady_clock::time_point enqueue_time;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point completion_time;
    
    // Execution
    uint32_t assigned_worker;
    uint64_t tokens_generated;
    
    // Callbacks
    std::function<void(const InferenceRequest&)> on_complete;
    std::function<void(uint32_t token)> on_token;
    
    InferenceRequest() = default;
    explicit InferenceRequest(const InferenceRequestPayload& payload);
    
    InferenceRequestPayload ToPayload() const;
};

// ============================================================================
// Inference Response
// ============================================================================

struct InferenceResponse {
    uint64_t request_id;
    uint8_t status;  // 0=success, 1=error, 2=cancelled
    uint32_t tokens_generated;
    uint32_t completion_time_ms;
    
    // Output tokens
    std::vector<uint32_t> output_tokens;
    
    // Error info
    uint32_t error_code;
    std::string error_message;
    
    InferenceResponse() = default;
    explicit InferenceResponse(uint64_t req_id);
};

// ============================================================================
// Stream Token
// ============================================================================

struct StreamToken {
    uint64_t request_id;
    uint32_t token_id;
    uint32_t token;
    float logprob;
    bool is_last;
    
    StreamToken() = default;
    StreamToken(uint64_t req, uint32_t tok_id, uint32_t tok, float prob, bool last);
};

// ============================================================================
// Request Queue
// ============================================================================

class RequestQueue {
public:
    RequestQueue();
    ~RequestQueue();
    
    // Queue operations
    void Enqueue(std::shared_ptr<InferenceRequest> request);
    std::shared_ptr<InferenceRequest> Dequeue();
    bool TryDequeue(std::shared_ptr<InferenceRequest>& request, std::chrono::milliseconds timeout);
    
    // Query
    size_t Size() const;
    bool Empty() const;
    void Clear();
    
    // Priority management
    void SetPriority(uint64_t request_id, uint16_t priority);
    
private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    
    // Priority queue: higher priority first, then FIFO within same priority
    struct PriorityCompare {
        bool operator()(const std::shared_ptr<InferenceRequest>& a,
                       const std::shared_ptr<InferenceRequest>& b) const;
    };
    std::priority_queue<std::shared_ptr<InferenceRequest>,
                       std::vector<std::shared_ptr<InferenceRequest>>,
                       PriorityCompare> queue_;
    
    std::atomic<bool> shutdown_{false};
};

// ============================================================================
// Request Tracker
// ============================================================================

class RequestTracker {
public:
    RequestTracker();
    ~RequestTracker();
    
    // Request management
    std::shared_ptr<InferenceRequest> CreateRequest(const InferenceRequestPayload& payload);
    std::shared_ptr<InferenceRequest> GetRequest(uint64_t request_id);
    bool RemoveRequest(uint64_t request_id);
    
    // State updates
    bool UpdateState(uint64_t request_id, RequestState new_state);
    bool AssignWorker(uint64_t request_id, uint32_t worker_id);
    
    // Query
    std::vector<std::shared_ptr<InferenceRequest>> GetActiveRequests() const;
    std::vector<std::shared_ptr<InferenceRequest>> GetRequestsByState(RequestState state) const;
    size_t GetActiveCount() const;
    
    // Completion tracking
    std::future<InferenceResponse> GetFuture(uint64_t request_id);
    void CompleteRequest(uint64_t request_id, const InferenceResponse& response);
    void FailRequest(uint64_t request_id, uint32_t error_code, const std::string& message);
    void CancelRequest(uint64_t request_id);
    
private:
    mutable std::mutex mutex_;
    std::unordered_map<uint64_t, std::shared_ptr<InferenceRequest>> requests_;
    std::unordered_map<uint64_t, std::promise<InferenceResponse>> promises_;
    
    std::atomic<uint64_t> next_request_id_{1};
};

// ============================================================================
// Load Balancer
// ============================================================================

struct WorkerLoad {
    uint32_t worker_id;
    uint32_t active_requests;
    uint32_t queue_depth;
    double cpu_percent;
    double memory_gb;
    double tps_capacity;
    int64_t last_heartbeat_ms;
    
    double GetScore() const;
};

class LoadBalancer {
public:
    LoadBalancer();
    ~LoadBalancer();
    
    // Worker registration
    void RegisterWorker(uint32_t worker_id, const WorkerLoad& load);
    void UnregisterWorker(uint32_t worker_id);
    void UpdateWorkerLoad(uint32_t worker_id, const WorkerLoad& load);
    
    // Selection
    uint32_t SelectWorker(const InferenceRequest& request);
    std::vector<uint32_t> GetHealthyWorkers() const;
    
    // Query
    WorkerLoad GetWorkerLoad(uint32_t worker_id) const;
    std::vector<WorkerLoad> GetAllLoads() const;
    
    // Health check
    void MarkWorkerHealthy(uint32_t worker_id);
    void MarkWorkerUnhealthy(uint32_t worker_id);
    std::vector<uint32_t> GetUnhealthyWorkers() const;
    
private:
    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, WorkerLoad> workers_;
    std::unordered_set<uint32_t> unhealthy_workers_;
};

// ============================================================================
// Inference Runtime
// ============================================================================

class InferenceRuntime {
public:
    struct Config {
        size_t max_concurrent_requests = 100;
        size_t max_queue_depth = 1000;
        std::chrono::milliseconds default_timeout{30000};
        std::chrono::milliseconds stream_timeout{60000};
        bool enable_priority_scheduling = true;
        bool enable_load_balancing = true;
    };
    
    explicit InferenceRuntime(const Config& config);
    ~InferenceRuntime();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsRunning() const { return running_.load(); }
    
    // Request submission
    uint64_t SubmitRequest(const InferenceRequestPayload& payload);
    std::future<InferenceResponse> SubmitRequestAsync(const InferenceRequestPayload& payload);
    
    // Request control
    bool CancelRequest(uint64_t request_id);
    RequestState GetRequestState(uint64_t request_id);
    
    // Response handling
    void SubmitResponse(uint64_t request_id, const InferenceResponse& response);
    void SubmitStreamToken(uint64_t request_id, const StreamToken& token);
    
    // Worker management
    void RegisterWorker(uint32_t worker_id, const WorkerLoad& load);
    void UpdateWorkerLoad(uint32_t worker_id, const WorkerLoad& load);
    void UnregisterWorker(uint32_t worker_id);
    
    // Statistics
    struct Stats {
        uint64_t requests_submitted;
        uint64_t requests_completed;
        uint64_t requests_failed;
        uint64_t requests_cancelled;
        uint64_t tokens_generated;
        double avg_latency_ms;
        double avg_tps;
    };
    Stats GetStats() const;
    void ResetStats();
    
    // Accessors
    RequestQueue& GetQueue() { return queue_; }
    RequestTracker& GetTracker() { return tracker_; }
    LoadBalancer& GetLoadBalancer() { return load_balancer_; }
    
    // Callbacks for integration with backends
    using TokenCallback = std::function<void(uint64_t, uint32_t)>;
    using CompleteCallback = std::function<void(uint64_t, const std::vector<uint32_t>&)>;
    using ErrorCallback = std::function<void(uint64_t, const std::string&)>;
    
    void SetTokenCallback(TokenCallback cb) { token_callback_ = cb; }
    void SetCompleteCallback(CompleteCallback cb) { complete_callback_ = cb; }
    void SetErrorCallback(ErrorCallback cb) { error_callback_ = cb; }
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    RequestQueue queue_;
    RequestTracker tracker_;
    LoadBalancer load_balancer_;
    
    // Worker threads
    std::vector<std::thread> workers_;
    void WorkerLoop();
    void ProcessRequest(std::shared_ptr<InferenceRequest> request);
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Stats stats_{};
    
    // Shutdown
    std::atomic<bool> shutdown_{false};
    
    // Callbacks
    TokenCallback token_callback_;
    CompleteCallback complete_callback_;
    ErrorCallback error_callback_;
};

} // namespace Distributed
} // namespace RawrXD
