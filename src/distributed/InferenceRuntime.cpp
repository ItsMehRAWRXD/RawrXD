// RawrXD Inference Runtime - Distributed Inference Coordination
// Copyright (c) 2026 RawrXD Team

#include "InferenceRuntime.hpp"
#include <algorithm>
#include <sstream>

namespace RawrXD {
namespace Distributed {

// ============================================================================
// Request State
// ============================================================================

const char* RequestStateToString(RequestState state) {
    switch (state) {
        case RequestState::PENDING: return "PENDING";
        case RequestState::ASSIGNED: return "ASSIGNED";
        case RequestState::RUNNING: return "RUNNING";
        case RequestState::STREAMING: return "STREAMING";
        case RequestState::COMPLETED: return "COMPLETED";
        case RequestState::CANCELLED: return "CANCELLED";
        case RequestState::FAILED: return "FAILED";
        case RequestState::TIMEOUT: return "TIMEOUT";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Inference Request
// ============================================================================

InferenceRequest::InferenceRequest(const InferenceRequestPayload& payload)
    : request_id(payload.request_id)
    , model_id(payload.model_id)
    , batch_size(payload.batch_size)
    , seq_length(payload.seq_length)
    , max_tokens(0)  // Not in payload, set separately
    , expert_mask(payload.expert_mask)
    , priority(payload.priority)
    , flags(payload.flags)
    , state(RequestState::PENDING)
    , enqueue_time(std::chrono::steady_clock::now())
    , assigned_worker(0)
    , tokens_generated(0) {
}

InferenceRequestPayload InferenceRequest::ToPayload() const {
    InferenceRequestPayload payload{};
    payload.request_id = request_id;
    payload.model_id = model_id;
    payload.batch_size = batch_size;
    payload.seq_length = seq_length;
    payload.expert_mask = expert_mask;
    payload.priority = priority;
    payload.flags = flags;
    return payload;
}

// ============================================================================
// Inference Response
// ============================================================================

InferenceResponse::InferenceResponse(uint64_t req_id)
    : request_id(req_id)
    , status(0)
    , tokens_generated(0)
    , completion_time_ms(0)
    , error_code(0) {
}

// ============================================================================
// Stream Token
// ============================================================================

StreamToken::StreamToken(uint64_t req, uint32_t tok_id, uint32_t tok, float prob, bool last)
    : request_id(req)
    , token_id(tok_id)
    , token(tok)
    , logprob(prob)
    , is_last(last) {
}

// ============================================================================
// Request Queue
// ============================================================================

RequestQueue::RequestQueue() = default;
RequestQueue::~RequestQueue() {
    Clear();
}

bool RequestQueue::PriorityCompare::operator()(
    const std::shared_ptr<InferenceRequest>& a,
    const std::shared_ptr<InferenceRequest>& b) const {
    // Higher priority first
    if (a->priority != b->priority) {
        return a->priority < b->priority;
    }
    // Then FIFO (earlier enqueue time first)
    return a->enqueue_time > b->enqueue_time;
}

void RequestQueue::Enqueue(std::shared_ptr<InferenceRequest> request) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(request);
    }
    cv_.notify_one();
}

std::shared_ptr<InferenceRequest> RequestQueue::Dequeue() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] { return !queue_.empty() || shutdown_.load(); });
    
    if (shutdown_.load() && queue_.empty()) {
        return nullptr;
    }
    
    auto request = queue_.top();
    queue_.pop();
    return request;
}

bool RequestQueue::TryDequeue(std::shared_ptr<InferenceRequest>& request, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    if (!cv_.wait_for(lock, timeout, [this] { return !queue_.empty() || shutdown_.load(); })) {
        return false;
    }
    
    if (shutdown_.load() && queue_.empty()) {
        return false;
    }
    
    request = queue_.top();
    queue_.pop();
    return true;
}

size_t RequestQueue::Size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

bool RequestQueue::Empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
}

void RequestQueue::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    shutdown_.store(true);
    while (!queue_.empty()) {
        queue_.pop();
    }
    cv_.notify_all();
}

void RequestQueue::SetPriority(uint64_t request_id, uint16_t priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Note: Priority queue doesn't support updating priority in-place
    // Would need to rebuild queue or use different data structure
    // For now, this is a no-op
    (void)request_id;
    (void)priority;
}

// ============================================================================
// Request Tracker
// ============================================================================

RequestTracker::RequestTracker() = default;
RequestTracker::~RequestTracker() = default;

std::shared_ptr<InferenceRequest> RequestTracker::CreateRequest(const InferenceRequestPayload& payload) {
    auto request = std::make_shared<InferenceRequest>(payload);
    request->request_id = next_request_id_.fetch_add(1);
    request->state = RequestState::PENDING;
    
    std::lock_guard<std::mutex> lock(mutex_);
    requests_[request->request_id] = request;
    
    // Create promise for async completion
    promises_[request->request_id] = std::promise<InferenceResponse>();
    
    return request;
}

std::shared_ptr<InferenceRequest> RequestTracker::GetRequest(uint64_t request_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = requests_.find(request_id);
    if (it != requests_.end()) {
        return it->second;
    }
    return nullptr;
}

bool RequestTracker::RemoveRequest(uint64_t request_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    requests_.erase(request_id);
    promises_.erase(request_id);
    return true;
}

bool RequestTracker::UpdateState(uint64_t request_id, RequestState new_state) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = requests_.find(request_id);
    if (it == requests_.end()) {
        return false;
    }
    
    it->second->state.store(new_state);
    
    if (new_state == RequestState::RUNNING) {
        it->second->start_time = std::chrono::steady_clock::now();
    } else if (new_state == RequestState::COMPLETED || 
               new_state == RequestState::FAILED ||
               new_state == RequestState::CANCELLED) {
        it->second->completion_time = std::chrono::steady_clock::now();
    }
    
    return true;
}

bool RequestTracker::AssignWorker(uint64_t request_id, uint32_t worker_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = requests_.find(request_id);
    if (it == requests_.end()) {
        return false;
    }
    
    it->second->assigned_worker = worker_id;
    it->second->state.store(RequestState::ASSIGNED);
    return true;
}

std::vector<std::shared_ptr<InferenceRequest>> RequestTracker::GetActiveRequests() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<InferenceRequest>> active;
    
    for (const auto& [id, req] : requests_) {
        auto state = req->state.load();
        if (state == RequestState::PENDING || 
            state == RequestState::ASSIGNED ||
            state == RequestState::RUNNING ||
            state == RequestState::STREAMING) {
            active.push_back(req);
        }
    }
    
    return active;
}

std::vector<std::shared_ptr<InferenceRequest>> RequestTracker::GetRequestsByState(RequestState state) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<InferenceRequest>> result;
    
    for (const auto& [id, req] : requests_) {
        if (req->state.load() == state) {
            result.push_back(req);
        }
    }
    
    return result;
}

size_t RequestTracker::GetActiveCount() const {
    return GetActiveRequests().size();
}

std::future<InferenceResponse> RequestTracker::GetFuture(uint64_t request_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return promises_[request_id].get_future();
}

void RequestTracker::CompleteRequest(uint64_t request_id, const InferenceResponse& response) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto req_it = requests_.find(request_id);
    if (req_it != requests_.end()) {
        req_it->second->state.store(RequestState::COMPLETED);
        req_it->second->completion_time = std::chrono::steady_clock::now();
    }
    
    auto prom_it = promises_.find(request_id);
    if (prom_it != promises_.end()) {
        prom_it->second.set_value(response);
    }
}

void RequestTracker::FailRequest(uint64_t request_id, uint32_t error_code, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto req_it = requests_.find(request_id);
    if (req_it != requests_.end()) {
        req_it->second->state.store(RequestState::FAILED);
        req_it->second->completion_time = std::chrono::steady_clock::now();
    }
    
    InferenceResponse response(request_id);
    response.status = 1;  // Error
    response.error_code = error_code;
    response.error_message = message;
    
    auto prom_it = promises_.find(request_id);
    if (prom_it != promises_.end()) {
        prom_it->second.set_value(response);
    }
}

void RequestTracker::CancelRequest(uint64_t request_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto req_it = requests_.find(request_id);
    if (req_it != requests_.end()) {
        req_it->second->state.store(RequestState::CANCELLED);
        req_it->second->completion_time = std::chrono::steady_clock::now();
    }
    
    InferenceResponse response(request_id);
    response.status = 2;  // Cancelled
    
    auto prom_it = promises_.find(request_id);
    if (prom_it != promises_.end()) {
        prom_it->second.set_value(response);
    }
}

// ============================================================================
// Load Balancer
// ============================================================================

double WorkerLoad::GetScore() const {
    // Lower score = better worker
    // Consider: active requests, queue depth, CPU, memory, TPS capacity
    double score = active_requests * 10.0 + queue_depth * 5.0;
    score += cpu_percent * 2.0;
    score -= tps_capacity * 0.1;  // Higher TPS = lower score (better)
    
    // Penalize stale heartbeats
    if (last_heartbeat_ms > 5000) {
        score += 1000.0;  // Heavy penalty for stale workers
    }
    
    return score;
}

LoadBalancer::LoadBalancer() = default;
LoadBalancer::~LoadBalancer() = default;

void LoadBalancer::RegisterWorker(uint32_t worker_id, const WorkerLoad& load) {
    std::lock_guard<std::mutex> lock(mutex_);
    workers_[worker_id] = load;
}

void LoadBalancer::UnregisterWorker(uint32_t worker_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    workers_.erase(worker_id);
    unhealthy_workers_.erase(worker_id);
}

void LoadBalancer::UpdateWorkerLoad(uint32_t worker_id, const WorkerLoad& load) {
    std::lock_guard<std::mutex> lock(mutex_);
    workers_[worker_id] = load;
}

uint32_t LoadBalancer::SelectWorker(const InferenceRequest& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint32_t best_worker = 0;
    double best_score = std::numeric_limits<double>::max();
    
    for (const auto& [id, load] : workers_) {
        // Skip unhealthy workers
        if (unhealthy_workers_.count(id) > 0) {
            continue;
        }
        
        // Skip workers that don't have capacity
        if (load.queue_depth >= 100) {
            continue;
        }
        
        double score = load.GetScore();
        
        // Consider expert affinity if MoE
        if (request.expert_mask != 0) {
            // Would check if worker has required experts
            // For now, no penalty
        }
        
        if (score < best_score) {
            best_score = score;
            best_worker = id;
        }
    }
    
    return best_worker;
}

std::vector<uint32_t> LoadBalancer::GetHealthyWorkers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<uint32_t> healthy;
    
    for (const auto& [id, load] : workers_) {
        if (unhealthy_workers_.count(id) == 0) {
            healthy.push_back(id);
        }
    }
    
    return healthy;
}

WorkerLoad LoadBalancer::GetWorkerLoad(uint32_t worker_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = workers_.find(worker_id);
    if (it != workers_.end()) {
        return it->second;
    }
    return WorkerLoad{};
}

std::vector<WorkerLoad> LoadBalancer::GetAllLoads() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<WorkerLoad> loads;
    
    for (const auto& [id, load] : workers_) {
        loads.push_back(load);
    }
    
    return loads;
}

void LoadBalancer::MarkWorkerHealthy(uint32_t worker_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    unhealthy_workers_.erase(worker_id);
}

void LoadBalancer::MarkWorkerUnhealthy(uint32_t worker_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    unhealthy_workers_.insert(worker_id);
}

std::vector<uint32_t> LoadBalancer::GetUnhealthyWorkers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<uint32_t>(unhealthy_workers_.begin(), unhealthy_workers_.end());
}

// ============================================================================
// Inference Runtime
// ============================================================================

InferenceRuntime::InferenceRuntime(const Config& config)
    : config_(config) {
}

InferenceRuntime::~InferenceRuntime() {
    Shutdown();
}

bool InferenceRuntime::Initialize() {
    if (running_.exchange(true)) {
        return false;  // Already running
    }
    
    // Start worker threads
    size_t num_workers = std::max(1u, std::thread::hardware_concurrency());
    for (size_t i = 0; i < num_workers; ++i) {
        workers_.emplace_back(&InferenceRuntime::WorkerLoop, this);
    }
    
    return true;
}

void InferenceRuntime::Shutdown() {
    if (!running_.exchange(false)) {
        return;
    }
    
    shutdown_.store(true);
    queue_.Clear();
    
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
}

uint64_t InferenceRuntime::SubmitRequest(const InferenceRequestPayload& payload) {
    if (!running_.load()) {
        return 0;  // Runtime not running
    }
    
    auto request = tracker_.CreateRequest(payload);
    queue_.Enqueue(request);
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.requests_submitted++;
    }
    
    return request->request_id;
}

std::future<InferenceResponse> InferenceRuntime::SubmitRequestAsync(const InferenceRequestPayload& payload) {
    uint64_t request_id = SubmitRequest(payload);
    if (request_id == 0) {
        // Return a failed future
        std::promise<InferenceResponse> promise;
        promise.set_value(InferenceResponse{0});
        return promise.get_future();
    }
    
    return tracker_.GetFuture(request_id);
}

bool InferenceRuntime::CancelRequest(uint64_t request_id) {
    auto request = tracker_.GetRequest(request_id);
    if (!request) {
        return false;
    }
    
    auto state = request->state.load();
    if (state == RequestState::COMPLETED || 
        state == RequestState::FAILED ||
        state == RequestState::CANCELLED) {
        return false;  // Already terminal
    }
    
    tracker_.CancelRequest(request_id);
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.requests_cancelled++;
    }
    
    return true;
}

RequestState InferenceRuntime::GetRequestState(uint64_t request_id) {
    auto request = tracker_.GetRequest(request_id);
    if (!request) {
        return RequestState::FAILED;
    }
    return request->state.load();
}

void InferenceRuntime::SubmitResponse(uint64_t request_id, const InferenceResponse& response) {
    tracker_.CompleteRequest(request_id, response);
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        if (response.status == 0) {
            stats_.requests_completed++;
            stats_.tokens_generated += response.tokens_generated;
        } else {
            stats_.requests_failed++;
        }
    }
}

void InferenceRuntime::SubmitStreamToken(uint64_t request_id, const StreamToken& token) {
    auto request = tracker_.GetRequest(request_id);
    if (!request) {
        return;
    }
    
    if (request->on_token) {
        request->on_token(token.token);
    }
    
    request->tokens_generated++;
    
    if (token.is_last) {
        InferenceResponse response(request_id);
        response.status = 0;  // Success
        response.tokens_generated = request->tokens_generated;
        SubmitResponse(request_id, response);
    }
}

void InferenceRuntime::RegisterWorker(uint32_t worker_id, const WorkerLoad& load) {
    load_balancer_.RegisterWorker(worker_id, load);
}

void InferenceRuntime::UpdateWorkerLoad(uint32_t worker_id, const WorkerLoad& load) {
    load_balancer_.UpdateWorkerLoad(worker_id, load);
}

void InferenceRuntime::UnregisterWorker(uint32_t worker_id) {
    load_balancer_.UnregisterWorker(worker_id);
}

void InferenceRuntime::WorkerLoop() {
    while (!shutdown_.load()) {
        std::shared_ptr<InferenceRequest> request;
        if (!queue_.TryDequeue(request, std::chrono::milliseconds(100))) {
            continue;
        }
        
        if (!request) {
            continue;
        }
        
        ProcessRequest(request);
    }
}

void InferenceRuntime::ProcessRequest(std::shared_ptr<InferenceRequest> request) {
    // Update state to running
    tracker_.UpdateState(request->request_id, RequestState::RUNNING);
    
    // Select worker using load balancer
    uint32_t worker_id = load_balancer_.SelectWorker(*request);
    if (worker_id == 0) {
        // No available workers
        tracker_.FailRequest(request->request_id, 1, "No available workers");
        return;
    }
    
    tracker_.AssignWorker(request->request_id, worker_id);
    
    // In a real implementation, this would dispatch to the actual inference engine
    // For now, we simulate successful completion
    
    // Simulate token generation
    request->state.store(RequestState::STREAMING);
    
    for (uint32_t i = 0; i < 10; ++i) {
        if (request->state.load() == RequestState::CANCELLED) {
            return;
        }
        
        StreamToken token(request->request_id, i, i + 100, 0.9f, i == 9);
        SubmitStreamToken(request->request_id, token);
        
        // Simulate generation time
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

InferenceRuntime::Stats InferenceRuntime::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void InferenceRuntime::ResetStats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = Stats{};
}

} // namespace Distributed
} // namespace RawrXD
