// scheduler.cpp
// Layer 0: Credit-Based Scheduler Implementation

#include "scheduler.h"
#include <algorithm>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <vector>

namespace rawrxd::scheduler {

// ═══════════════════════════════════════════════════════════════════════════════
// Internal Implementation
// ═══════════════════════════════════════════════════════════════════════════════

struct NodeState {
    NodeId id;
    NodeType type;
    Priority prio;
    std::chrono::steady_clock::time_point enqueue_time;
    std::chrono::steady_clock::time_point start_time;
    TokenCredits credits_used;
    bool active;
};

struct TypeState {
    TokenCredits available_credits;
    TokenCredits total_credits;
    TokenCredits credit_limit;
    TimeSlice time_slice_limit;
    std::chrono::milliseconds latency_slo{100};
    size_t max_queue_depth{1000};
    
    // Metrics
    std::atomic<uint64_t> allocation_count{0};
    std::atomic<uint64_t> rejection_count{0};
    std::vector<std::chrono::microseconds> recent_latencies;
    std::mutex latency_mutex;
};

class SchedulerImpl {
public:
    SchedulerImpl() = default;
    
    std::map<NodeType, TypeState> type_states_;
    std::map<NodeId, NodeState> node_states_;
    
    // Priority queue: lower priority value = higher priority
    std::priority_queue<
        std::pair<Priority, NodeId>,
        std::vector<std::pair<Priority, NodeId>>,
        std::greater<std::pair<Priority, NodeId>>
    > queue_;
    
    mutable std::mutex mutex_;
    std::atomic<bool> initialized_{false};
    
    // Global pressure tracking
    std::atomic<size_t> total_active_nodes_{0};
    std::atomic<size_t> total_queue_depth_{0};
    static constexpr size_t MAX_TOTAL_ACTIVE = 10000;
    
    // Statistics
    std::atomic<uint64_t> total_allocations_{0};
    std::atomic<uint64_t> total_rejections_{0};
    std::atomic<uint64_t> total_preemptions_{0};
    std::atomic<uint64_t> total_yields_{0};
};

// ═══════════════════════════════════════════════════════════════════════════════
// CreditBasedScheduler Implementation
// ═══════════════════════════════════════════════════════════════════════════════

CreditBasedScheduler::CreditBasedScheduler() 
    : impl_(std::make_unique<SchedulerImpl>()) {
    
    // Initialize default type states
    impl_->type_states_[NodeType::Inference] = TypeState{};
    impl_->type_states_[NodeType::Embedding] = TypeState{};
    impl_->type_states_[NodeType::Tokenization] = TypeState{};
    impl_->type_states_[NodeType::Detokenization] = TypeState{};
    impl_->type_states_[NodeType::Scheduling] = TypeState{};
}

CreditBasedScheduler::~CreditBasedScheduler() = default;

std::optional<CreditAllocation> CreditBasedScheduler::AllocateCredits(
    NodeType type,
    Priority prio,
    TokenCredits requested) {
    
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->type_states_.find(type);
    if (it == impl_->type_states_.end()) {
        return std::nullopt;
    }
    
    auto& state = it->second;
    
    // Check global pressure
    if (impl_->total_active_nodes_.load() >= SchedulerImpl::MAX_TOTAL_ACTIVE) {
        impl_->total_rejections_++;
        return std::nullopt;
    }
    
    // Check credit availability
    if (state.available_credits < requested && prio > Priority::Critical) {
        // Non-critical work gets rejected if no credits
        state.rejection_count++;
        impl_->total_rejections_++;
        return std::nullopt;
    }
    
    // Allocate credits
    TokenCredits granted = std::min(requested, state.available_credits);
    state.available_credits -= granted;
    state.allocation_count++;
    impl_->total_allocations_++;
    
    CreditAllocation alloc;
    alloc.granted = granted;
    alloc.reserved = granted / 2;  // 50% guaranteed
    alloc.burst = granted * 2;     // 2x burst allowed
    alloc.replenish_interval = std::chrono::milliseconds(100);
    alloc.throttled = (granted < requested);
    
    return alloc;
}

void CreditBasedScheduler::ReplenishCredits(NodeType type, TokenCredits amount) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->type_states_.find(type);
    if (it != impl_->type_states_.end()) {
        it->second.available_credits = std::min(
            it->second.available_credits + amount,
            it->second.credit_limit
        );
    }
}

void CreditBasedScheduler::ReturnCredits(NodeType type, TokenCredits amount) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->type_states_.find(type);
    if (it != impl_->type_states_.end()) {
        it->second.available_credits = std::min(
            it->second.available_credits + amount,
            it->second.credit_limit
        );
    }
}

std::optional<TimeAllocation> CreditBasedScheduler::AllocateTimeSlice(
    NodeId id,
    Priority prio,
    TimeSlice requested) {
    
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    // Check if node exists
    auto it = impl_->node_states_.find(id);
    if (it == impl_->node_states_.end()) {
        return std::nullopt;
    }
    
    auto& node = it->second;
    auto& type_state = impl_->type_states_[node.type];
    
    // Limit time slice
    TimeSlice granted = std::min(requested, type_state.time_slice_limit);
    
    // Critical priority gets more time
    if (prio == Priority::Critical) {
        granted = granted * 2;
    }
    
    node.start_time = std::chrono::steady_clock::now();
    node.active = true;
    impl_->total_active_nodes_++;
    
    TimeAllocation alloc;
    alloc.granted = granted;
    alloc.deadline = node.start_time + granted;
    alloc.preemptible = (prio > Priority::High);
    
    return alloc;
}

bool CreditBasedScheduler::ShouldPreempt(NodeId current, NodeId candidate) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto current_it = impl_->node_states_.find(current);
    auto candidate_it = impl_->node_states_.find(candidate);
    
    if (current_it == impl_->node_states_.end() || candidate_it == impl_->node_states_.end()) {
        return false;
    }
    
    // Candidate preempts if it has higher priority (lower value)
    return candidate_it->second.prio < current_it->second.prio;
}

void CreditBasedScheduler::YieldTimeSlice(NodeId id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->node_states_.find(id);
    if (it != impl_->node_states_.end() && it->second.active) {
        it->second.active = false;
        impl_->total_active_nodes_--;
        impl_->total_yields_++;
    }
}

bool CreditBasedScheduler::Enqueue(NodeId id, NodeType type, Priority prio) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto& type_state = impl_->type_states_[type];
    
    // Check queue depth limit
    if (impl_->total_queue_depth_.load() >= type_state.max_queue_depth) {
        return false;
    }
    
    // Create node state
    NodeState state;
    state.id = id;
    state.type = type;
    state.prio = prio;
    state.enqueue_time = std::chrono::steady_clock::now();
    state.active = false;
    
    impl_->node_states_[id] = state;
    impl_->queue_.push({prio, id});
    impl_->total_queue_depth_++;
    
    return true;
}

std::optional<NodeId> CreditBasedScheduler::Dequeue() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    if (impl_->queue_.empty()) {
        return std::nullopt;
    }
    
    auto [prio, id] = impl_->queue_.top();
    impl_->queue_.pop();
    impl_->total_queue_depth_--;
    
    return id;
}

std::optional<NodeId> CreditBasedScheduler::Peek() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    if (impl_->queue_.empty()) {
        return std::nullopt;
    }
    
    return impl_->queue_.top().second;
}

QueueMetrics CreditBasedScheduler::GetQueueMetrics(NodeType type) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    QueueMetrics metrics;
    metrics.depth = impl_->total_queue_depth_.load();
    
    auto it = impl_->type_states_.find(type);
    if (it != impl_->type_states_.end()) {
        metrics.max_depth = it->second.max_queue_depth;
        
        std::lock_guard<std::mutex> latency_lock(it->second.latency_mutex);
        if (!it->second.recent_latencies.empty()) {
            auto sum = std::chrono::microseconds::zero();
            for (const auto& lat : it->second.recent_latencies) {
                sum += lat;
            }
            metrics.avg_wait_time = sum / it->second.recent_latencies.size();
            
            // Simple p99 (not exact but fast)
            auto sorted = it->second.recent_latencies;
            std::sort(sorted.begin(), sorted.end());
            size_t p99_idx = sorted.size() * 99 / 100;
            metrics.p99_wait_time = sorted[p99_idx];
        }
    }
    
    metrics.utilization = static_cast<float>(impl_->total_active_nodes_.load()) / 
                          SchedulerImpl::MAX_TOTAL_ACTIVE;
    
    return metrics;
}

void CreditBasedScheduler::SetLatencySLO(NodeType type, std::chrono::milliseconds target) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->type_states_.find(type);
    if (it != impl_->type_states_.end()) {
        it->second.latency_slo = target;
    }
}

bool CreditBasedScheduler::IsSLOMet(NodeType type) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->type_states_.find(type);
    if (it == impl_->type_states_.end()) {
        return true;
    }
    
    std::lock_guard<std::mutex> latency_lock(it->second.latency_mutex);
    if (it->second.recent_latencies.empty()) {
        return true;
    }
    
    auto avg = std::accumulate(it->second.recent_latencies.begin(),
                                it->second.recent_latencies.end(),
                                std::chrono::microseconds::zero()) / 
               it->second.recent_latencies.size();
    
    return avg <= it->second.latency_slo;
}

std::chrono::microseconds CreditBasedScheduler::GetCurrentLatency(NodeType type) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->type_states_.find(type);
    if (it == impl_->type_states_.end()) {
        return std::chrono::microseconds::zero();
    }
    
    std::lock_guard<std::mutex> latency_lock(it->second.latency_mutex);
    if (it->second.recent_latencies.empty()) {
        return std::chrono::microseconds::zero();
    }
    
    auto sum = std::chrono::microseconds::zero();
    for (const auto& lat : it->second.recent_latencies) {
        sum += lat;
    }
    return sum / it->second.recent_latencies.size();
}

bool CreditBasedScheduler::IsUnderPressure() const {
    return GetPressureLevel() > 0.8f;
}

float CreditBasedScheduler::GetPressureLevel() const {
    return static_cast<float>(impl_->total_active_nodes_.load()) / 
           SchedulerImpl::MAX_TOTAL_ACTIVE;
}

float CreditBasedScheduler::GetRecommendedThrottle() const {
    float pressure = GetPressureLevel();
    if (pressure < 0.5f) return 0.0f;
    if (pressure > 0.9f) return 1.0f;
    return (pressure - 0.5f) * 2.0f;
}

CreditBasedScheduler::Statistics CreditBasedScheduler::GetStatistics() const {
    Statistics stats;
    stats.total_allocations = impl_->total_allocations_.load();
    stats.total_rejections = impl_->total_rejections_.load();
    stats.total_preemptions = impl_->total_preemptions_.load();
    stats.total_yields = impl_->total_yields_.load();
    stats.avg_queue_depth = impl_->total_queue_depth_.load();
    
    // Compute average latency across all types
    double total_latency = 0.0;
    size_t latency_count = 0;
    
    for (const auto& [type, state] : impl_->type_states_) {
        std::lock_guard<std::mutex> lock(state.latency_mutex);
        for (const auto& lat : state.recent_latencies) {
            total_latency += lat.count();
            latency_count++;
        }
    }
    
    stats.avg_latency_ms = latency_count > 0 ? total_latency / latency_count / 1000.0 : 0.0;
    stats.p99_latency_ms = stats.avg_latency_ms; // Simplified
    
    return stats;
}

void CreditBasedScheduler::ResetStatistics() {
    impl_->total_allocations_ = 0;
    impl_->total_rejections_ = 0;
    impl_->total_preemptions_ = 0;
    impl_->total_yields_ = 0;
}

void CreditBasedScheduler::SetMaxQueueDepth(NodeType type, size_t max_depth) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->type_states_.find(type);
    if (it != impl_->type_states_.end()) {
        it->second.max_queue_depth = max_depth;
    }
}

void CreditBasedScheduler::SetCreditLimit(NodeType type, TokenCredits limit) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->type_states_.find(type);
    if (it != impl_->type_states_.end()) {
        it->second.credit_limit = limit;
        it->second.total_credits = limit;
        it->second.available_credits = limit;
    }
}

void CreditBasedScheduler::SetTimeSliceLimit(NodeType type, TimeSlice limit) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->type_states_.find(type);
    if (it != impl_->type_states_.end()) {
        it->second.time_slice_limit = limit;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Global Instance
// ═══════════════════════════════════════════════════════════════════════════════

static std::unique_ptr<CreditBasedScheduler> g_scheduler;
static std::once_flag g_init_flag;

CreditBasedScheduler& GetScheduler() {
    std::call_once(g_init_flag, []() {
        g_scheduler = std::make_unique<CreditBasedScheduler>();
    });
    return *g_scheduler;
}

bool InitializeScheduler(const std::string& config_path) {
    // For now, just initialize with defaults
    // In production, parse config file
    GetScheduler();
    return true;
}

void ShutdownScheduler() {
    g_scheduler.reset();
}

} // namespace rawrxd::scheduler
