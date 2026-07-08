// router.cpp
// Layer 1: Capability Router Implementation

#include "router.h"
#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <random>

namespace rawrxd::router {

// ═══════════════════════════════════════════════════════════════════════════════
// Internal Implementation
// ═══════════════════════════════════════════════════════════════════════════════

struct BackendState {
    BackendInfo info;
    std::vector<std::chrono::microseconds> recent_latencies;
    std::atomic<uint64_t> success_count{0};
    std::atomic<uint64_t> failure_count{0};
    std::atomic<uint64_t> route_count{0};
    std::mutex latency_mutex;
};

class RouterImpl {
public:
    std::map<BackendId, std::unique_ptr<BackendState>> backends_;
    mutable std::mutex mutex_;
    
    // Configuration
    RoutingStrategy default_strategy_ = RoutingStrategy::LatencyOptimized;
    float latency_weight_ = 0.4f;
    float cost_weight_ = 0.2f;
    float reliability_weight_ = 0.4f;
    
    // Statistics
    std::atomic<uint64_t> total_routes_{0};
    std::atomic<uint64_t> successful_routes_{0};
    std::atomic<uint64_t> failed_routes_{0};
    std::atomic<uint64_t> fallback_routes_{0};
    std::atomic<double> total_routing_time_us_{0.0};
};

// ═══════════════════════════════════════════════════════════════════════════════
// CapabilityRouter Implementation
// ═══════════════════════════════════════════════════════════════════════════════

CapabilityRouter::CapabilityRouter() 
    : impl_(std::make_unique<RouterImpl>()) {
}

CapabilityRouter::~CapabilityRouter() = default;

bool CapabilityRouter::RegisterBackend(const BackendInfo& info) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    if (impl_->backends_.find(info.id) != impl_->backends_.end()) {
        return false; // Already exists
    }
    
    auto state = std::make_unique<BackendState>();
    state->info = info;
    impl_->backends_[info.id] = std::move(state);
    
    return true;
}

void CapabilityRouter::UnregisterBackend(BackendId id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->backends_.erase(id);
}

void CapabilityRouter::UpdateBackendMetrics(BackendId id, const BackendInfo& metrics) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->backends_.find(id);
    if (it != impl_->backends_.end()) {
        // Preserve statistics, update info
        it->second->info.state = metrics.state;
        it->second->info.avg_latency = metrics.avg_latency;
        it->second->info.p99_latency = metrics.p99_latency;
        it->second->info.success_rate = metrics.success_rate;
        it->second->info.current_load = metrics.current_load;
        it->second->info.memory_available = metrics.memory_available;
    }
}

std::optional<BackendInfo> CapabilityRouter::GetBackendInfo(BackendId id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->backends_.find(id);
    if (it != impl_->backends_.end()) {
        return it->second->info;
    }
    
    return std::nullopt;
}

std::vector<BackendId> CapabilityRouter::ListHealthyBackends() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::vector<BackendId> healthy;
    for (const auto& [id, state] : impl_->backends_) {
        if (state->info.state == BackendState::Healthy) {
            healthy.push_back(id);
        }
    }
    
    return healthy;
}

std::optional<RoutingDecision> CapabilityRouter::Route(
    const CapabilityToken& cap,
    const WorkSpec& work) {
    
    return RouteWithStrategy(cap, work, work.strategy);
}

std::optional<RoutingDecision> CapabilityRouter::RouteWithStrategy(
    const CapabilityToken& cap,
    const WorkSpec& work,
    RoutingStrategy strategy) {
    
    auto start = std::chrono::steady_clock::now();
    
    // Check capability validity
    if (!cap.IsValid()) {
        impl_->failed_routes_++;
        return std::nullopt;
    }
    
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    // Find candidate backends
    std::vector<BackendId> candidates;
    for (const auto& [id, state] : impl_->backends_) {
        // Check if backend supports the architecture
        bool supports_arch = false;
        for (const auto& arch : state->info.supported_architectures) {
            if (arch == work.model_architecture) {
                supports_arch = true;
                break;
            }
        }
        
        if (supports_arch && state->info.state == BackendState::Healthy) {
            candidates.push_back(id);
        }
    }
    
    if (candidates.empty()) {
        impl_->failed_routes_++;
        return std::nullopt;
    }
    
    // Score candidates based on strategy
    std::vector<std::pair<BackendId, float>> scored;
    for (BackendId id : candidates) {
        auto& state = *impl_->backends_[id];
        float score = 0.0f;
        
        switch (strategy) {
            case RoutingStrategy::LatencyOptimized:
                score = 1.0f / (1.0f + state->info.avg_latency.count() / 1000.0f);
                break;
                
            case RoutingStrategy::ThroughputOptimized:
                score = (1.0f - state->info.current_load) * state->info.max_batch_size;
                break;
                
            case RoutingStrategy::CostOptimized:
                score = 1.0f / (1.0f + state->info.cost_per_token);
                break;
                
            case RoutingStrategy::ReliabilityOptimized:
                score = state->info.success_rate;
                break;
        }
        
        // Apply composite scoring
        float latency_score = 1.0f / (1.0f + state->info.avg_latency.count() / 1000.0f);
        float cost_score = 1.0f / (1.0f + state->info.cost_per_token);
        float reliability_score = state->info.success_rate;
        
        score = impl_->latency_weight_ * latency_score +
                impl_->cost_weight_ * cost_score +
                impl_->reliability_weight_ * reliability_score;
        
        scored.push_back({id, score});
    }
    
    // Sort by score (highest first)
    std::sort(scored.begin(), scored.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Build decision
    RoutingDecision decision;
    decision.backend = scored[0].first;
    decision.confidence = scored[0].second;
    decision.backend_name = impl_->backends_[decision.backend]->info.name;
    
    // Build reason string
    switch (strategy) {
        case RoutingStrategy::LatencyOptimized:
            decision.reason = "Lowest latency (" + 
                std::to_string(impl_->backends_[decision.backend]->info.avg_latency.count() / 1000) + "ms)";
            break;
        case RoutingStrategy::ThroughputOptimized:
            decision.reason = "Highest throughput (load=" + 
                std::to_string(static_cast<int>(impl_->backends_[decision.backend]->info.current_load * 100)) + "%)";
            break;
        case RoutingStrategy::CostOptimized:
            decision.reason = "Lowest cost ($" + 
                std::to_string(impl_->backends_[decision.backend]->info.cost_per_token) + "/token)";
            break;
        case RoutingStrategy::ReliabilityOptimized:
            decision.reason = "Highest reliability (" + 
                std::to_string(static_cast<int>(impl_->backends_[decision.backend]->info.success_rate * 100)) + "%)";
            break;
    }
    
    // Add alternatives
    for (size_t i = 1; i < scored.size() && i < 3; i++) {
        decision.alternatives.push_back(scored[i].first);
    }
    
    // Update statistics
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    impl_->total_routes_++;
    impl_->successful_routes_++;
    impl_->total_routing_time_us_ += duration.count();
    
    auto& state = *impl_->backends_[decision.backend];
    state.route_count_++;
    
    return decision;
}

bool CapabilityRouter::CanRoute(const CapabilityToken& cap, const WorkSpec& work) const {
    if (!cap.IsValid()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    for (const auto& [id, state] : impl_->backends_) {
        if (state->info.state != BackendState::Healthy) {
            continue;
        }
        
        for (const auto& arch : state->info.supported_architectures) {
            if (arch == work.model_architecture) {
                return true;
            }
        }
    }
    
    return false;
}

void CapabilityRouter::ReportLatency(BackendId backend, std::chrono::microseconds latency) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->backends_.find(backend);
    if (it != impl_->backends_.end()) {
        std::lock_guard<std::mutex> latency_lock(it->second->latency_mutex);
        it->second->recent_latencies.push_back(latency);
        
        // Keep only last 100 measurements
        if (it->second->recent_latencies.size() > 100) {
            it->second->recent_latencies.erase(it->second->recent_latencies.begin());
        }
        
        // Update rolling average
        auto sum = std::chrono::microseconds::zero();
        for (const auto& lat : it->second->recent_latencies) {
            sum += lat;
        }
        it->second->info.avg_latency = sum / it->second->recent_latencies.size();
    }
}

void CapabilityRouter::ReportOutcome(BackendId backend, bool success) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->backends_.find(backend);
    if (it != impl_->backends_.end()) {
        if (success) {
            it->second->success_count_++;
        } else {
            it->second->failure_count_++;
        }
        
        // Update success rate
        uint64_t total = it->second->success_count_ + it->second->failure_count_;
        if (total > 0) {
            it->second->info.success_rate = 
                static_cast<float>(it->second->success_count_) / total;
        }
    }
}

std::map<BackendId, float> CapabilityRouter::GetLoadDistribution() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::map<BackendId, float> distribution;
    for (const auto& [id, state] : impl_->backends_) {
        distribution[id] = state->info.current_load;
    }
    
    return distribution;
}

bool CapabilityRouter::IsOverloaded(BackendId backend) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->backends_.find(backend);
    if (it != impl_->backends_.end()) {
        return it->second->info.current_load > 0.9f;
    }
    
    return false;
}

float CapabilityRouter::GetRecommendedLoadShift(BackendId backend) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->backends_.find(backend);
    if (it == impl_->backends_.end()) {
        return 0.0f;
    }
    
    float load = it->second->info.current_load;
    if (load < 0.5f) {
        return 0.2f; // Can take more load
    } else if (load > 0.9f) {
        return -0.3f; // Should shed load
    }
    
    return 0.0f;
}

CapabilityRouter::Statistics CapabilityRouter::GetStatistics() const {
    Statistics stats;
    stats.total_routes = impl_->total_routes_.load();
    stats.successful_routes = impl_->successful_routes_.load();
    stats.failed_routes = impl_->failed_routes_.load();
    stats.fallback_routes = impl_->fallback_routes_.load();
    
    uint64_t routes = stats.total_routes;
    if (routes > 0) {
        stats.avg_routing_time_us = impl_->total_routing_time_us_ / routes;
    }
    
    // Compute average backend latency
    double total_latency = 0.0;
    size_t count = 0;
    
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& [id, state] : impl_->backends_) {
        total_latency += state->info.avg_latency.count();
        count++;
    }
    
    if (count > 0) {
        stats.avg_backend_latency_ms = (total_latency / count) / 1000.0;
    }
    
    return stats;
}

void CapabilityRouter::ResetStatistics() {
    impl_->total_routes_ = 0;
    impl_->successful_routes_ = 0;
    impl_->failed_routes_ = 0;
    impl_->fallback_routes_ = 0;
    impl_->total_routing_time_us_ = 0.0;
}

void CapabilityRouter::SetDefaultStrategy(RoutingStrategy strategy) {
    impl_->default_strategy_ = strategy;
}

void CapabilityRouter::SetLatencyWeight(float weight) {
    impl_->latency_weight_ = std::clamp(weight, 0.0f, 1.0f);
}

void CapabilityRouter::SetCostWeight(float weight) {
    impl_->cost_weight_ = std::clamp(weight, 0.0f, 1.0f);
}

void CapabilityRouter::SetReliabilityWeight(float weight) {
    impl_->reliability_weight_ = std::clamp(weight, 0.0f, 1.0f);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Global Instance
// ═══════════════════════════════════════════════════════════════════════════════

static std::unique_ptr<CapabilityRouter> g_router;
static std::once_flag g_init_flag;

CapabilityRouter& GetRouter() {
    std::call_once(g_init_flag, []() {
        g_router = std::make_unique<CapabilityRouter>();
    });
    return *g_router;
}

bool InitializeRouter(const std::string& config_path) {
    GetRouter();
    return true;
}

void ShutdownRouter() {
    g_router.reset();
}

} // namespace rawrxd::router
