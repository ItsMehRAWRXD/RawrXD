#include "scalability/AutoScaler.hpp"
#include "scalability/LoadBalancer.hpp"
#include <mutex>
#include <vector>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;

struct ScalingEvent {
    std::string type; // scale_up or scale_down
    std::string reason;
    int64_t timestamp;
    size_t nodeCountBefore;
    size_t nodeCountAfter;
};

static double s_scaleUpThreshold = 0.8;   // 80% load
static double s_scaleDownThreshold = 0.2; // 20% load
static size_t s_minNodes = 2;
static size_t s_maxNodes = 20;
static size_t s_currentNodes = 2;
static std::vector<ScalingEvent> s_scalingHistory;
static size_t s_scaleUpCount = 0;
static size_t s_scaleDownCount = 0;

void AutoScaler::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_scaleUpThreshold = 0.8;
        s_scaleDownThreshold = 0.2;
        s_minNodes = 2;
        s_maxNodes = 20;
        s_currentNodes = 2;
        s_scalingHistory.clear();
        s_scaleUpCount = 0;
        s_scaleDownCount = 0;
        s_initialized = true;
    }
}

void AutoScaler::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Auto-evaluate scaling needs
    auto metrics = LoadBalancer::GetLoadBalancerMetrics();
    double avgLoad = metrics.value("average_load", 0.0);
    size_t healthyNodes = metrics.value("healthy_nodes", 0);
    
    // Check if we need to scale
    if (avgLoad > s_scaleUpThreshold && healthyNodes < s_maxNodes) {
        ScaleUp("high_load");
    } else if (avgLoad < s_scaleDownThreshold && healthyNodes > s_minNodes) {
        ScaleDown("low_load");
    }
}

bool AutoScaler::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json AutoScaler::EvaluateScalingNeeds() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    auto metrics = LoadBalancer::GetLoadBalancerMetrics();
    double avgLoad = metrics.value("average_load", 0.0);
    size_t healthyNodes = metrics.value("healthy_nodes", 0);
    
    std::string recommendation = "maintain";
    std::string reason = "load_within_thresholds";
    
    if (avgLoad > s_scaleUpThreshold && healthyNodes < s_maxNodes) {
        recommendation = "scale_up";
        reason = "high_average_load";
    } else if (avgLoad < s_scaleDownThreshold && healthyNodes > s_minNodes) {
        recommendation = "scale_down";
        reason = "low_average_load";
    }
    
    return {
        {"current_nodes", healthyNodes},
        {"average_load", avgLoad},
        {"recommendation", recommendation},
        {"reason", reason},
        {"scale_up_threshold", s_scaleUpThreshold},
        {"scale_down_threshold", s_scaleDownThreshold}
    };
}

bool AutoScaler::ScaleUp(const std::string& reason) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return false;
    
    if (s_currentNodes >= s_maxNodes) {
        return false;
    }
    
    size_t before = s_currentNodes;
    s_currentNodes++;
    s_scaleUpCount++;
    
    ScalingEvent event;
    event.type = "scale_up";
    event.reason = reason;
    event.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    event.nodeCountBefore = before;
    event.nodeCountAfter = s_currentNodes;
    s_scalingHistory.push_back(event);
    
    // Keep history bounded
    if (s_scalingHistory.size() > 100) {
        s_scalingHistory.erase(s_scalingHistory.begin());
    }
    
    return true;
}

bool AutoScaler::ScaleDown(const std::string& reason) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return false;
    
    if (s_currentNodes <= s_minNodes) {
        return false;
    }
    
    size_t before = s_currentNodes;
    s_currentNodes--;
    s_scaleDownCount++;
    
    ScalingEvent event;
    event.type = "scale_down";
    event.reason = reason;
    event.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    event.nodeCountBefore = before;
    event.nodeCountAfter = s_currentNodes;
    s_scalingHistory.push_back(event);
    
    // Keep history bounded
    if (s_scalingHistory.size() > 100) {
        s_scalingHistory.erase(s_scalingHistory.begin());
    }
    
    return true;
}

void AutoScaler::SetThresholds(double scaleUpThreshold, double scaleDownThreshold) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_scaleUpThreshold = scaleUpThreshold;
    s_scaleDownThreshold = scaleDownThreshold;
}

nlohmann::json AutoScaler::GetThresholds() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"scale_up_threshold", s_scaleUpThreshold},
        {"scale_down_threshold", s_scaleDownThreshold}
    };
}

void AutoScaler::SetLimits(size_t minNodes, size_t maxNodes) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_minNodes = minNodes;
    s_maxNodes = maxNodes;
}

nlohmann::json AutoScaler::GetLimits() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"min_nodes", s_minNodes},
        {"max_nodes", s_maxNodes},
        {"current_nodes", s_currentNodes}
    };
}

nlohmann::json AutoScaler::GetScalingHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& event : s_scalingHistory) {
        result.push_back({
            {"type", event.type},
            {"reason", event.reason},
            {"timestamp", event.timestamp},
            {"nodes_before", event.nodeCountBefore},
            {"nodes_after", event.nodeCountAfter}
        });
    }
    return result;
}

nlohmann::json AutoScaler::GetAutoScalerMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"current_nodes", s_currentNodes},
        {"min_nodes", s_minNodes},
        {"max_nodes", s_maxNodes},
        {"scale_up_count", s_scaleUpCount},
        {"scale_down_count", s_scaleDownCount},
        {"total_scaling_events", s_scalingHistory.size()}
    };
}
