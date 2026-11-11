#include "resource/OptimizationEngine.hpp"
#include "resource/ResourceAllocator.hpp"
#include <mutex>
#include <map>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;

struct Optimization {
    std::string id;
    std::string description;
    std::string target;
    double expectedImprovement;
    bool applied;
    int64_t appliedAt;
};

static std::map<std::string, Optimization> s_optimizations;
static size_t s_optimizationCounter = 0;

static std::string GenerateOptimizationId() {
    s_optimizationCounter++;
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    return "opt-" + std::to_string(now) + "-" + std::to_string(s_optimizationCounter);
}

void OptimizationEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_optimizations.clear();
        s_optimizationCounter = 0;
        s_initialized = true;
    }
}

void OptimizationEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Auto-generate optimization recommendations
    auto utilization = ResourceAllocator::GetResourceUtilization();
    for (const auto& [type, data] : utilization.items()) {
        double util = data.value("utilization", 0.0);
        if (util > 0.8) {
            // High utilization - recommend optimization
            Optimization opt;
            opt.id = GenerateOptimizationId();
            opt.description = "Reduce " + type + " usage";
            opt.target = type;
            opt.expectedImprovement = 0.15;
            opt.applied = false;
            s_optimizations[opt.id] = opt;
        }
    }
}

bool OptimizationEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json OptimizationEngine::OptimizeResourceUsage() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    auto utilization = ResourceAllocator::GetResourceUtilization();
    nlohmann::json optimizations = nlohmann::json::array();
    
    for (const auto& [type, data] : utilization.items()) {
        double util = data.value("utilization", 0.0);
        if (util > 0.7) {
            optimizations.push_back({
                {"resource", type},
                {"utilization", util},
                {"recommendation", "scale_up_or_optimize"}
            });
        }
    }
    
    return {
        {"optimizations_found", optimizations.size()},
        {"recommendations", optimizations}
    };
}

nlohmann::json OptimizationEngine::FindBottlenecks() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    auto utilization = ResourceAllocator::GetResourceUtilization();
    nlohmann::json bottlenecks = nlohmann::json::array();
    
    for (const auto& [type, data] : utilization.items()) {
        double util = data.value("utilization", 0.0);
        if (util > 0.9) {
            bottlenecks.push_back({
                {"resource", type},
                {"utilization", util},
                {"severity", "critical"}
            });
        } else if (util > 0.75) {
            bottlenecks.push_back({
                {"resource", type},
                {"utilization", util},
                {"severity", "warning"}
            });
        }
    }
    
    return {
        {"bottlenecks_found", bottlenecks.size()},
        {"bottlenecks", bottlenecks}
    };
}

nlohmann::json OptimizationEngine::RecommendOptimizations() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, opt] : s_optimizations) {
        if (!opt.applied) {
            result.push_back({
                {"id", opt.id},
                {"description", opt.description},
                {"target", opt.target},
                {"expected_improvement", opt.expectedImprovement}
            });
        }
    }
    return result;
}

void OptimizationEngine::ApplyOptimization(const std::string& optimizationId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_optimizations.find(optimizationId);
    if (it != s_optimizations.end()) {
        it->second.applied = true;
        it->second.appliedAt = std::chrono::system_clock::now().time_since_epoch().count();
    }
}

void OptimizationEngine::RevertOptimization(const std::string& optimizationId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_optimizations.find(optimizationId);
    if (it != s_optimizations.end()) {
        it->second.applied = false;
    }
}

nlohmann::json OptimizationEngine::GetActiveOptimizations() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, opt] : s_optimizations) {
        if (opt.applied) {
            result.push_back({
                {"id", opt.id},
                {"description", opt.description},
                {"applied_at", opt.appliedAt}
            });
        }
    }
    return result;
}

nlohmann::json OptimizationEngine::GetOptimizationMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t appliedCount = 0;
    size_t pendingCount = 0;
    for (const auto& [id, opt] : s_optimizations) {
        if (opt.applied) appliedCount++;
        else pendingCount++;
    }
    
    return {
        {"total_optimizations", s_optimizations.size()},
        {"applied", appliedCount},
        {"pending", pendingCount}
    };
}
