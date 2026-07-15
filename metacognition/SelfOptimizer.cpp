#include "metacognition/SelfOptimizer.hpp"
#include <mutex>
#include <map>
#include <vector>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, nlohmann::json> s_activeOptimizations;
static std::vector<nlohmann::json> s_optimizationHistory;
static size_t s_optimizationCount = 0;

void SelfOptimizer::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_activeOptimizations.clear();
        s_optimizationHistory.clear();
        s_optimizationCount = 0;
        s_initialized = true;
    }
}

void SelfOptimizer::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool SelfOptimizer::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void SelfOptimizer::TuneParameter(const std::string& component, const std::string& param, double value) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    nlohmann::json tuning = {
        {"component", component},
        {"parameter", param},
        {"new_value", value},
        {"tuned_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
    
    s_optimizationHistory.push_back(tuning);
    s_optimizationCount++;
}

void SelfOptimizer::EnableOptimization(const std::string& optimizationId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_activeOptimizations[optimizationId] = {
        {"id", optimizationId},
        {"enabled_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"status", "active"}
    };
}

void SelfOptimizer::DisableOptimization(const std::string& optimizationId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_activeOptimizations.find(optimizationId);
    if (it != s_activeOptimizations.end()) {
        it->second["status"] = "disabled";
        it->second["disabled_at"] = std::chrono::system_clock::now().time_since_epoch().count();
    }
}

nlohmann::json SelfOptimizer::GetActiveOptimizations() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, opt] : s_activeOptimizations) {
        if (opt.value("status", "") == "active") {
            result.push_back(opt);
        }
    }
    return result;
}

nlohmann::json SelfOptimizer::GetOptimizationHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_optimizationHistory;
}

nlohmann::json SelfOptimizer::GetOptimizationMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t activeCount = 0;
    for (const auto& [id, opt] : s_activeOptimizations) {
        if (opt.value("status", "") == "active") {
            activeCount++;
        }
    }
    
    return {
        {"total_optimizations", s_optimizationCount},
        {"active_optimizations", activeCount},
        {"history_entries", s_optimizationHistory.size()}
    };
}
