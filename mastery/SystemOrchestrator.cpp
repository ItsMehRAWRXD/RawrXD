#include "mastery/SystemOrchestrator.hpp"
#include <mutex>
#include <map>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, nlohmann::json> s_layerStates;
static size_t s_coordinationCount = 0;

void SystemOrchestrator::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_layerStates.clear();
        s_coordinationCount = 0;
        
        // Initialize all layer states
        std::vector<std::string> layers = {
            "fabric", "distributed", "adaptive", "cognition", "consciousness",
            "autonomy", "emergence", "metastability", "identity", "temporal",
            "causal", "intent", "prediction", "learning", "executive",
            "values", "reflection", "communication", "social", "creativity",
            "ethics", "wisdom", "metacognition"
        };
        
        for (const auto& layer : layers) {
            s_layerStates[layer] = {
                {"name", layer},
                {"status", "initialized"},
                {"initialized_at", std::chrono::system_clock::now().time_since_epoch().count()},
                {"health", "healthy"}
            };
        }
        
        s_initialized = true;
    }
}

void SystemOrchestrator::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all layer states
    for (auto& [name, state] : s_layerStates) {
        state["last_tick"] = std::chrono::system_clock::now().time_since_epoch().count();
    }
}

bool SystemOrchestrator::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json SystemOrchestrator::GetSystemState() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json state;
    state["timestamp"] = std::chrono::system_clock::now().time_since_epoch().count();
    state["layers"] = nlohmann::json::array();
    
    int healthyCount = 0;
    for (const auto& [name, layerState] : s_layerStates) {
        state["layers"].push_back(layerState);
        if (layerState.value("health", "") == "healthy") {
            healthyCount++;
        }
    }
    
    state["total_layers"] = s_layerStates.size();
    state["healthy_layers"] = healthyCount;
    state["system_health"] = static_cast<double>(healthyCount) / s_layerStates.size();
    state["status"] = healthyCount == static_cast<int>(s_layerStates.size()) ? "operational" : "degraded";
    
    return state;
}

nlohmann::json SystemOrchestrator::GetLayerStatus(const std::string& layerName) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_layerStates.find(layerName);
    if (it != s_layerStates.end()) {
        return it->second;
    }
    return nlohmann::json{};
}

void SystemOrchestrator::CoordinateLayers(const nlohmann::json& coordinationPlan) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_coordinationCount++;
    
    // Apply coordination plan
    if (coordinationPlan.contains("priorities")) {
        for (const auto& [layer, priority] : coordinationPlan["priorities"].items()) {
            if (s_layerStates.find(layer) != s_layerStates.end()) {
                s_layerStates[layer]["priority"] = priority;
            }
        }
    }
}

nlohmann::json SystemOrchestrator::ExecuteMasterPlan(const nlohmann::json& plan) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json result;
    result["plan_executed"] = plan;
    result["executed_at"] = std::chrono::system_clock::now().time_since_epoch().count();
    result["status"] = "completed";
    
    // Execute plan steps
    if (plan.contains("steps")) {
        int completedSteps = 0;
        for (const auto& step : plan["steps"]) {
            // In a real implementation, this would execute each step
            completedSteps++;
        }
        result["steps_completed"] = completedSteps;
        result["completion_rate"] = static_cast<double>(completedSteps) / plan["steps"].size();
    }
    
    return result;
}

nlohmann::json SystemOrchestrator::GetSystemHealth() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    int healthyCount = 0;
    int warningCount = 0;
    int criticalCount = 0;
    
    for (const auto& [name, state] : s_layerStates) {
        std::string health = state.value("health", "unknown");
        if (health == "healthy") healthyCount++;
        else if (health == "warning") warningCount++;
        else if (health == "critical") criticalCount++;
    }
    
    double overallHealth = s_layerStates.empty() ? 0.0 : 
                          static_cast<double>(healthyCount) / s_layerStates.size();
    
    return {
        {"overall_health", overallHealth},
        {"healthy_layers", healthyCount},
        {"warning_layers", warningCount},
        {"critical_layers", criticalCount},
        {"total_layers", s_layerStates.size()},
        {"status", overallHealth > 0.9 ? "healthy" : (overallHealth > 0.7 ? "degraded" : "critical")}
    };
}

nlohmann::json SystemOrchestrator::GetSystemMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"layers_active", s_layerStates.size()},
        {"coordinations_performed", s_coordinationCount},
        {"system_uptime", std::chrono::system_clock::now().time_since_epoch().count()}
    };
}
