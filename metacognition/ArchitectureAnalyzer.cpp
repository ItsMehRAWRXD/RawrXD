#include "metacognition/ArchitectureAnalyzer.hpp"
#include <mutex>
#include <map>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, nlohmann::json> s_layerMetrics;
static size_t s_analysisCount = 0;

void ArchitectureAnalyzer::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_layerMetrics.clear();
        s_analysisCount = 0;
        s_initialized = true;
    }
}

void ArchitectureAnalyzer::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Periodic performance analysis
    // In a real implementation, this would measure actual performance
}

bool ArchitectureAnalyzer::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json ArchitectureAnalyzer::AnalyzeLayerPerformance(const std::string& layerName) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    s_analysisCount++;
    
    // Simulate performance metrics
    nlohmann::json metrics = {
        {"layer", layerName},
        {"analyzed_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"tick_rate", 60.0}, // ticks per second
        {"avg_latency_ms", 0.5 + (rand() % 10) / 10.0},
        {"memory_usage_mb", 10 + (rand() % 50)},
        {"cpu_utilization", 0.1 + (rand() % 30) / 100.0},
        {"status", "healthy"}
    };
    
    s_layerMetrics[layerName] = metrics;
    return metrics;
}

nlohmann::json ArchitectureAnalyzer::IdentifyBottlenecks() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json bottlenecks = nlohmann::json::array();
    
    // Identify layers with high latency
    for (const auto& [name, metrics] : s_layerMetrics) {
        double latency = metrics.value("avg_latency_ms", 0.0);
        if (latency > 1.0) {
            bottlenecks.push_back({
                {"layer", name},
                {"latency_ms", latency},
                {"severity", latency > 2.0 ? "high" : "medium"}
            });
        }
    }
    
    return {
        {"bottlenecks_found", bottlenecks.size()},
        {"bottlenecks", bottlenecks},
        {"analyzed_layers", s_layerMetrics.size()}
    };
}

nlohmann::json ArchitectureAnalyzer::MeasureInterLayerLatency() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    // Simulate inter-layer communication latency
    return {
        {"fabric_to_distributed_us", 50},
        {"distributed_to_adaptive_us", 100},
        {"adaptive_to_cognition_us", 75},
        {"cognition_to_consciousness_us", 60},
        {"consciousness_to_autonomy_us", 80},
        {"total_pipeline_ms", 0.365}
    };
}

nlohmann::json ArchitectureAnalyzer::SuggestOptimizations() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json suggestions = nlohmann::json::array();
    
    auto bottlenecks = IdentifyBottlenecks();
    for (const auto& bottleneck : bottlenecks["bottlenecks"]) {
        std::string layer = bottleneck.value("layer", "");
        suggestions.push_back({
            {"target_layer", layer},
            {"suggestion", "Consider parallelizing " + layer + " operations"},
            {"expected_improvement", "20-30%"}
        });
    }
    
    // General suggestions
    suggestions.push_back({
        {"target_layer", "global"},
        {"suggestion", "Enable batch processing for tick operations"},
        {"expected_improvement", "15-25%"}
    });
    
    return {
        {"suggestions", suggestions},
        {"total_suggestions", suggestions.size()}
    };
}

nlohmann::json ArchitectureAnalyzer::GetArchitectureMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"layers_monitored", s_layerMetrics.size()},
        {"analyses_performed", s_analysisCount},
        {"last_analysis", std::chrono::system_clock::now().time_since_epoch().count()}
    };
}
