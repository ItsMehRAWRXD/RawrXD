// ============================================================================
// High-Performance Inference Bridge
// ============================================================================
// Connects Medusa GPU engine to the main inference pipeline
// Target: 100+ tok/s on RX 7800 XT with 32K context
// ============================================================================

#include "medusa_gpu_engine.hpp"
#include <iostream>
#include <memory>
#include <chrono>

namespace RawrXD {
namespace Inference {

// ============================================================================
// Global Engine Instance
// ============================================================================
static std::unique_ptr<MedusaGPUEngine> g_medusa_engine = nullptr;
static bool g_high_performance_mode = false;

// ============================================================================
// Initialize High-Performance Mode
// ============================================================================
bool InitializeHighPerformanceInference(const std::string& model_path, int ngl = 999) {
    std::cout << "[HighPerf] Initializing Medusa GPU engine...\n";
    
    MedusaConfig config;
    config.num_heads = 8;              // More heads = more parallelism
    config.tokens_per_head = 8;       // 8 candidates per head
    config.batch_size = 128;           // Process 128 candidates at once
    config.max_context = 32768;          // 32K context window
    config.acceptance_threshold = 0.65f; // Slightly aggressive for speed
    config.vram_budget_mb = 14000;     // Use 14GB of 16GB VRAM
    
    g_medusa_engine = CreateMedusaEngine(config);
    if (!g_medusa_engine) {
        std::cerr << "[HighPerf] Failed to create Medusa engine\n";
        return false;
    }
    
    if (!g_medusa_engine->LoadModelWeights(model_path, ngl)) {
        std::cerr << "[HighPerf] Failed to load model weights\n";
        return false;
    }
    
    g_high_performance_mode = true;
    std::cout << "[HighPerf] Ready - 32K context, Medusa heads active\n";
    return true;
}

// ============================================================================
// Generate with Maximum Performance
// ============================================================================
std::vector<int32_t> GenerateHighPerformance(const std::vector<int32_t>& prompt,
                                            uint32_t max_tokens,
                                            std::function<void(const std::string&)> callback) {
    if (!g_high_performance_mode || !g_medusa_engine) {
        std::cerr << "[HighPerf] Engine not initialized\n";
        return {};
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    auto tokens = g_medusa_engine->Generate(prompt, max_tokens, callback);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    float tps = (float)tokens.size() / (duration.count() / 1000.0f);
    std::cout << "[HighPerf] Generated " << tokens.size() << " tokens in " 
              << duration.count() << "ms (" << tps << " tok/s)\n";
    
    return tokens;
}

// ============================================================================
// Get Performance Metrics
// ============================================================================
struct PerformanceMetrics {
    float current_tps;
    float avg_latency_ms;
    uint64_t total_tokens;
    float acceptance_rate;
    bool gpu_active;
};

PerformanceMetrics GetPerformanceMetrics() {
    PerformanceMetrics metrics = {};
    
    if (g_medusa_engine) {
        metrics.current_tps = g_medusa_engine->GetCurrentTPS();
        metrics.avg_latency_ms = g_medusa_engine->GetAverageLatency();
        metrics.total_tokens = g_medusa_engine->GetTokensGenerated();
        metrics.gpu_active = true;
    } else {
        metrics.gpu_active = false;
    }
    
    return metrics;
}

// ============================================================================
// Shutdown
// ============================================================================
void ShutdownHighPerformanceInference() {
    g_medusa_engine.reset();
    g_high_performance_mode = false;
    std::cout << "[HighPerf] Shutdown complete\n";
}

} // namespace Inference
} // namespace RawrXD

// ============================================================================
// C API for Integration
// ============================================================================
extern "C" {

__declspec(dllexport) bool InitializeHighPerf(const char* model_path, int ngl) {
    return RawrXD::Inference::InitializeHighPerformanceInference(model_path, ngl);
}

__declspec(dllexport) void ShutdownHighPerf() {
    RawrXD::Inference::ShutdownHighPerformanceInference();
}

__declspec(dllexport) float GetCurrentTPS() {
    auto metrics = RawrXD::Inference::GetPerformanceMetrics();
    return metrics.current_tps;
}

__declspec(dllexport) bool IsGPUActive() {
    auto metrics = RawrXD::Inference::GetPerformanceMetrics();
    return metrics.gpu_active;
}

}
