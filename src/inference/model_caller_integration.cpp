// ============================================================================
// Model Caller Integration - Replaces hardcoded CPU backend
// ============================================================================
// This file patches ai_model_caller_real.cpp to use the backend selector
// ============================================================================

#include "backend_selector_real.hpp"
#include <iostream>
#include <stdlib.h>

// Forward declarations from ai_model_caller_real.cpp
struct ggml_rxd_backend;
struct ggml_rxd_context;
extern ggml_rxd_backend* ggml_rxd_backend_cpu_init();

namespace RawrXD {
namespace Inference {

// ============================================================================
// Initialize Backend with Selection
// ============================================================================
ggml_rxd_backend* InitializeBackendWithSelection(ggml_rxd_context* ctx, 
                                                const BackendConfig& config) {
    // Probe system capabilities
    BackendCapabilities caps = ProbeSystemCapabilities();
    
    // Select optimal backend
    BackendType selected = SelectOptimalBackend(config, caps);
    
    std::cout << "[ModelCaller] Backend selection:\n";
    std::cout << "  Requested: " << static_cast<int>(config.type) << "\n";
    std::cout << "  Selected: " << static_cast<int>(selected) << "\n";
    std::cout << "  GPU: " << (caps.gpu_name.empty() ? "None" : caps.gpu_name.c_str()) << "\n";
    std::cout << "  VRAM: " << caps.vram_mb << " MB\n";
    
    // Initialize the selected backend
    switch (selected) {
        case BackendType::MEDUSA_GPU:
            std::cout << "[ModelCaller] Initializing Medusa GPU backend\n";
            // Medusa has its own execution path, not a GGML backend
            // Return nullptr to signal custom path
            return nullptr;
            
        case BackendType::VULKAN:
            std::cout << "[ModelCaller] Initializing Vulkan backend\n";
            // TODO: Return real Vulkan backend when available
            // For now, fall through to CPU
            
        case BackendType::CPU:
        default:
            std::cout << "[ModelCaller] Initializing CPU backend\n";
            return ggml_rxd_backend_cpu_init();
    }
}

// ============================================================================
// Environment-based Configuration
// ============================================================================
BackendConfig GetBackendConfigFromEnvironment() {
    BackendConfig config;
    
    // Check for forced backend
    const char* backend_env = std::getenv("RAWRXD_BACKEND");
    if (backend_env) {
        if (std::strcmp(backend_env, "cpu") == 0) {
            config.type = BackendType::CPU;
            config.force_cpu = true;
        } else if (std::strcmp(backend_env, "vulkan") == 0) {
            config.type = BackendType::VULKAN;
        } else if (std::strcmp(backend_env, "medusa") == 0) {
            config.type = BackendType::MEDUSA_GPU;
        }
    }
    
    // Check for Medusa configuration
    const char* medusa_heads = std::getenv("RAWRXD_MEDUSA_HEADS");
    if (medusa_heads) {
        config.medusa_heads = std::atoi(medusa_heads);
        if (config.medusa_heads < 1) config.medusa_heads = 8;
        if (config.medusa_heads > 16) config.medusa_heads = 16;
    }
    
    // Check for context size
    const char* ctx_env = std::getenv("RAWRXD_CONTEXT");
    if (ctx_env) {
        config.max_context = std::atoi(ctx_env);
        if (config.max_context < 2048) config.max_context = 2048;
        if (config.max_context > 131072) config.max_context = 131072;
    }
    
    // Check for VRAM budget
    const char* vram_env = std::getenv("RAWRXD_VRAM_BUDGET");
    if (vram_env) {
        config.vram_budget_mb = std::atoi(vram_env);
    }
    
    // Check if Medusa should be disabled
    const char* no_medusa = std::getenv("RAWRXD_NO_MEDUSA");
    if (no_medusa) {
        config.enable_medusa = false;
    }
    
    return config;
}

// ============================================================================
// Telemetry Integration
// ============================================================================
void LogBackendMetrics(const IInferenceBackend* backend) {
    if (!backend) return;
    
    std::cout << "[Telemetry] Backend: " << backend->GetName() << "\n";
    std::cout << "[Telemetry] TPS: " << backend->GetTokensPerSecond() << "\n";
    std::cout << "[Telemetry] Latency: " << backend->GetAverageLatencyMs() << " ms\n";
    std::cout << "[Telemetry] VRAM: " << backend->GetVRAMUsedMB() << " MB\n";
}

} // namespace Inference
} // namespace RawrXD

// ============================================================================
// C API for Integration
// ============================================================================
extern "C" {

// Called from ai_model_caller_real.cpp to replace hardcoded CPU init
__declspec(dllexport) void* InitializeSmartBackend(void* ctx) {
    using namespace RawrXD::Inference;
    
    BackendConfig config = GetBackendConfigFromEnvironment();
    return InitializeBackendWithSelection(static_cast<ggml_rxd_context*>(ctx), config);
}

__declspec(dllexport) int GetSelectedBackendType() {
    using namespace RawrXD::Inference;
    BackendConfig config = GetBackendConfigFromEnvironment();
    BackendCapabilities caps = ProbeSystemCapabilities();
    BackendType selected = SelectOptimalBackend(config, caps);
    return static_cast<int>(selected);
}

}
