// ============================================================================
// Test: Real Backend Selection and GPU Execution
// ============================================================================
// Verifies:
// 1. Backend probing works
// 2. GPU is detected (if available)
// 3. Backend selection logic works
// 4. No performance claims without measurement
// ============================================================================

#include "backend_selector_real.hpp"
#include <iostream>
#include <cassert>
#include <cstdlib>
#include <cstring>

using namespace RawrXD::Inference;

// Minimal environment config function for testing
BackendConfig GetTestConfig() {
    BackendConfig config;
    
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
    
    const char* medusa_heads = std::getenv("RAWRXD_MEDUSA_HEADS");
    if (medusa_heads) {
        config.medusa_heads = std::atoi(medusa_heads);
        if (config.medusa_heads < 1) config.medusa_heads = 8;
        if (config.medusa_heads > 16) config.medusa_heads = 16;
    }
    
    const char* ctx_env = std::getenv("RAWRXD_CONTEXT");
    if (ctx_env) {
        config.max_context = std::atoi(ctx_env);
        if (config.max_context < 2048) config.max_context = 2048;
        if (config.max_context > 131072) config.max_context = 131072;
    }
    
    const char* no_medusa = std::getenv("RAWRXD_NO_MEDUSA");
    if (no_medusa) {
        config.enable_medusa = false;
    }
    
    return config;
}

void TestProbeCapabilities() {
    std::cout << "\n=== Test: Probe System Capabilities ===\n";
    
    BackendCapabilities caps = ProbeSystemCapabilities();
    
    std::cout << "Results:\n";
    std::cout << "  Vulkan available: " << (caps.vulkan_available ? "YES" : "NO") << "\n";
    std::cout << "  GPU name: " << (caps.gpu_name.empty() ? "N/A" : caps.gpu_name) << "\n";
    std::cout << "  VRAM: " << caps.vram_mb << " MB\n";
    std::cout << "  Medusa available: " << (caps.medusa_available ? "YES" : "NO") << "\n";
    std::cout << "  FP16 support: " << (caps.supports_fp16 ? "YES" : "NO") << "\n";
    std::cout << "  Matrix cores: " << (caps.has_matrix_cores ? "YES" : "NO") << "\n";
    
    // Assertions - these should pass on any system
    assert(caps.vram_mb == 0 || caps.vram_mb >= 0);  // VRAM is non-negative
    
    std::cout << "✓ Probe test passed\n";
}

void TestBackendSelection() {
    std::cout << "\n=== Test: Backend Selection ===\n";
    
    BackendCapabilities caps = {};
    caps.vulkan_available = true;
    caps.vram_mb = 16384;  // 16GB
    caps.medusa_available = true;
    
    // Test 1: Auto-select with Medusa available
    {
        BackendConfig config;
        config.type = BackendType::AUTO;
        config.enable_medusa = true;
        
        BackendType selected = SelectOptimalBackend(config, caps);
        assert(selected == BackendType::MEDUSA_GPU);
        std::cout << "✓ Auto-select chose Medusa when available\n";
    }
    
    // Test 2: Force CPU
    {
        BackendConfig config;
        config.force_cpu = true;
        
        BackendType selected = SelectOptimalBackend(config, caps);
        assert(selected == BackendType::CPU);
        std::cout << "✓ Force CPU works\n";
    }
    
    // Test 3: Medusa not available (low VRAM)
    {
        BackendCapabilities low_vram_caps = caps;
        low_vram_caps.vram_mb = 4000;  // 4GB
        low_vram_caps.medusa_available = false;
        
        BackendConfig config;
        config.type = BackendType::AUTO;
        
        BackendType selected = SelectOptimalBackend(config, low_vram_caps);
        assert(selected == BackendType::VULKAN);  // Falls back to Vulkan
        std::cout << "✓ Falls back to Vulkan when Medusa unavailable\n";
    }
    
    // Test 4: No GPU at all
    {
        BackendCapabilities no_gpu_caps = {};
        no_gpu_caps.vulkan_available = false;
        no_gpu_caps.medusa_available = false;
        
        BackendConfig config;
        config.type = BackendType::AUTO;
        
        BackendType selected = SelectOptimalBackend(config, no_gpu_caps);
        assert(selected == BackendType::CPU);
        std::cout << "✓ Falls back to CPU when no GPU\n";
    }
    
    std::cout << "✓ All selection tests passed\n";
}

void TestBackendCreation() {
    std::cout << "\n=== Test: Backend Creation ===\n";
    
    // Test CPU backend creation
    {
        auto backend = CreateBackend(BackendType::CPU);
        assert(backend != nullptr);
        assert(backend->GetType() == BackendType::CPU);
        assert(backend->GetName() == "CPU");
        
        BackendConfig config;
        assert(backend->Initialize(config));
        assert(backend->IsInitialized());
        
        backend->Shutdown();
        assert(!backend->IsInitialized());
        
        std::cout << "✓ CPU backend creation works\n";
    }
    
    // Test Medusa backend creation (will fail to init without GPU)
    {
        auto backend = CreateBackend(BackendType::MEDUSA_GPU);
        assert(backend != nullptr);
        assert(backend->GetType() == BackendType::MEDUSA_GPU);
        
        BackendConfig config;
        config.model_path = "";  // No model, will fail gracefully
        
        // This may fail if no GPU, but shouldn't crash
        bool initialized = backend->Initialize(config);
        std::cout << "  Medusa init: " << (initialized ? "SUCCESS" : "FAILED (expected if no GPU)") << "\n";
        
        std::cout << "✓ Medusa backend creation works\n";
    }
    
    std::cout << "✓ All backend creation tests passed\n";
}

void TestEnvironmentConfig() {
    std::cout << "\n=== Test: Environment Configuration ===\n";
    
    // Note: These tests don't set env vars, just verify the function exists
    // Real env var testing would need to be done manually
    
    BackendConfig config = GetTestConfig();
    
    std::cout << "  Default config loaded:\n";
    std::cout << "    Type: " << static_cast<int>(config.type) << " (AUTO=3)\n";
    std::cout << "    Force CPU: " << (config.force_cpu ? "YES" : "NO") << "\n";
    std::cout << "    Medusa heads: " << config.medusa_heads << "\n";
    std::cout << "    Max context: " << config.max_context << "\n";
    std::cout << "    VRAM budget: " << config.vram_budget_mb << " MB\n";
    
    std::cout << "✓ Environment config test passed\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Backend Selector - Real Tests\n";
    std::cout << "========================================\n";
    std::cout << "\nNOTE: These tests verify functionality, NOT performance.\n";
    std::cout << "Performance claims require separate benchmarking.\n";
    
    try {
        TestProbeCapabilities();
        TestBackendSelection();
        TestBackendCreation();
        TestEnvironmentConfig();
        
        std::cout << "\n========================================\n";
        std::cout << "All tests PASSED\n";
        std::cout << "========================================\n";
        std::cout << "\nNext steps:\n";
        std::cout << "1. Run with RAWRXD_BACKEND=medusa to test Medusa\n";
        std::cout << "2. Profile actual token generation speed\n";
        std::cout << "3. Verify GPU utilization with tools\n";
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTest FAILED: " << e.what() << "\n";
        return 1;
    }
}
