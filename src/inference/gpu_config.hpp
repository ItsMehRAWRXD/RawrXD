// ============================================================================
// GPU Configuration - Feature Flags
// ============================================================================
// Controls which GPU optimizations are enabled
// Allows safe shipping of Phase 2 while Phase 1 remains experimental
// ============================================================================

#pragma once

#include <string>

namespace RawrXD {
namespace Inference {

// ============================================================================
// GPU Feature Flags
// ============================================================================
struct GPUConfig {
    // Phase 1: Tiled MatMul (EXPERIMENTAL - currently slower)
    // Default: false (use original MatMul)
    bool use_tiled_matmul = false;
    
    // Phase 2: Weight Cache (PRODUCTION READY)
    // Default: true (enables 7x speedup)
    bool use_weight_cache = true;
    
    // Phase 3: Kernel Fusion (NOT IMPLEMENTED)
    bool use_fused_kernels = false;
    
    // Phase 4: Medusa Speculative (NOT IMPLEMENTED)
    bool use_medusa = false;
    
    // Phase 5: Quantization (NOT IMPLEMENTED)
    bool use_fp8_compute = false;
    bool use_int4_weights = false;
    
    // Tiled MatMul tuning (only used if use_tiled_matmul = true)
    uint32_t tiled_workgroup_size = 32;  // 16, 32, or 64
    bool tiled_enable_profiling = false;  // Log detailed telemetry
    
    // Weight cache tuning
    size_t weight_cache_max_mb = 14000;  // Max VRAM for weights (14GB)
    bool weight_cache_preload_all = true;  // Pre-upload all layers
    
    // Load from INI file
    bool LoadFromFile(const std::string& filepath);
    
    // Save to INI file
    bool SaveToFile(const std::string& filepath) const;
    
    // Print current configuration
    void Print() const;
};

// ============================================================================
// Global Configuration Access
// ============================================================================
GPUConfig* GetGPUConfig();
void InitializeGPUConfig(const std::string& config_path = "");
void ShutdownGPUConfig();

} // namespace Inference
} // namespace RawrXD
