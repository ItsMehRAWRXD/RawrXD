// ============================================================================
// GPU Configuration Implementation
// ============================================================================
// Simple INI-style config loader for GPU feature flags
// ============================================================================

#include "gpu_config.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace RawrXD {
namespace Inference {

// Global config instance
static GPUConfig* g_gpu_config = nullptr;

GPUConfig* GetGPUConfig() {
    return g_gpu_config;
}

void InitializeGPUConfig(const std::string& config_path) {
    if (!g_gpu_config) {
        g_gpu_config = new GPUConfig();
        
        // Try to load from file if provided
        if (!config_path.empty()) {
            if (!g_gpu_config->LoadFromFile(config_path)) {
                std::cout << "[GPUConfig] Using default configuration\n";
            }
        }
        
        g_gpu_config->Print();
    }
}

void ShutdownGPUConfig() {
    if (g_gpu_config) {
        delete g_gpu_config;
        g_gpu_config = nullptr;
    }
}

// Helper: trim whitespace
static std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, last - first + 1);
}

// Helper: convert to lowercase
static std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// Helper: parse bool from string
static bool ParseBool(const std::string& value) {
    std::string lower = ToLower(Trim(value));
    return (lower == "true" || lower == "1" || lower == "yes" || lower == "on");
}

bool GPUConfig::LoadFromFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "[GPUConfig] Failed to open: " << filepath << "\n";
        return false;
    }
    
    std::cout << "[GPUConfig] Loading from: " << filepath << "\n";
    
    std::string line;
    std::string current_section;
    
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        line = Trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        
        // Check for section
        if (line[0] == '[' && line.back() == ']') {
            current_section = ToLower(line.substr(1, line.length() - 2));
            continue;
        }
        
        // Parse key=value
        size_t equals_pos = line.find('=');
        if (equals_pos == std::string::npos) continue;
        
        std::string key = Trim(line.substr(0, equals_pos));
        std::string value = Trim(line.substr(equals_pos + 1));
        
        key = ToLower(key);
        
        // Parse based on section
        if (current_section == "gpu") {
            if (key == "use_tiled_matmul") {
                use_tiled_matmul = ParseBool(value);
                std::cout << "  use_tiled_matmul = " << (use_tiled_matmul ? "true" : "false");
                if (use_tiled_matmul) {
                    std::cout << " [EXPERIMENTAL - may be slower]";
                }
                std::cout << "\n";
            }
            else if (key == "use_weight_cache") {
                use_weight_cache = ParseBool(value);
                std::cout << "  use_weight_cache = " << (use_weight_cache ? "true" : "false");
                if (use_weight_cache) {
                    std::cout << " [PRODUCTION]";
                }
                std::cout << "\n";
            }
            else if (key == "use_fused_kernels") {
                use_fused_kernels = ParseBool(value);
                std::cout << "  use_fused_kernels = " << (use_fused_kernels ? "true" : "false");
                if (use_fused_kernels) {
                    std::cout << " [NOT IMPLEMENTED]";
                }
                std::cout << "\n";
            }
            else if (key == "use_medusa") {
                use_medusa = ParseBool(value);
                std::cout << "  use_medusa = " << (use_medusa ? "true" : "false");
                if (use_medusa) {
                    std::cout << " [NOT IMPLEMENTED]";
                }
                std::cout << "\n";
            }
            else if (key == "use_fp8_compute") {
                use_fp8_compute = ParseBool(value);
                std::cout << "  use_fp8_compute = " << (use_fp8_compute ? "true" : "false");
                if (use_fp8_compute) {
                    std::cout << " [NOT IMPLEMENTED]";
                }
                std::cout << "\n";
            }
            else if (key == "use_int4_weights") {
                use_int4_weights = ParseBool(value);
                std::cout << "  use_int4_weights = " << (use_int4_weights ? "true" : "false");
                if (use_int4_weights) {
                    std::cout << " [NOT IMPLEMENTED]";
                }
                std::cout << "\n";
            }
            else if (key == "tiled_workgroup_size") {
                tiled_workgroup_size = std::stoul(value);
                std::cout << "  tiled_workgroup_size = " << tiled_workgroup_size << "\n";
            }
            else if (key == "tiled_enable_profiling") {
                tiled_enable_profiling = ParseBool(value);
                std::cout << "  tiled_enable_profiling = " << (tiled_enable_profiling ? "true" : "false") << "\n";
            }
            else if (key == "weight_cache_max_mb") {
                weight_cache_max_mb = std::stoul(value);
                std::cout << "  weight_cache_max_mb = " << weight_cache_max_mb << " MB\n";
            }
            else if (key == "weight_cache_preload_all") {
                weight_cache_preload_all = ParseBool(value);
                std::cout << "  weight_cache_preload_all = " << (weight_cache_preload_all ? "true" : "false") << "\n";
            }
        }
    }
    
    file.close();
    return true;
}

bool GPUConfig::SaveToFile(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "[GPUConfig] Failed to write: " << filepath << "\n";
        return false;
    }
    
    file << "; RawrXD GPU Configuration\n";
    file << "; Generated automatically\n\n";
    
    file << "[gpu]\n";
    file << "; Phase 1: Tiled MatMul (EXPERIMENTAL - currently slower)\n";
    file << "use_tiled_matmul = " << (use_tiled_matmul ? "true" : "false") << "\n\n";
    
    file << "; Phase 2: Weight Cache (PRODUCTION READY)\n";
    file << "use_weight_cache = " << (use_weight_cache ? "true" : "false") << "\n";
    file << "weight_cache_max_mb = " << weight_cache_max_mb << "\n";
    file << "weight_cache_preload_all = " << (weight_cache_preload_all ? "true" : "false") << "\n\n";
    
    file << "; Phase 3: Kernel Fusion (NOT IMPLEMENTED)\n";
    file << "use_fused_kernels = " << (use_fused_kernels ? "true" : "false") << "\n\n";
    
    file << "; Phase 4: Medusa Speculative (NOT IMPLEMENTED)\n";
    file << "use_medusa = " << (use_medusa ? "true" : "false") << "\n\n";
    
    file << "; Phase 5: Quantization (NOT IMPLEMENTED)\n";
    file << "use_fp8_compute = " << (use_fp8_compute ? "true" : "false") << "\n";
    file << "use_int4_weights = " << (use_int4_weights ? "true" : "false") << "\n\n";
    
    file << "; Tiled MatMul tuning (only used if enabled)\n";
    file << "tiled_workgroup_size = " << tiled_workgroup_size << "\n";
    file << "tiled_enable_profiling = " << (tiled_enable_profiling ? "true" : "false") << "\n";
    
    file.close();
    return true;
}

void GPUConfig::Print() const {
    std::cout << "\n========================================\n";
    std::cout << "GPU Configuration\n";
    std::cout << "========================================\n";
    
    std::cout << "\nPhase 1: Tiled MatMul\n";
    std::cout << "  use_tiled_matmul = " << (use_tiled_matmul ? "true" : "false");
    if (use_tiled_matmul) {
        std::cout << " [EXPERIMENTAL - currently slower]";
    } else {
        std::cout << " [DISABLED - using original MatMul]";
    }
    std::cout << "\n";
    std::cout << "  tiled_workgroup_size = " << tiled_workgroup_size << "\n";
    std::cout << "  tiled_enable_profiling = " << (tiled_enable_profiling ? "true" : "false") << "\n";
    
    std::cout << "\nPhase 2: Weight Cache\n";
    std::cout << "  use_weight_cache = " << (use_weight_cache ? "true" : "false");
    if (use_weight_cache) {
        std::cout << " [PRODUCTION - 7x speedup]";
    }
    std::cout << "\n";
    std::cout << "  weight_cache_max_mb = " << weight_cache_max_mb << " MB\n";
    std::cout << "  weight_cache_preload_all = " << (weight_cache_preload_all ? "true" : "false") << "\n";
    
    std::cout << "\nPhase 3: Kernel Fusion\n";
    std::cout << "  use_fused_kernels = " << (use_fused_kernels ? "true" : "false");
    std::cout << " [NOT IMPLEMENTED]\n";
    
    std::cout << "\nPhase 4: Medusa\n";
    std::cout << "  use_medusa = " << (use_medusa ? "true" : "false");
    std::cout << " [NOT IMPLEMENTED]\n";
    
    std::cout << "\nPhase 5: Quantization\n";
    std::cout << "  use_fp8_compute = " << (use_fp8_compute ? "true" : "false");
    std::cout << " [NOT IMPLEMENTED]\n";
    std::cout << "  use_int4_weights = " << (use_int4_weights ? "true" : "false");
    std::cout << " [NOT IMPLEMENTED]\n";
    
    std::cout << "\n========================================\n\n";
}

} // namespace Inference
} // namespace RawrXD
