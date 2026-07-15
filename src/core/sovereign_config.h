// =============================================================================
// sovereign_config.h
// Configuration management for Sovereign Engine
// JSON-based, environment-aware, production-ready
// =============================================================================

#ifndef SOVEREIGN_CONFIG_H
#define SOVEREIGN_CONFIG_H

#include <string>
#include <stdint.h>

namespace Sovereign {

// =============================================================================
// Configuration Structure
// =============================================================================
struct SovereignConfig {
    // Model settings
    std::string model_path;
    std::string model_format = "auto";  // auto, gguf, onnx, etc.
    
    // Inference settings
    uint32_t max_tokens = 512;
    float temperature = 0.8f;
    float top_p = 0.95f;
    uint32_t top_k = 40;
    uint32_t seed = 0;  // 0 = random
    
    // Performance settings
    uint32_t num_threads = 0;  // 0 = auto-detect
    uint32_t batch_size = 1;
    bool use_mmap = true;
    bool lock_memory = false;
    
    // Memory settings
    uint64_t arena_size_mb = 4096;  // 4GB default
    uint64_t kv_cache_size_mb = 512;  // 512MB default
    
    // Hardware settings
    bool use_avx512 = true;
    bool use_avx2 = true;
    bool use_gpu = false;  // Future: GPU offload
    
    // Logging settings
    std::string log_level = "info";  // debug, info, warn, error
    std::string log_file;  // empty = stdout only
    bool log_colors = true;
    
    // Server settings (for API mode)
    uint32_t server_port = 8080;
    std::string server_host = "127.0.0.1";
    
    // Load from JSON file
    static SovereignConfig FromFile(const std::string& path);
    
    // Load from JSON string
    static SovereignConfig FromJson(const std::string& json);
    
    // Save to JSON file
    bool SaveToFile(const std::string& path) const;
    
    // Validate configuration
    bool Validate(std::string& error) const;
    
    // Print configuration
    void Print() const;
    
    // Get default config path
    static std::string GetDefaultConfigPath();
};

// =============================================================================
// Environment Detection
// =============================================================================
struct SystemInfo {
    uint32_t cpu_cores = 0;
    uint32_t cpu_threads = 0;
    uint64_t total_ram_mb = 0;
    uint64_t available_ram_mb = 0;
    bool has_avx512 = false;
    bool has_avx2 = false;
    bool has_fma = false;
    
    static SystemInfo Detect();
    void Print() const;
};

// =============================================================================
// Status Codes
// =============================================================================
enum class SovereignStatus : int {
    OK = 0,
    ERR_INVALID_CONFIG = -1,
    ERR_OUT_OF_MEMORY = -2,
    ERR_MODEL_LOAD = -3,
    ERR_MODEL_FORMAT = -4,
    ERR_HARDWARE_UNSUPPORTED = -5,
    ERR_FILE_NOT_FOUND = -6,
    ERR_PERMISSION_DENIED = -7,
    ERR_RUNTIME = -8,
    ERR_NOT_INITIALIZED = -9,
    ERR_ALREADY_RUNNING = -10,
    ERR_INVALID_ARGUMENT = -11,
    ERR_QUANTIZATION = -12,
    ERR_TOKENIZER = -13,
};

const char* SovereignStatusToString(SovereignStatus status);

} // namespace Sovereign

#endif // SOVEREIGN_CONFIG_H
