//==============================================================================
// SovereignConfig.hpp
// Configuration management for Sovereign CLI
//
// Phase 7C.2 Complete Integration
//==============================================================================

#ifndef SOVEREIGN_CONFIG_HPP
#define SOVEREIGN_CONFIG_HPP

#include <cstddef>
#include <cstdint>

namespace sovereign {
namespace cli {

// Default configuration values
constexpr size_t DEFAULT_MEMORY_LIMIT_MB = 0;  // Unlimited
constexpr int DEFAULT_NUM_THREADS = 0;         // Auto-detect
constexpr bool DEFAULT_VERBOSE = false;
constexpr bool DEFAULT_USE_MASM = true;
constexpr bool DEFAULT_USE_INTRINSICS = true;
constexpr bool DEFAULT_USE_REFERENCE = false;

// Performance tuning defaults
constexpr size_t DEFAULT_BATCH_SIZE = 512;
constexpr size_t DEFAULT_CACHE_SIZE_MB = 1024;
constexpr float DEFAULT_TEMPERATURE = 0.8f;
constexpr int DEFAULT_MAX_TOKENS = 2048;

//==============================================================================
// Configuration Structure
//==============================================================================
struct SovereignConfig {
    // General settings
    bool verbose = DEFAULT_VERBOSE;
    int numThreads = DEFAULT_NUM_THREADS;
    size_t memoryLimitMB = DEFAULT_MEMORY_LIMIT_MB;
    
    // Backend selection
    bool useMASM = DEFAULT_USE_MASM;
    bool useIntrinsics = DEFAULT_USE_INTRINSICS;
    bool useReference = DEFAULT_USE_REFERENCE;
    
    // Performance settings
    size_t batchSize = DEFAULT_BATCH_SIZE;
    size_t cacheSizeMB = DEFAULT_CACHE_SIZE_MB;
    
    // Inference settings
    float temperature = DEFAULT_TEMPERATURE;
    int maxTokens = DEFAULT_MAX_TOKENS;
    
    // Paths
    char modelPath[256] = {0};
    char tokenizerPath[256] = {0};
    char cachePath[256] = {0};
    
    // Feature flags
    bool enableFlashAttention = true;
    bool enableQuantization = true;
    bool enableStreaming = false;
    bool enableTelemetry = false;
};

//==============================================================================
// Configuration Manager
//==============================================================================
class ConfigManager {
public:
    static ConfigManager& getInstance();
    
    // Load/Save configuration
    bool loadFromFile(const char* path);
    bool saveToFile(const char* path);
    
    // Load from environment variables
    bool loadFromEnvironment();
    
    // Get current configuration
    const SovereignConfig& getConfig() const { return config_; }
    SovereignConfig& getConfig() { return config_; }
    
    // Reset to defaults
    void resetToDefaults();
    
    // Validate configuration
    bool validate();
    
    // Print current configuration
    void print() const;
    
private:
    ConfigManager();
    ~ConfigManager() = default;
    
    SovereignConfig config_;
    bool loaded_ = false;
};

} // namespace cli
} // namespace sovereign

#endif // SOVEREIGN_CONFIG_HPP
