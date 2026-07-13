// Backend Factory and Configuration Management
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "sovereign_backend.hpp"
#include "ollama_backend.hpp"
#include <memory>
#include <string>

namespace rawrxd::benchmark {

// ============================================================================
// Backend Factory
// ============================================================================

class BackendFactory {
public:
    // Create backend adapter based on type
    static std::unique_ptr<BackendAdapter> Create(BackendType type);
    
    // Create backend adapter from string name
    static std::unique_ptr<BackendAdapter> Create(const std::string& name);
    
    // Get available backend types
    static std::vector<BackendType> GetAvailableBackends();
    
    // Check if backend is available
    static bool IsAvailable(BackendType type);
    
    // Get backend display name
    static const char* GetDisplayName(BackendType type);
    
    // Get backend description
    static const char* GetDescription(BackendType type);
};

// ============================================================================
// Configuration Manager
// ============================================================================

class ConfigurationManager {
public:
    // Load configuration from file
    static BenchmarkConfig LoadFromFile(const std::string& path);
    
    // Save configuration to file
    static bool SaveToFile(const BenchmarkConfig& config, const std::string& path);
    
    // Load from environment variables
    static BenchmarkConfig LoadFromEnvironment();
    
    // Load from command line arguments
    static BenchmarkConfig LoadFromArgs(int argc, char** argv);
    
    // Merge configurations (right takes precedence)
    static BenchmarkConfig Merge(const BenchmarkConfig& base, 
                                  const BenchmarkConfig& override);
    
    // Validate configuration
    static bool Validate(const BenchmarkConfig& config, std::string& error);
    
    // Print configuration
    static void Print(const BenchmarkConfig& config);
};

// ============================================================================
// Backend Configuration
// ============================================================================

struct BackendConfiguration {
    // Common settings
    std::string endpoint;
    std::string model_name;
    int max_tokens = 512;
    float temperature = 0.0f;
    int seed = 42;
    
    // Connection settings
    int connect_timeout_ms = 5000;
    int read_timeout_ms = 30000;
    int total_timeout_ms = 60000;
    int max_retries = 3;
    int retry_delay_ms = 1000;
    bool exponential_backoff = true;
    
    // Pool settings
    bool enable_connection_pool = true;
    size_t max_connections = 10;
    int idle_timeout_ms = 30000;
    
    // Sovereign-specific
    struct SovereignConfig {
        bool enable_seg = true;
        bool enable_learning = true;
        bool enable_telemetry = true;
        std::string coordination_strategy = "round_robin";
    } sovereign;
    
    // Ollama-specific
    struct OllamaConfig {
        int num_ctx = 2048;
        int num_keep = 5;
        int num_gpu = 1;
        bool low_vram = false;
        bool f16_kv = true;
        int num_thread = 0;  // 0 = auto
    } ollama;
    
    // Load from JSON
    static BackendConfiguration FromJson(const std::string& json);
    std::string ToJson() const;
    
    // Apply to BenchmarkConfig
    void ApplyTo(BenchmarkConfig& config) const;
    
    // Extract from BenchmarkConfig
    static BackendConfiguration FromBenchmarkConfig(const BenchmarkConfig& config);
};

// ============================================================================
// Endpoint Manager
// ============================================================================

class EndpointManager {
public:
    // Register endpoint
    void RegisterEndpoint(BackendType type, const std::string& endpoint);
    
    // Get endpoint for backend
    std::string GetEndpoint(BackendType type) const;
    
    // Check endpoint health
    bool CheckEndpoint(BackendType type) const;
    
    // Wait for endpoint to be ready
    bool WaitForReady(BackendType type, int timeout_seconds) const;
    
    // Get default endpoints
    static std::string GetDefaultEndpoint(BackendType type);
    
    // Parse endpoint URL
    static bool ParseEndpoint(const std::string& endpoint, 
                               std::string& protocol,
                               std::string& host, 
                               int& port,
                               std::string& path);
    
    // Build full URL
    static std::string BuildUrl(const std::string& endpoint, 
                                 const std::string& path);

private:
    std::map<BackendType, std::string> endpoints_;
};

// ============================================================================
// Model Configuration
// ============================================================================

struct ModelConfiguration {
    std::string name;
    std::string display_name;
    std::string family;
    std::string quantization;
    int64_t parameter_count = 0;
    int context_length = 4096;
    std::vector<std::string> capabilities;
    
    // Backend-specific model names
    std::map<BackendType, std::string> backend_names;
    
    // Get model name for specific backend
    std::string GetBackendName(BackendType backend) const;
    
    // Check if model supports capability
    bool HasCapability(const std::string& capability) const;
};

class ModelRegistry {
public:
    // Register default models
    void RegisterDefaults();
    
    // Register custom model
    void RegisterModel(const ModelConfiguration& model);
    
    // Get model configuration
    std::optional<ModelConfiguration> GetModel(const std::string& name) const;
    
    // Get all models
    std::vector<ModelConfiguration> GetAllModels() const;
    
    // Get models for backend
    std::vector<ModelConfiguration> GetModelsForBackend(BackendType backend) const;
    
    // Get default model for backend
    ModelConfiguration GetDefaultModel(BackendType backend) const;
};

// ============================================================================
// Validation Utilities
// ============================================================================

class ConfigValidator {
public:
    // Validate backend type
    static bool ValidateBackendType(BackendType type, std::string& error);
    
    // Validate endpoint URL
    static bool ValidateEndpoint(const std::string& endpoint, std::string& error);
    
    // Validate model name
    static bool ValidateModelName(const std::string& model, std::string& error);
    
    // Validate numeric ranges
    static bool ValidateRange(int value, int min, int max, 
                                const std::string& name, std::string& error);
    static bool ValidateRange(float value, float min, float max, 
                               const std::string& name, std::string& error);
    
    // Validate file path
    static bool ValidatePath(const std::string& path, bool must_exist, 
                              std::string& error);
};

// ============================================================================
// Environment Configuration
// ============================================================================

class EnvironmentConfig {
public:
    // Get environment variable as string
    static std::string GetString(const std::string& name, 
                                  const std::string& default_value = "");
    
    // Get environment variable as int
    static int GetInt(const std::string& name, int default_value = 0);
    
    // Get environment variable as bool
    static bool GetBool(const std::string& name, bool default_value = false);
    
    // Get environment variable as float
    static float GetFloat(const std::string& name, float default_value = 0.0f);
    
    // Check if environment variable exists
    static bool Has(const std::string& name);
    
    // Set environment variable
    static bool Set(const std::string& name, const std::string& value);
    
    // Configuration keys
    static constexpr const char* BACKEND_TYPE = "RAWRXD_BENCHMARK_BACKEND";
    static constexpr const char* ENDPOINT = "RAWRXD_BENCHMARK_ENDPOINT";
    static constexpr const char* MODEL_NAME = "RAWRXD_BENCHMARK_MODEL";
    static constexpr const char* SWARM_SIZE = "RAWRXD_BENCHMARK_SWARM_SIZE";
    static constexpr const char* WARMUP_RUNS = "RAWRXD_BENCHMARK_WARMUP_RUNS";
    static constexpr const char* MEASURED_RUNS = "RAWRXD_BENCHMARK_MEASURED_RUNS";
    static constexpr const char* OUTPUT_DIR = "RAWRXD_BENCHMARK_OUTPUT_DIR";
    static constexpr const char* VERBOSE = "RAWRXD_BENCHMARK_VERBOSE";
};

} // namespace rawrxd::benchmark
