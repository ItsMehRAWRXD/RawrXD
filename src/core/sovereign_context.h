// =============================================================================
// sovereign_context.h
// Production-ready C++ API for Sovereign Engine
// Clean interface, opaque implementation, status codes
// =============================================================================

#ifndef SOVEREIGN_CONTEXT_H
#define SOVEREIGN_CONTEXT_H

#include "sovereign_config.h"
#include <string>
#include <vector>
#include <memory>

namespace Sovereign {

// Forward declarations
class TransformerForward;
struct ModelWeights;
struct KVCache;

// =============================================================================
// Generation Result
// =============================================================================
struct GenerationResult {
    std::string text;
    std::vector<uint32_t> tokens;
    float tokens_per_second = 0.0f;
    uint32_t tokens_generated = 0;
    SovereignStatus status = SovereignStatus::OK;
    std::string error_message;
    
    bool Success() const { return status == SovereignStatus::OK; }
};

// =============================================================================
// Model Info
// =============================================================================
struct ModelInfo {
    std::string name;
    std::string architecture;
    uint32_t num_layers = 0;
    uint32_t num_heads = 0;
    uint32_t hidden_size = 0;
    uint32_t vocab_size = 0;
    uint32_t context_length = 0;
    std::string quantization_format;
    size_t model_size_bytes = 0;
};

// =============================================================================
// Performance Metrics
// =============================================================================
struct PerformanceMetrics {
    float tokens_per_second = 0.0f;
    float latency_ms = 0.0f;
    uint64_t total_tokens_generated = 0;
    uint64_t total_prompt_tokens = 0;
    uint64_t memory_usage_bytes = 0;
    float cpu_utilization = 0.0f;
};

// =============================================================================
// SovereignContext: The Main API
// =============================================================================
class SovereignContext {
public:
    // Construction / Destruction
    SovereignContext();
    explicit SovereignContext(const SovereignConfig& config);
    ~SovereignContext(); // Defined in .cpp where Impl is complete
    
    // Disable copy, enable move
    SovereignContext(const SovereignContext&) = delete;
    SovereignContext& operator=(const SovereignContext&) = delete;
    SovereignContext(SovereignContext&&) noexcept;
    SovereignContext& operator=(SovereignContext&&) noexcept;
    
    // Initialization
    SovereignStatus Initialize();
    SovereignStatus Initialize(const SovereignConfig& config);
    bool IsInitialized() const;
    void Shutdown();
    
    // Model Management
    SovereignStatus LoadModel(const std::string& model_path);
    SovereignStatus LoadModel(const std::string& model_path, const std::string& format);
    void UnloadModel();
    bool IsModelLoaded() const;
    ModelInfo GetModelInfo() const;
    
    // Generation
    GenerationResult Generate(const std::string& prompt);
    GenerationResult Generate(const std::string& prompt, uint32_t max_tokens);
    GenerationResult Generate(const std::string& prompt, const SovereignConfig& override_config);
    
    // Token-level access (advanced)
    std::vector<uint32_t> Tokenize(const std::string& text);
    std::string Detokenize(const std::vector<uint32_t>& tokens);
    GenerationResult GenerateFromTokens(const std::vector<uint32_t>& prompt_tokens);
    
    // Configuration
    SovereignConfig GetConfig() const;
    void SetConfig(const SovereignConfig& config);
    
    // Metrics
    PerformanceMetrics GetMetrics() const;
    void ResetMetrics();
    
    // System
    static SystemInfo GetSystemInfo();
    static std::string GetVersion();
    static bool IsHardwareSupported();
    
    // Status
    SovereignStatus GetLastStatus() const;
    std::string GetLastError() const;
    void ClearError();
    
private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

// =============================================================================
// C API (for FFI / bindings)
// =============================================================================
extern "C" {
    typedef void* SovereignHandle;
    
    SovereignHandle Sovereign_Create();
    SovereignHandle Sovereign_CreateWithConfig(const char* config_json);
    void Sovereign_Destroy(SovereignHandle handle);
    
    int Sovereign_LoadModel(SovereignHandle handle, const char* model_path);
    void Sovereign_UnloadModel(SovereignHandle handle);
    int Sovereign_IsModelLoaded(SovereignHandle handle);
    
    int Sovereign_Generate(SovereignHandle handle, const char* prompt, 
                           char* output_buffer, size_t buffer_size);
    
    int Sovereign_GetLastError(SovereignHandle handle, char* buffer, size_t buffer_size);
    void Sovereign_ClearError(SovereignHandle handle);
    
    void Sovereign_GetVersion(char* buffer, size_t buffer_size);
}

} // namespace Sovereign

#endif // SOVEREIGN_CONTEXT_H
