#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <future>
#include "intent_config.hpp"
#include "intent_abi.hpp"

// =============================================================================
// Model Adapter Interface - Makes models interchangeable
// Toggleable at compile-time and runtime
// =============================================================================

namespace RawrXD {
namespace Intent {

// Model capabilities
enum class ModelCapability : uint32_t {
    NONE = 0,
    COMPLETION = 1 << 0,
    CHAT = 1 << 1,
    STREAMING = 1 << 2,
    FUNCTION_CALLING = 1 << 3,
    REASONING = 1 << 4,
    CODE_GENERATION = 1 << 5,
    CODE_ANALYSIS = 1 << 6,
    LONG_CONTEXT = 1 << 7,
    TOOL_USE = 1 << 8,
};

inline ModelCapability operator|(ModelCapability a, ModelCapability b) {
    return static_cast<ModelCapability>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

// Model context - what the model sees
struct ModelContext {
    std::string system_prompt;
    std::vector<std::pair<std::string, std::string>> messages;  // role, content
    std::vector<std::string> relevant_files;
    std::vector<std::string> relevant_symbols;
    std::string compiler_errors;
    std::string test_results;
    std::string telemetry;
    
    // Constraints
    uint32_t max_tokens = 4096;
    float temperature = 0.7f;
    std::string response_format;  // "json", "text", etc.
};

// Model response
struct ModelResponse {
    bool success = false;
    std::string content;
    std::string reasoning;
    std::optional<IntentRequest> intent;
    float confidence = 0.0f;
    uint32_t tokens_used = 0;
    uint64_t latency_ms = 0;
    std::vector<std::string> warnings;
};

// Available tools for the model
struct Tool {
    std::string name;
    std::string description;
    std::string parameters_schema;  // JSON schema
};

// Abstract model backend interface
class IReasoningBackend {
public:
    virtual ~IReasoningBackend() = default;
    
    // Core completion
    virtual ModelResponse Complete(const ModelContext& ctx) = 0;
    
    // Streaming completion (if supported)
    virtual void CompleteStreaming(
        const ModelContext& ctx,
        std::function<void(const std::string& chunk)> on_chunk
    ) = 0;
    
    // Check capabilities
    virtual bool Supports(ModelCapability cap) const = 0;
    
    // Backend info
    virtual std::string GetName() const = 0;
    virtual std::string GetVersion() const = 0;
    virtual uint32_t GetMaxContextLength() const = 0;
    
    // Health check
    virtual bool IsHealthy() const = 0;
    
    // Toggle
    virtual void SetEnabled(bool enabled) = 0;
    virtual bool IsEnabled() const = 0;
};

// Backend configuration
struct BackendConfig {
    std::string name;
    std::string type;  // "kimi", "moonshot", "openai", "gguf", etc.
    std::string endpoint;
    std::string api_key;
    std::string model_name;
    uint32_t timeout_ms = 30000;
    uint32_t max_retries = 3;
    bool enabled = true;
    uint32_t priority = 0;  // Higher = preferred
    
    // Capability overrides
    ModelCapability capabilities = ModelCapability::NONE;
    
    // Toggle
    static BackendConfig& Instance();
    void LoadFromFile(const std::string& path);
    void SaveToFile(const std::string& path) const;
};

// Model adapter - routes to appropriate backend
class ModelAdapter {
public:
    static ModelAdapter& Instance();
    
    // Register a backend
    void RegisterBackend(std::shared_ptr<IReasoningBackend> backend);
    void UnregisterBackend(const std::string& name);
    
    // Select best backend for task
    std::shared_ptr<IReasoningBackend> SelectBackend(ModelCapability required);
    std::shared_ptr<IReasoningBackend> SelectBackend(
        ModelCapability required,
        const std::string& preferred
    );
    
    // Complete with automatic backend selection
    ModelResponse Complete(const ModelContext& ctx);
    ModelResponse Complete(const ModelContext& ctx, const std::string& preferred_backend);
    
    // Convert model response to intent
    IntentResponse ConvertToIntent(const ModelResponse& response);
    
    // Toggle
    void EnableAdapter(bool enable) { enabled_ = enable; }
    bool IsEnabled() const { return enabled_.load(); }
    
    // Get all backends
    std::vector<std::shared_ptr<IReasoningBackend>> GetAllBackends() const;
    std::vector<std::string> GetBackendNames() const;
    
private:
    ModelAdapter() = default;
    
    std::vector<std::shared_ptr<IReasoningBackend>> backends_;
    mutable std::mutex backends_mutex_;
    std::atomic<bool> enabled_{true};
};

// Concrete backend implementations (stubs for now)

class KimiBackend : public IReasoningBackend {
public:
    explicit KimiBackend(const BackendConfig& config);
    
    ModelResponse Complete(const ModelContext& ctx) override;
    void CompleteStreaming(
        const ModelContext& ctx,
        std::function<void(const std::string& chunk)> on_chunk
    ) override;
    bool Supports(ModelCapability cap) const override;
    std::string GetName() const override { return "Kimi"; }
    std::string GetVersion() const override { return "v1"; }
    uint32_t GetMaxContextLength() const override { return 200000; }
    bool IsHealthy() const override;
    void SetEnabled(bool enabled) override { enabled_ = enabled; }
    bool IsEnabled() const override { return enabled_.load(); }
    
private:
    BackendConfig config_;
    std::atomic<bool> enabled_{true};
};

class MoonshotBackend : public IReasoningBackend {
public:
    explicit MoonshotBackend(const BackendConfig& config);
    
    ModelResponse Complete(const ModelContext& ctx) override;
    void CompleteStreaming(
        const ModelContext& ctx,
        std::function<void(const std::string& chunk)> on_chunk
    ) override;
    bool Supports(ModelCapability cap) const override;
    std::string GetName() const override { return "Moonshot"; }
    std::string GetVersion() const override { return "v1"; }
    uint32_t GetMaxContextLength() const override { return 128000; }
    bool IsHealthy() const override;
    void SetEnabled(bool enabled) override { enabled_ = enabled; }
    bool IsEnabled() const override { return enabled_.load(); }
    
private:
    BackendConfig config_;
    std::atomic<bool> enabled_{true};
};

class GGUFBackend : public IReasoningBackend {
public:
    explicit GGUFBackend(const BackendConfig& config);
    
    ModelResponse Complete(const ModelContext& ctx) override;
    void CompleteStreaming(
        const ModelContext& ctx,
        std::function<void(const std::string& chunk)> on_chunk
    ) override;
    bool Supports(ModelCapability cap) const override;
    std::string GetName() const override { return "GGUF"; }
    std::string GetVersion() const override { return "local"; }
    uint32_t GetMaxContextLength() const override { return 32768; }
    bool IsHealthy() const override;
    void SetEnabled(bool enabled) override { enabled_ = enabled; }
    bool IsEnabled() const override { return enabled_.load(); }
    
private:
    BackendConfig config_;
    std::atomic<bool> enabled_{true};
    void* model_handle_ = nullptr;
};

// Compile-time conditional macros
#if RAWR_MODEL_ADAPTER_ENABLED
    #define RAWR_CT_MODEL_ADAPTER(code) code
#else
    #define RAWR_CT_MODEL_ADAPTER(code)
#endif

} // namespace Intent
} // namespace RawrXD
