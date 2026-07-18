// Phase Y.1/5: Plugin SDK
// RawrXD Plugin SDK - Developer toolkit for extending RawrXD

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Developer {

// Plugin API version
constexpr uint32_t PLUGIN_API_VERSION = 1;

// Plugin capabilities
enum class PluginCapability {
    TOOL_PROVIDER,      // Provides custom tools
    MODEL_PROVIDER,     // Provides custom model backends
    UI_EXTENSION,       // Extends the UI
    INFERENCE_HOOK,     // Hooks into inference pipeline
    MEMORY_PROVIDER,    // Provides custom memory backends
    AUTHENTICATION,     // Custom authentication methods
    TELEMETRY,          // Custom telemetry sinks
    SCHEDULER,          // Custom scheduling algorithms
};

// Plugin manifest
struct PluginManifest {
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    std::string license;
    std::string homepage;
    std::string repository;
    
    // API compatibility
    uint32_t api_version;
    std::vector<std::string> rawrxd_versions;  // Compatible RawrXD versions
    
    // Capabilities
    std::vector<PluginCapability> capabilities;
    
    // Entry points
    std::string entry_point;  // Main entry function name
    std::vector<std::string> exports;
    
    // Dependencies
    std::vector<std::string> dependencies;  // Other plugin IDs
    std::vector<std::string> system_requirements;
    
    // Configuration
    std::unordered_map<std::string, std::string> default_config;
    std::vector<std::string> required_permissions;
};

// Plugin context
struct PluginContext {
    std::string plugin_id;
    std::string rawrxd_version;
    std::string config_path;
    std::string data_path;
    std::string log_path;
    
    // Runtime info
    std::chrono::system_clock::time_point loaded_at;
    uint32_t thread_count;
    
    // Callbacks
    std::function<void(const std::string& level, const std::string& message)> log_callback;
    std::function<std::optional<std::string>(const std::string& key)> config_callback;
};

// Tool definition (for TOOL_PROVIDER plugins)
struct ToolDefinition {
    std::string name;
    std::string description;
    std::string category;
    
    // Schema
    std::string input_schema;   // JSON schema for input
    std::string output_schema;  // JSON schema for output
    
    // Execution
    std::function<std::string(const std::string& input_json)> execute;
    std::chrono::seconds timeout;
    
    // Metadata
    bool is_async;
    bool requires_confirmation;
    std::vector<std::string> required_permissions;
};

// Model backend definition (for MODEL_PROVIDER plugins)
struct ModelBackendDefinition {
    std::string name;
    std::string description;
    std::vector<std::string> supported_formats;  // gguf, onnx, etc.
    
    // Capabilities
    bool supports_gpu;
    bool supports_quantization;
    bool supports_streaming;
    
    // Functions
    std::function<bool(const std::string& model_path)> can_load;
    std::function<std::unique_ptr<class IModelBackend>(const std::string& model_path)> create;
};

// Model backend interface
class IModelBackend {
public:
    virtual ~IModelBackend() = default;
    
    // Lifecycle
    virtual bool Initialize(const std::unordered_map<std::string, std::string>& config) = 0;
    virtual void Shutdown() = 0;
    
    // Inference
    virtual std::string Generate(const std::string& prompt,
                                   const std::unordered_map<std::string, std::string>& params) = 0;
    virtual void GenerateStream(const std::string& prompt,
                                   const std::unordered_map<std::string, std::string>& params,
                                   std::function<void(const std::string& token)> callback) = 0;
    
    // State
    virtual void ClearContext() = 0;
    virtual std::unordered_map<std::string, std::string> GetStats() = 0;
};

// UI extension point (for UI_EXTENSION plugins)
struct UIExtensionPoint {
    std::string location;  // "sidebar", "toolbar", "statusbar", "panel", "dialog"
    std::string name;
    std::string description;
    
    // Rendering
    std::function<void(void* native_window_handle)> render_callback;
    std::function<void(const std::string& event, const std::string& data)> event_handler;
    
    // Layout
    uint32_t preferred_width;
    uint32_t preferred_height;
    bool is_resizable;
};

// Inference hook (for INFERENCE_HOOK plugins)
struct InferenceHook {
    std::string name;
    std::string stage;  // "pre_tokenize", "post_tokenize", "pre_generate", "post_generate"
    
    // Hook function
    std::function<std::string(const std::string& input, const std::unordered_map<std::string, std::string>& context)> hook;
    
    // Priority (lower = earlier)
    int32_t priority;
    bool is_enabled;
};

// Plugin interface
class IPlugin {
public:
    virtual ~IPlugin() = default;
    
    // Lifecycle
    virtual bool Initialize(const PluginContext& context) = 0;
    virtual void Shutdown() = 0;
    
    // Info
    virtual PluginManifest GetManifest() const = 0;
    virtual std::string GetStatus() const = 0;
    
    // Capabilities
    virtual std::vector<ToolDefinition> GetTools() { return {}; }
    virtual std::vector<ModelBackendDefinition> GetModelBackends() { return {}; }
    virtual std::vector<UIExtensionPoint> GetUIExtensions() { return {}; }
    virtual std::vector<InferenceHook> GetInferenceHooks() { return {}; }
    
    // Configuration
    virtual bool OnConfigChanged(const std::string& key, const std::string& value) { return true; }
    
    // Events
    virtual void OnSystemEvent(const std::string& event, const std::unordered_map<std::string, std::string>& data) {}
};

// Plugin manager interface
class IPluginManager {
public:
    virtual ~IPluginManager() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& plugin_directory) = 0;
    virtual void Shutdown() = 0;
    
    // Plugin management
    virtual bool LoadPlugin(const std::string& path) = 0;
    virtual bool UnloadPlugin(const std::string& plugin_id) = 0;
    virtual bool ReloadPlugin(const std::string& plugin_id) = 0;
    virtual bool EnablePlugin(const std::string& plugin_id) = 0;
    virtual bool DisablePlugin(const std::string& plugin_id) = 0;
    
    // Queries
    virtual std::vector<PluginManifest> ListPlugins() = 0;
    virtual std::optional<PluginManifest> GetPlugin(const std::string& plugin_id) = 0;
    virtual std::vector<PluginManifest> GetPluginsByCapability(PluginCapability capability) = 0;
    virtual bool IsPluginLoaded(const std::string& plugin_id) = 0;
    virtual bool IsPluginEnabled(const std::string& plugin_id) = 0;
    
    // Tools
    virtual std::vector<ToolDefinition> GetAllTools() = 0;
    virtual std::optional<ToolDefinition> GetTool(const std::string& name) = 0;
    
    // Model backends
    virtual std::vector<ModelBackendDefinition> GetAllModelBackends() = 0;
    virtual std::optional<ModelBackendDefinition> GetModelBackend(const std::string& name) = 0;
    
    // UI extensions
    virtual std::vector<UIExtensionPoint> GetAllUIExtensions() = 0;
    
    // Inference hooks
    virtual std::vector<InferenceHook> GetAllInferenceHooks() = 0;
    
    // Events
    virtual void BroadcastEvent(const std::string& event, 
                                   const std::unordered_map<std::string, std::string>& data) = 0;
    
    // Validation
    virtual bool ValidatePlugin(const std::string& path, std::string* error = nullptr) = 0;
    virtual std::string GetPluginErrors(const std::string& plugin_id) = 0;
};

// Plugin factory function type
using CreatePluginFunc = IPlugin* (*)();
using DestroyPluginFunc = void (*)(IPlugin*);

// Export macros for plugins
#define RAWRXD_PLUGIN_EXPORT extern "C" __declspec(dllexport)

#define RAWRXD_DEFINE_PLUGIN(PluginClass) \
    RAWRXD_PLUGIN_EXPORT RawrXD::Developer::IPlugin* CreatePlugin() { \
        return new PluginClass(); \
    } \
    RAWRXD_PLUGIN_EXPORT void DestroyPlugin(RawrXD::Developer::IPlugin* plugin) { \
        delete plugin; \
    } \
    RAWRXD_PLUGIN_EXPORT uint32_t GetAPIVersion() { \
        return RawrXD::Developer::PLUGIN_API_VERSION; \
    }

// Global plugin manager
extern std::unique_ptr<IPluginManager> g_plugin_manager;

// Initialize plugin manager
bool InitializePluginManager(const std::string& plugin_directory);
void ShutdownPluginManager();
bool IsPluginManagerEnabled();

} // namespace Developer
} // namespace RawrXD
