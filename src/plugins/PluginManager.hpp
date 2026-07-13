// Phase M.1/5: Plugin System Architecture
// RawrXD Plugin Manager - Dynamic Extension System

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <functional>
#include <filesystem>
#include <mutex>

namespace RawrXD {
namespace Plugins {

// Plugin interface version
constexpr uint32_t PLUGIN_INTERFACE_VERSION = 1;

// Forward declarations
class IPlugin;
class PluginContext;

// Plugin metadata structure
struct PluginMetadata {
    std::string id;                    // Unique plugin ID
    std::string name;                  // Display name
    std::string version;               // Semantic version
    std::string author;                // Author/organization
    std::string description;           // Short description
    std::string license;               // License type
    std::vector<std::string> dependencies; // Required plugins
    std::vector<std::string> exports;    // Exported capabilities
    uint32_t api_version;              // Required API version
    bool hot_reloadable;               // Supports hot reload
};

// Plugin capability types
enum class PluginCapability {
    INFERENCE_PREPROCESSOR,    // Pre-process inputs
    INFERENCE_POSTPROCESSOR,   // Post-process outputs
    MODEL_LOADER,              // Custom model format support
    TOKENIZER_EXTENSION,       // Extended tokenizer features
    SAMPLING_STRATEGY,         // Custom sampling algorithms
    TOOL_PROVIDER,             // External tool integration
    MONITORING_EXPORTER,       // Metrics export
    UI_EXTENSION,              // UI components
    API_MIDDLEWARE,            // API request/response handling
    CUSTOM_OPERATOR            // Custom compute operators
};

// Plugin interface - all plugins must implement
class IPlugin {
public:
    virtual ~IPlugin() = default;
    
    // Lifecycle methods
    virtual bool Initialize(PluginContext* context) = 0;
    virtual void Shutdown() = 0;
    virtual bool Reload() { return false; }  // Optional hot reload
    
    // Metadata
    virtual const PluginMetadata& GetMetadata() const = 0;
    
    // Capability registration
    virtual std::vector<PluginCapability> GetCapabilities() const = 0;
    virtual bool HasCapability(PluginCapability capability) const = 0;
    
    // Health check
    virtual bool IsHealthy() const { return true; }
    virtual std::string GetStatus() const { return "OK"; }
};

// Plugin context - provides access to core systems
class PluginContext {
public:
    // Logging
    virtual void LogInfo(const std::string& message) = 0;
    virtual void LogWarning(const std::string& message) = 0;
    virtual void LogError(const std::string& message) = 0;
    
    // Configuration
    virtual std::string GetConfigValue(const std::string& key) = 0;
    virtual void SetConfigValue(const std::string& key, const std::string& value) = 0;
    
    // Event system
    using EventHandler = std::function<void(const std::string& event, const std::string& data)>;
    virtual void SubscribeToEvent(const std::string& event, EventHandler handler) = 0;
    virtual void PublishEvent(const std::string& event, const std::string& data) = 0;
    
    // Plugin interop
    virtual IPlugin* GetPlugin(const std::string& id) = 0;
    virtual bool IsPluginLoaded(const std::string& id) = 0;
    
    // Resource management
    virtual std::string GetDataDirectory() const = 0;
    virtual std::string GetCacheDirectory() const = 0;
};

// Plugin instance wrapper
struct PluginInstance {
    std::string path;
    PluginMetadata metadata;
    std::unique_ptr<IPlugin> plugin;
    void* library_handle;
    std::chrono::steady_clock::time_point loaded_at;
    bool enabled;
    
    PluginInstance() : library_handle(nullptr), enabled(false) {}
};

// Plugin manager - central registry and lifecycle management
class PluginManager {
public:
    PluginManager();
    ~PluginManager();
    
    // Initialization
    bool Initialize(const std::string& plugin_directory);
    void Shutdown();
    
    // Plugin loading
    bool LoadPlugin(const std::string& path);
    bool LoadPlugin(const std::string& path, const PluginMetadata& metadata);
    bool UnloadPlugin(const std::string& id);
    bool ReloadPlugin(const std::string& id);
    
    // Bulk operations
    int LoadAllPlugins();
    void UnloadAllPlugins();
    int ReloadAllPlugins();
    
    // Query
    std::vector<std::string> GetLoadedPlugins() const;
    std::vector<std::string> GetPluginsByCapability(PluginCapability capability) const;
    const PluginMetadata* GetPluginMetadata(const std::string& id) const;
    IPlugin* GetPlugin(const std::string& id);
    bool IsPluginLoaded(const std::string& id) const;
    bool IsPluginEnabled(const std::string& id) const;
    
    // Enable/disable
    bool EnablePlugin(const std::string& id);
    bool DisablePlugin(const std::string& id);
    
    // Capability discovery
    std::vector<IPlugin*> GetPluginsWithCapability(PluginCapability capability);
    
    // Event system
    void SubscribeToEvent(const std::string& event, PluginContext::EventHandler handler);
    void PublishEvent(const std::string& event, const std::string& data);
    
    // Health monitoring
    struct HealthStatus {
        std::string plugin_id;
        bool healthy;
        std::string status;
        std::chrono::steady_clock::time_point last_check;
    };
    std::vector<HealthStatus> GetHealthStatus() const;
    
    // Statistics
    struct Statistics {
        size_t total_loaded;
        size_t total_enabled;
        size_t total_failed;
        std::chrono::steady_clock::time_point uptime;
    };
    Statistics GetStatistics() const;
    
private:
    std::unordered_map<std::string, std::unique_ptr<PluginInstance>> plugins_;
    std::unordered_map<PluginCapability, std::vector<std::string>> capability_index_;
    std::string plugin_directory_;
    std::mutex mutex_;
    bool initialized_;
    std::chrono::steady_clock::time_point start_time_;
    
    // Platform-specific loading
    void* LoadLibrary(const std::string& path);
    void UnloadLibrary(void* handle);
    void* GetSymbol(void* handle, const std::string& name);
    
    // Dependency resolution
    bool CheckDependencies(const PluginMetadata& metadata);
    bool ResolveDependencies(const std::string& id);
    
    // Event subscribers
    std::unordered_map<std::string, std::vector<PluginContext::EventHandler>> event_subscribers_;
};

// Plugin factory function type
using CreatePluginFunc = IPlugin* (*)();
using DestroyPluginFunc = void (*)(IPlugin*);
using GetMetadataFunc = const PluginMetadata* (*)();

// Convenience macros for plugin implementation
#define RAWRXD_PLUGIN_ENTRYPOINT(PluginClass) \
    extern "C" { \
        RAWRXD_PLUGIN_API RawrXD::Plugins::IPlugin* CreatePlugin() { \
            return new PluginClass(); \
        } \
        RAWRXD_PLUGIN_API void DestroyPlugin(RawrXD::Plugins::IPlugin* plugin) { \
            delete plugin; \
        } \
        RAWRXD_PLUGIN_API const RawrXD::Plugins::PluginMetadata* GetMetadata() { \
            static RawrXD::Plugins::PluginMetadata metadata = PluginClass::GetStaticMetadata(); \
            return &metadata; \
        } \
    }

} // namespace Plugins
} // namespace RawrXD
