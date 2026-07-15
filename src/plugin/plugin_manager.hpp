// RawrXD Plugin Manager
// Phase AI: Plugin System

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <filesystem>

namespace rawrxd {
namespace plugin {

// Plugin API version
constexpr uint32_t PLUGIN_API_VERSION = 1;

// Plugin types
enum class PluginType {
    BACKEND,        // Inference backend
    MODEL_LOADER,   // Custom model loader
    TOKENIZER,      // Custom tokenizer
    SAMPLER,        // Custom sampling strategy
    PREPROCESSOR,   // Input preprocessor
    POSTPROCESSOR,  // Output postprocessor
    LOGGER,         // Custom logger
    METRICS,        // Custom metrics exporter
    AUTH,           // Authentication provider
    CUSTOM          // Custom plugin type
};

// Plugin state
enum class PluginState {
    UNLOADED,
    LOADED,
    INITIALIZED,
    RUNNING,
    ERROR,
    DISABLED
};

// Plugin information
struct PluginInfo {
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    std::string license;
    PluginType type;
    uint32_t api_version;
    std::vector<std::string> dependencies;
    std::unordered_map<std::string, std::string> metadata;
    
    PluginInfo() : type(PluginType::CUSTOM), api_version(PLUGIN_API_VERSION) {}
};

// Plugin configuration
struct PluginConfig {
    std::string plugin_id;
    bool enabled;
    int priority;  // Higher priority = loaded first
    std::unordered_map<std::string, std::string> settings;
    std::vector<std::string> hooks;  // Hooks to register for
};

// Plugin interface (base class for all plugins)
class IPlugin {
public:
    virtual ~IPlugin() = default;
    
    // Lifecycle methods
    virtual bool initialize(const std::unordered_map<std::string, std::string>& config) = 0;
    virtual void shutdown() = 0;
    
    // Information
    virtual PluginInfo getInfo() const = 0;
    
    // State management
    virtual PluginState getState() const = 0;
    virtual void setState(PluginState state) = 0;
    
    // Health check
    virtual bool isHealthy() const = 0;
    
    // Configuration
    virtual void onConfigChanged(const std::string& key, const std::string& value) = 0;
};

// Hook types for plugin interception
enum class HookType {
    PRE_INFERENCE,      // Before inference
    POST_INFERENCE,     // After inference
    PRE_TOKENIZE,       // Before tokenization
    POST_TOKENIZE,      // After tokenization
    PRE_LOAD_MODEL,     // Before model loading
    POST_LOAD_MODEL,    // After model loading
    ON_ERROR,           // On error occurrence
    ON_SHUTDOWN,        // On system shutdown
    CUSTOM              // Custom hook
};

// Hook context
struct HookContext {
    HookType type;
    std::string operation;
    std::unordered_map<std::string, std::string> metadata;
    std::unordered_map<std::string, void*> data;
    bool cancelled;
    std::string cancel_reason;
    
    HookContext() : type(HookType::CUSTOM), cancelled(false) {}
};

// Hook callback signature
using HookCallback = std::function<void(HookContext& context)>;

// Plugin hook registration
struct HookRegistration {
    HookType type;
    std::string plugin_id;
    int priority;
    HookCallback callback;
};

// Forward declarations
class PluginLoader;
class PluginSandbox;
class HookManager;

/**
 * PluginManager - Central plugin management
 * 
 * Manages plugin lifecycle, loading, and hook execution.
 */
class PluginManager {
public:
    PluginManager();
    ~PluginManager();
    
    // Initialize plugin system
    bool initialize(const std::string& plugin_dir = "plugins");
    void shutdown();
    
    // Plugin discovery and loading
    std::vector<PluginInfo> discoverPlugins();
    bool loadPlugin(const std::string& plugin_path);
    bool unloadPlugin(const std::string& plugin_id);
    bool reloadPlugin(const std::string& plugin_id);
    
    // Plugin management
    bool enablePlugin(const std::string& plugin_id);
    bool disablePlugin(const std::string& plugin_id);
    bool configurePlugin(const std::string& plugin_id, const PluginConfig& config);
    
    // Plugin queries
    std::shared_ptr<IPlugin> getPlugin(const std::string& plugin_id) const;
    std::vector<std::shared_ptr<IPlugin>> getPluginsByType(PluginType type) const;
    std::vector<std::shared_ptr<IPlugin>> getAllPlugins() const;
    std::vector<PluginInfo> getLoadedPluginInfo() const;
    
    // Hook management
    void registerHook(const std::string& plugin_id, HookType type, HookCallback callback, int priority = 0);
    void unregisterHook(const std::string& plugin_id, HookType type);
    void executeHooks(HookType type, HookContext& context);
    bool executeHooksWithCancel(HookType type, HookContext& context);  // Returns false if cancelled
    
    // Event notification
    void notifyEvent(const std::string& event_type, const std::unordered_map<std::string, std::string>& data);
    
    // Status
    bool isHealthy() const;
    size_t getLoadedPluginCount() const;
    size_t getActivePluginCount() const;
    
    // Configuration
    void setPluginDirectory(const std::string& dir);
    std::string getPluginDirectory() const;
    void setSandboxEnabled(bool enabled);
    bool isSandboxEnabled() const;
    
private:
    std::unordered_map<std::string, std::shared_ptr<IPlugin>> plugins_;
    std::unordered_map<std::string, void*> plugin_handles_;  // Dynamic library handles
    std::unordered_map<HookType, std::vector<HookRegistration>> hooks_;
    std::unordered_map<std::string, PluginConfig> plugin_configs_;
    
    mutable std::mutex plugins_mutex_;
    mutable std::mutex hooks_mutex_;
    
    std::unique_ptr<PluginLoader> loader_;
    std::unique_ptr<PluginSandbox> sandbox_;
    
    std::string plugin_directory_;
    bool sandbox_enabled_;
    bool initialized_;
    
    // Internal methods
    bool validatePlugin(const std::string& plugin_path);
    bool checkDependencies(const PluginInfo& info);
    void* loadLibrary(const std::string& path);
    void unloadLibrary(void* handle);
    IPlugin* createPluginInstance(void* handle);
    void sortHooksByPriority();
};

/**
 * PluginLoader - Platform-specific plugin loading
 */
class PluginLoader {
public:
    virtual ~PluginLoader() = default;
    
    virtual std::vector<std::string> getPluginFiles(const std::string& directory) = 0;
    virtual void* loadLibrary(const std::string& path) = 0;
    virtual void unloadLibrary(void* handle) = 0;
    virtual void* getSymbol(void* handle, const std::string& name) = 0;
    virtual std::string getError() = 0;
};

/**
 * PluginSandbox - Security sandbox for plugins
 */
class PluginSandbox {
public:
    PluginSandbox();
    ~PluginSandbox();
    
    bool initialize();
    void shutdown();
    
    // Resource limits
    void setMemoryLimit(size_t bytes);
    void setCpuTimeLimit(int seconds);
    void setFileSystemAccess(bool allowed);
    void setNetworkAccess(bool allowed);
    
    // Sandbox execution
    bool enterSandbox();
    void exitSandbox();
    bool isInSandbox() const;
    
    // Validation
    bool validatePlugin(const std::string& plugin_path);
    
private:
    bool initialized_;
    bool in_sandbox_;
    size_t memory_limit_;
    int cpu_time_limit_;
    bool filesystem_allowed_;
    bool network_allowed_;
};

/**
 * HookManager - Hook registration and execution
 */
class HookManager {
public:
    HookManager();
    
    void registerHook(const HookRegistration& reg);
    void unregisterHook(const std::string& plugin_id, HookType type);
    void executeHooks(HookType type, HookContext& context);
    bool executeHooksWithCancel(HookType type, HookContext& context);
    
    std::vector<HookRegistration> getHooks(HookType type) const;
    void clearHooks();
    
private:
    std::unordered_map<HookType, std::vector<HookRegistration>> hooks_;
    mutable std::mutex mutex_;
    
    void sortHooks(HookType type);
};

// C API for plugin creation (exported by plugins)
extern "C" {
    typedef IPlugin* (*CreatePluginFunc)();
    typedef void (*DestroyPluginFunc)(IPlugin*);
    typedef uint32_t (*GetApiVersionFunc)();
    
    // Plugin must export these functions
    // RAWRXD_EXPORT IPlugin* rawrxd_create_plugin();
    // RAWRXD_EXPORT void rawrxd_destroy_plugin(IPlugin* plugin);
    // RAWRXD_EXPORT uint32_t rawrxd_get_api_version();
}

// Platform-specific export macros
#ifdef _WIN32
    #define RAWRXD_PLUGIN_EXPORT __declspec(dllexport)
#else
    #define RAWRXD_PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

// Plugin registration helper
#define RAWRXD_REGISTER_PLUGIN(PluginClass) \
    extern "C" { \
        RAWRXD_PLUGIN_EXPORT rawrxd::plugin::IPlugin* rawrxd_create_plugin() { \
            return new PluginClass(); \
        } \
        RAWRXD_PLUGIN_EXPORT void rawrxd_destroy_plugin(rawrxd::plugin::IPlugin* plugin) { \
            delete plugin; \
        } \
        RAWRXD_PLUGIN_EXPORT uint32_t rawrxd_get_api_version() { \
            return rawrxd::plugin::PLUGIN_API_VERSION; \
        } \
    }

// Global plugin manager accessor
PluginManager* getPluginManager();
void setPluginManager(std::unique_ptr<PluginManager> manager);

} // namespace plugin
} // namespace rawrxd
