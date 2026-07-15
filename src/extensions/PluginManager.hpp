// RawrXD Plugin Manager
// Phase X.1: Plugin system for extensibility
// Enables third-party extensions and custom functionality

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <functional>
#include <any>

namespace RawrXD {
namespace Extensions {

// Plugin API version
constexpr uint32_t PLUGIN_API_VERSION = 1;

// Plugin interface base class
class IPlugin {
public:
    virtual ~IPlugin() = default;
    
    // Plugin information
    virtual const char* getName() const = 0;
    virtual const char* getVersion() const = 0;
    virtual const char* getAuthor() const = 0;
    virtual const char* getDescription() const = 0;
    virtual uint32_t getAPIVersion() const = 0;
    
    // Lifecycle
    virtual bool initialize() = 0;
    virtual bool shutdown() = 0;
    
    // Capabilities
    virtual std::vector<std::string> getCapabilities() const = 0;
    virtual bool hasCapability(const std::string& capability) const = 0;
};

// Plugin interface factory
using PluginCreateFunc = IPlugin* (*)();
using PluginDestroyFunc = void (*)(IPlugin*);

// Plugin metadata
struct PluginMetadata {
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    std::string path;
    uint32_t apiVersion{0};
    std::vector<std::string> dependencies;
    std::vector<std::string> capabilities;
    std::map<std::string, std::string> config;
    bool isLoaded{false};
    bool isEnabled{true};
};

// Plugin instance
struct PluginInstance {
    PluginMetadata metadata;
    IPlugin* instance{nullptr};
    void* libraryHandle{nullptr};
    PluginDestroyFunc destroyFunc{nullptr};
    std::chrono::system_clock::time_point loadedAt;
};

// Extension point
struct ExtensionPoint {
    std::string name;
    std::string description;
    std::vector<std::string> requiredCapabilities;
    std::function<bool(IPlugin*)> validator;
};

// Plugin hook
struct PluginHook {
    std::string name;
    std::string description;
    std::vector<std::string> eventTypes;
    std::function<void(const std::map<std::string, std::any>&)> callback;
    int priority{100};  // Lower = higher priority
    bool enabled{true};
};

// Plugin manager
class PluginManager {
public:
    PluginManager();
    ~PluginManager();
    
    // Initialization
    bool initialize(const std::string& pluginDirectory);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Plugin loading
    bool loadPlugin(const std::string& path);
    bool unloadPlugin(const std::string& name);
    bool reloadPlugin(const std::string& name);
    bool loadAllPlugins();
    
    // Plugin management
    bool enablePlugin(const std::string& name);
    bool disablePlugin(const std::string& name);
    bool isPluginLoaded(const std::string& name) const;
    bool isPluginEnabled(const std::string& name) const;
    
    // Plugin access
    IPlugin* getPlugin(const std::string& name) const;
    std::vector<std::string> listPlugins() const;
    std::vector<std::string> listLoadedPlugins() const;
    std::vector<std::string> listEnabledPlugins() const;
    PluginMetadata getPluginMetadata(const std::string& name) const;
    
    // Capabilities
    std::vector<std::string> getAvailableCapabilities() const;
    std::vector<std::string> getPluginsWithCapability(const std::string& capability) const;
    bool hasCapability(const std::string& capability) const;
    
    // Extension points
    void registerExtensionPoint(const ExtensionPoint& point);
    void unregisterExtensionPoint(const std::string& name);
    std::vector<std::string> listExtensionPoints() const;
    std::vector<IPlugin*> getExtensionsForPoint(const std::string& pointName) const;
    
    // Hooks
    void registerHook(const PluginHook& hook);
    void unregisterHook(const std::string& name);
    void triggerHook(const std::string& name, const std::map<std::string, std::any>& data);
    void triggerHookAsync(const std::string& name, const std::map<std::string, std::any>& data);
    
    // Plugin communication
    bool sendMessage(const std::string& pluginName, const std::string& message, 
                    const std::map<std::string, std::any>& data);
    std::any callPluginMethod(const std::string& pluginName, const std::string& method,
                             const std::vector<std::any>& args);
    
    // Configuration
    bool setPluginConfig(const std::string& name, const std::string& key, const std::string& value);
    std::string getPluginConfig(const std::string& name, const std::string& key, 
                               const std::string& defaultValue = "") const;
    bool savePluginConfig(const std::string& name);
    bool loadPluginConfig(const std::string& name);
    
    // Dependency resolution
    bool checkDependencies(const std::string& name) const;
    std::vector<std::string> getMissingDependencies(const std::string& name) const;
    std::vector<std::string> resolveLoadOrder(const std::vector<std::string>& plugins) const;
    
    // Sandboxing (optional)
    void enableSandboxing(bool enabled);
    bool isSandboxingEnabled() const;
    void setPluginPermissions(const std::string& name, const std::vector<std::string>& permissions);
    std::vector<std::string> getPluginPermissions(const std::string& name) const;
    bool hasPermission(const std::string& pluginName, const std::string& permission) const;
    
    // Statistics
    struct PluginStats {
        uint32_t totalPlugins;
        uint32_t loadedPlugins;
        uint32_t enabledPlugins;
        uint32_t failedPlugins;
        uint32_t extensionPoints;
        uint32_t registeredHooks;
    };
    PluginStats getStats() const;
    
    // Events
    using PluginEventCallback = std::function<void(const std::string& event, 
                                                   const std::string& pluginName)>;
    void onPluginEvent(PluginEventCallback callback);

private:
    void notifyEvent(const std::string& event, const std::string& pluginName);
    bool validatePlugin(const std::string& path, PluginMetadata& metadata);
    bool resolveDependencies(const std::string& name, std::vector<std::string>& resolved, 
                            std::vector<std::string>& unresolved);
    
    mutable std::mutex mutex_;
    std::string pluginDirectory_;
    std::map<std::string, PluginInstance> plugins_;
    std::map<std::string, ExtensionPoint> extensionPoints_;
    std::map<std::string, std::vector<PluginHook>> hooks_;
    std::map<std::string, std::vector<std::string>> pluginPermissions_;
    
    bool initialized_{false};
    bool sandboxingEnabled_{false};
    PluginEventCallback eventCallback_;
};

// Plugin helper macros for easy plugin creation
#define RAWRXD_PLUGIN(className) \
    extern "C" { \
        RAWRXD_API RawrXD::Extensions::IPlugin* createPlugin() { \
            return new className(); \
        } \
        RAWRXD_API void destroyPlugin(RawrXD::Extensions::IPlugin* plugin) { \
            delete plugin; \
        } \
    }

// Example plugin interfaces

// Model provider plugin interface
class IModelProvider : public IPlugin {
public:
    virtual ~IModelProvider() = default;
    virtual bool canLoadModel(const std::string& path) const = 0;
    virtual void* loadModel(const std::string& path) = 0;
    virtual void unloadModel(void* modelHandle) = 0;
    virtual std::vector<std::string> getSupportedFormats() const = 0;
};

// Backend provider plugin interface
class IBackendProvider : public IPlugin {
public:
    virtual ~IBackendProvider() = default;
    virtual std::string getBackendName() const = 0;
    virtual bool isAvailable() const = 0;
    virtual void* createContext(const std::map<std::string, std::string>& config) = 0;
    virtual void destroyContext(void* context) = 0;
    virtual std::vector<std::string> getSupportedOperations() const = 0;
};

// Inference hook plugin interface
class IInferenceHook : public IPlugin {
public:
    virtual ~IInferenceHook() = default;
    virtual void onPreInference(const std::map<std::string, std::any>& input) = 0;
    virtual void onPostInference(const std::map<std::string, std::any>& input,
                                  const std::map<std::string, std::any>& output) = 0;
    virtual void onTokenGenerated(int tokenId, const std::string& token) = 0;
};

} // namespace Extensions
} // namespace RawrXD
