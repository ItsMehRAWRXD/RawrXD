// RawrXD Hot Reload Manager
// Phase W.1: Dynamic configuration and code reloading
// Enables zero-downtime updates and configuration changes

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <filesystem>

namespace RawrXD {
namespace Maintenance {

// Reloadable component interface
class IReloadable {
public:
    virtual ~IReloadable() = default;
    virtual bool reload() = 0;
    virtual std::string getName() const = 0;
    virtual std::string getVersion() const = 0;
};

// Reload type
enum class ReloadType {
    CONFIGURATION,  // Configuration file changed
    CODE,           // Code/DLL changed
    MODEL,          // Model file changed
    PLUGIN,         // Plugin changed
    CERTIFICATE,    // TLS certificate changed
    FULL            // Full restart required
};

// Reload result
struct ReloadResult {
    bool success;
    ReloadType type;
    std::string componentName;
    std::string oldVersion;
    std::string newVersion;
    std::chrono::system_clock::time_point timestamp;
    std::string errorMessage;
    std::chrono::milliseconds duration;
};

// File watcher event
struct FileWatchEvent {
    std::string path;
    std::filesystem::file_time_type lastWriteTime;
    uintmax_t fileSize;
    std::string hash;
};

// Component registration
struct ComponentRegistration {
    std::string name;
    std::string version;
    ReloadType supportedReloads;
    std::function<bool()> reloadCallback;
    std::vector<std::string> watchedFiles;
    std::chrono::seconds reloadCooldown{5};
    bool autoReload{true};
};

// Hot reload manager
class HotReloadManager {
public:
    HotReloadManager();
    ~HotReloadManager();
    
    // Initialization
    bool initialize(const std::string& configPath = "");
    bool shutdown();
    bool isRunning() const { return running_; }
    
    // Component registration
    void registerComponent(const ComponentRegistration& registration);
    void registerComponent(const std::string& name, 
                          IReloadable* component,
                          const std::vector<std::string>& watchedFiles = {});
    void unregisterComponent(const std::string& name);
    bool hasComponent(const std::string& name) const;
    std::vector<std::string> listComponents() const;
    
    // Manual reload
    ReloadResult reloadComponent(const std::string& name, ReloadType type = ReloadType::CONFIGURATION);
    ReloadResult reloadAll(ReloadType type = ReloadType::CONFIGURATION);
    bool reloadConfiguration(const std::string& componentName = "");
    bool reloadPlugins();
    bool reloadModels();
    bool reloadCertificates();
    
    // File watching
    void watchFile(const std::string& path, const std::string& componentName);
    void unwatchFile(const std::string& path);
    void watchDirectory(const std::string& path, const std::string& pattern = "*");
    std::vector<std::string> getWatchedFiles() const;
    
    // Auto-reload control
    void enableAutoReload(const std::string& componentName = "");
    void disableAutoReload(const std::string& componentName = "");
    bool isAutoReloadEnabled(const std::string& componentName) const;
    void setReloadCooldown(const std::string& componentName, std::chrono::seconds cooldown);
    
    // Reload history
    std::vector<ReloadResult> getReloadHistory(std::chrono::hours duration = std::chrono::hours{24}) const;
    std::vector<ReloadResult> getReloadHistoryForComponent(const std::string& name,
                                                         std::chrono::hours duration = std::chrono::hours{24}) const;
    ReloadResult getLastReload(const std::string& componentName = "") const;
    
    // Status
    struct ComponentStatus {
        std::string name;
        std::string currentVersion;
        std::chrono::system_clock::time_point lastReloadTime;
        uint32_t reloadCount;
        bool autoReloadEnabled;
        bool isHealthy;
        std::string lastError;
    };
    ComponentStatus getComponentStatus(const std::string& name) const;
    std::vector<ComponentStatus> getAllComponentStatuses() const;
    
    // Callbacks
    using ReloadCallback = std::function<void(const ReloadResult& result)>;
    using FileChangeCallback = std::function<void(const FileWatchEvent& event)>;
    void onReload(ReloadCallback callback);
    void onFileChange(FileChangeCallback callback);
    void onBeforeReload(std::function<void(const std::string& componentName)> callback);
    void onAfterReload(std::function<void(const ReloadResult& result)> callback);
    
    // Validation
    bool validateComponent(const std::string& name) const;
    bool canReload(const std::string& name, ReloadType type) const;
    std::vector<std::string> getReloadableComponents(ReloadType type) const;
    
    // Statistics
    struct ReloadStats {
        uint32_t totalReloads;
        uint32_t successfulReloads;
        uint32_t failedReloads;
        std::chrono::milliseconds averageReloadTime;
        std::map<std::string, uint32_t> reloadsByComponent;
        std::map<ReloadType, uint32_t> reloadsByType;
    };
    ReloadStats getStats() const;
    
    // Emergency operations
    bool emergencyRollback(const std::string& componentName);
    bool emergencyRollbackAll();
    void enableEmergencyMode();
    void disableEmergencyMode();
    bool isEmergencyMode() const;

private:
    void fileWatcherLoop();
    void checkForChanges();
    bool performReload(const std::string& name, ReloadType type);
    std::string calculateFileHash(const std::string& path) const;
    void notifyReloadCallbacks(const ReloadResult& result);
    
    mutable std::mutex mutex_;
    std::map<std::string, ComponentRegistration> components_;
    std::map<std::string, IReloadable*> reloadableComponents_;
    std::map<std::string, FileWatchEvent> watchedFiles_;
    std::vector<ReloadResult> reloadHistory_;
    
    std::atomic<bool> running_{false};
    std::atomic<bool> emergencyMode_{false};
    std::thread watcherThread_;
    
    ReloadCallback reloadCallback_;
    FileChangeCallback fileChangeCallback_;
    std::function<void(const std::string&)> beforeReloadCallback_;
    std::function<void(const ReloadResult&)> afterReloadCallback_;
};

// Configuration reloader
class ConfigurationReloader : public IReloadable {
public:
    ConfigurationReloader(const std::string& configPath);
    
    bool reload() override;
    std::string getName() const override { return "ConfigurationReloader"; }
    std::string getVersion() const override;
    
    // Configuration access
    std::string getValue(const std::string& key, const std::string& defaultValue = "") const;
    int getIntValue(const std::string& key, int defaultValue = 0) const;
    double getDoubleValue(const std::string& key, double defaultValue = 0.0) const;
    bool getBoolValue(const std::string& key, bool defaultValue = false) const;
    std::vector<std::string> getArrayValue(const std::string& key) const;
    
    // Configuration modification
    void setValue(const std::string& key, const std::string& value);
    void removeValue(const std::string& key);
    bool hasValue(const std::string& key) const;
    
    // Persistence
    bool saveToFile(const std::string& path = "");
    bool loadFromFile(const std::string& path);
    
    // Callbacks
    using ConfigChangeCallback = std::function<void(const std::string& key, 
                                                     const std::string& oldValue,
                                                     const std::string& newValue)>;
    void onChange(ConfigChangeCallback callback);

private:
    std::string configPath_;
    std::map<std::string, std::string> config_;
    mutable std::mutex mutex_;
    ConfigChangeCallback changeCallback_;
};

// Plugin reloader
class PluginReloader : public IReloadable {
public:
    PluginReloader(const std::string& pluginDirectory);
    
    bool reload() override;
    std::string getName() const override { return "PluginReloader"; }
    std::string getVersion() const override;
    
    // Plugin management
    bool loadPlugin(const std::string& path);
    bool unloadPlugin(const std::string& name);
    bool reloadPlugin(const std::string& name);
    std::vector<std::string> listLoadedPlugins() const;
    bool isPluginLoaded(const std::string& name) const;
    
    // Plugin access
    void* getPluginSymbol(const std::string& pluginName, const std::string& symbolName);
    
    // Auto-discovery
    void scanForPlugins();
    void setAutoLoad(bool enabled);

private:
    std::string pluginDirectory_;
    std::map<std::string, void*> loadedPlugins_;  // name -> handle
    mutable std::mutex mutex_;
    bool autoLoad_{false};
};

// Model hot-swapper
class ModelHotSwapper : public IReloadable {
public:
    ModelHotSwapper();
    
    bool reload() override;
    std::string getName() const override { return "ModelHotSwapper"; }
    std::string getVersion() const override;
    
    // Model registration
    void registerModel(const std::string& modelId, const std::string& path);
    void unregisterModel(const std::string& modelId);
    
    // Hot-swap operations
    bool swapModel(const std::string& modelId, const std::string& newPath);
    bool preloadModel(const std::string& modelId, const std::string& path);
    bool activatePreloaded(const std::string& modelId);
    
    // Status
    struct ModelStatus {
        std::string modelId;
        std::string currentPath;
        std::string pendingPath;
        bool isLoaded;
        bool hasPendingSwap;
        uint64_t loadTimeMs;
        uint64_t memoryUsage;
    };
    ModelStatus getModelStatus(const std::string& modelId) const;
    std::vector<ModelStatus> getAllModelStatuses() const;

private:
    struct ModelEntry {
        std::string path;
        std::string pendingPath;
        bool isLoaded{false};
        void* modelHandle{nullptr};
        std::chrono::system_clock::time_point loadTime;
    };
    
    mutable std::mutex mutex_;
    std::map<std::string, ModelEntry> models_;
};

} // namespace Maintenance
} // namespace RawrXD
