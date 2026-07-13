/**
 * PluginSystem.hpp
 *
 * Phase Q Batch 5/5: Plugin System
 *
 * Extension architecture with plugin marketplace, sandboxing,
 * and lifecycle management for third-party extensions.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace SDK {

// ============================================================================
// Forward Declarations
// ============================================================================

class Plugin;
class PluginHost;
class PluginManager;
class PluginSandbox;
class ExtensionPoint;

// ============================================================================
// Plugin API Version
// ============================================================================

struct PluginAPIVersion {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    
    bool IsCompatibleWith(const PluginAPIVersion& other) const;
    std::string ToString() const;
    static PluginAPIVersion FromString(const std::string& str);
    static PluginAPIVersion Current();
};

// ============================================================================
// Plugin Manifest
// ============================================================================

struct PluginManifest {
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    std::optional<std::string> authorEmail;
    std::optional<std::string> homepage;
    std::optional<std::string> repository;
    
    // Dependencies
    std::vector<std::string> dependencies;  // Other plugin IDs
    std::vector<std::string> conflicts;
    PluginAPIVersion minAPIVersion;
    PluginAPIVersion maxAPIVersion;
    
    // Capabilities
    std::vector<std::string> permissions;
    std::vector<std::string> extensionPoints;
    std::map<std::string, std::string> configurationSchema;
    
    // Entry points
    std::string entryPoint;  // Path to main plugin file
    std::optional<std::string> settingsPage;
    std::optional<std::string> icon;
    
    // Metadata
    std::vector<std::string> tags;
    std::optional<std::string> license;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
    
    // Security
    std::string signature;
    std::vector<std::string> certificates;
    bool sandboxed = true;
    
    bool IsValid() const;
    std::string ToJson() const;
    static PluginManifest FromJson(const std::string& json);
};

// ============================================================================
// Plugin Context
// ============================================================================

class PluginContext {
public:
    struct Config {
        std::string pluginId;
        std::string pluginDataPath;
        std::string pluginConfigPath;
        std::map<std::string, std::string> environment;
        uint32_t maxMemoryMB = 512;
        uint32_t maxCPUThreads = 2;
        std::chrono::seconds maxExecutionTime{300};
    };
    
    explicit PluginContext(const Config& config);
    
    // Configuration
    const Config& GetConfig() const { return config_; }
    
    // Logging
    void LogInfo(const std::string& message) const;
    void LogWarning(const std::string& message) const;
    void LogError(const std::string& message) const;
    void LogDebug(const std::string& message) const;
    
    // Data storage
    std::string GetDataPath() const { return config_.pluginDataPath; }
    std::string GetConfigPath() const { return config_.pluginConfigPath; }
    
    // Settings
    std::map<std::string, std::string> GetSettings() const;
    void UpdateSettings(const std::map<std::string, std::string>& settings);
    
    // API access
    std::shared_ptr<APIClient> GetAPIClient() const;
    
    // Events
    using EventHandler = std::function<void(const std::string& eventType,
                                           const std::string& payload)>;
    void SubscribeToEvent(const std::string& eventType, EventHandler handler);
    void UnsubscribeFromEvent(const std::string& eventType);
    void PublishEvent(const std::string& eventType, const std::string& payload);
    
    // Notifications
    void ShowNotification(const std::string& title, 
                          const std::string& message,
                          const std::optional<std::string>& action = std::nullopt);
    
private:
    Config config_;
    std::map<std::string, std::vector<EventHandler>> eventHandlers_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Extension Point
// ============================================================================

class ExtensionPoint {
public:
    struct Config {
        std::string name;
        std::string description;
        std::vector<std::string> requiredInterfaces;
        std::vector<std::string> optionalInterfaces;
        bool multipleExtensionsAllowed;
        uint32_t maxExtensions;
    };
    
    explicit ExtensionPoint(const Config& config);
    
    // Registration
    using ExtensionFactory = std::function<std::shared_ptr<void>(PluginContext&)>;
    void RegisterExtension(const std::string& pluginId, ExtensionFactory factory);
    void UnregisterExtension(const std::string& pluginId);
    
    // Access
    std::vector<std::shared_ptr<void>> GetExtensions() const;
    std::shared_ptr<void> GetExtension(const std::string& pluginId) const;
    bool HasExtension(const std::string& pluginId) const;
    
    // Configuration
    const Config& GetConfig() const { return config_; }
    std::vector<std::string> GetRegisteredPlugins() const;
    
private:
    Config config_;
    std::map<std::string, std::shared_ptr<void>> extensions_;
    std::map<std::string, ExtensionFactory> factories_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Plugin Interface
// ============================================================================

class IPlugin {
public:
    virtual ~IPlugin() = default;
    
    // Lifecycle
    virtual bool Initialize(PluginContext& context) = 0;
    virtual void Shutdown() = 0;
    virtual bool IsInitialized() const = 0;
    
    // Information
    virtual PluginManifest GetManifest() const = 0;
    virtual std::string GetId() const = 0;
    virtual std::string GetVersion() const = 0;
    
    // Capabilities
    virtual std::vector<std::string> GetExtensionPoints() const = 0;
    virtual bool ImplementsExtensionPoint(const std::string& name) const = 0;
    
    // Settings
    virtual std::map<std::string, std::string> GetDefaultSettings() const = 0;
    virtual bool ValidateSettings(const std::map<std::string, std::string>& settings) const = 0;
    
    // Health
    virtual bool IsHealthy() const = 0;
    virtual std::string GetHealthStatus() const = 0;
};

// ============================================================================
// Plugin Sandbox
// ============================================================================

class PluginSandbox {
public:
    struct Config {
        uint32_t maxMemoryMB = 512;
        uint32_t maxCPUThreads = 2;
        std::chrono::seconds maxExecutionTime{300};
        bool networkAccess = false;
        bool filesystemAccess = false;
        std::vector<std::string> allowedPaths;
        std::vector<std::string> blockedPaths;
        bool enableSeccomp = true;
        bool enableAppArmor = false;
    };
    
    explicit PluginSandbox(const Config& config);
    ~PluginSandbox();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Execution
    using SandboxTask = std::function<void()>;
    bool Execute(SandboxTask task);
    bool ExecuteWithTimeout(SandboxTask task, std::chrono::seconds timeout);
    
    // Resource monitoring
    struct ResourceUsage {
        uint64_t memoryUsedBytes;
        uint64_t peakMemoryBytes;
        double cpuPercent;
        uint32_t threadCount;
        std::chrono::milliseconds executionTime;
    };
    ResourceUsage GetResourceUsage() const;
    
    // Security
    bool IsSecure() const;
    std::vector<std::string> GetSecurityViolations() const;
    
private:
    Config config_;
    bool initialized_;
    
    ResourceUsage currentUsage_;
    mutable std::mutex mutex_;
    
    void* sandboxContext_;  // Platform-specific sandbox context
    
    void SetupSandbox();
    void TeardownSandbox();
    void MonitorResources();
};

// ============================================================================
// Plugin Instance
// ============================================================================

class PluginInstance {
public:
    enum class State {
        UNLOADED,
        LOADING,
        LOADED,
        INITIALIZING,
        ACTIVE,
        ERROR,
        UNLOADING
    };
    
    PluginInstance(const PluginManifest& manifest,
                   std::shared_ptr<PluginSandbox> sandbox);
    ~PluginInstance();
    
    // Lifecycle
    bool Load(const std::string& pluginPath);
    bool Initialize(PluginContext& context);
    void Shutdown();
    void Unload();
    
    // State
    State GetState() const { return state_; }
    bool IsActive() const { return state_ == State::ACTIVE; }
    bool HasError() const { return state_ == State::ERROR; }
    std::string GetErrorMessage() const { return errorMessage_; }
    
    // Access
    std::shared_ptr<IPlugin> GetPlugin() const { return plugin_; }
    const PluginManifest& GetManifest() const { return manifest_; }
    PluginContext* GetContext() const { return context_.get(); }
    
    // Statistics
    struct Stats {
        std::chrono::system_clock::time_point loadedAt;
        std::optional<std::chrono::system_clock::time_point> activatedAt;
        uint64_t apiCalls;
        uint64_t eventsHandled;
        std::chrono::milliseconds totalExecutionTime;
    };
    Stats GetStats() const { return stats_; }
    
private:
    PluginManifest manifest_;
    std::shared_ptr<PluginSandbox> sandbox_;
    std::shared_ptr<IPlugin> plugin_;
    std::unique_ptr<PluginContext> context_;
    State state_;
    std::string errorMessage_;
    Stats stats_;
    mutable std::mutex mutex_;
    
    void* libraryHandle_;  // Platform-specific library handle
};

// ============================================================================
// Plugin Marketplace
// ============================================================================

class PluginMarketplace {
public:
    struct PluginListing {
        PluginManifest manifest;
        uint64_t downloads;
        double rating;
        uint32_t reviewCount;
        std::chrono::system_clock::time_point publishedAt;
        bool verified;
        std::optional<std::string> publisher;
        std::vector<std::string> screenshots;
        std::optional<std::string> demoUrl;
    };
    
    struct Review {
        std::string reviewId;
        std::string pluginId;
        std::string userId;
        int rating;  // 1-5
        std::string title;
        std::string content;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> updatedAt;
        bool verifiedPurchase;
    };
    
    explicit PluginMarketplace(const std::string& marketplaceUrl);
    
    // Discovery
    std::vector<PluginListing> Search(const std::string& query,
                                        const std::map<std::string, std::string>& filters) const;
    std::vector<PluginListing> GetFeaturedPlugins() const;
    std::vector<PluginListing> GetPopularPlugins() const;
    std::vector<PluginListing> GetNewPlugins() const;
    std::vector<PluginListing> GetPluginsByCategory(const std::string& category) const;
    std::vector<PluginListing> GetPluginsByTag(const std::string& tag) const;
    
    // Details
    std::optional<PluginListing> GetPluginDetails(const std::string& pluginId) const;
    std::vector<Review> GetPluginReviews(const std::string& pluginId,
                                            uint32_t page = 1,
                                            uint32_t pageSize = 20) const;
    
    // Installation
    bool InstallPlugin(const std::string& pluginId, 
                       const std::string& version = "latest");
    bool UpdatePlugin(const std::string& pluginId);
    bool UninstallPlugin(const std::string& pluginId);
    
    // Reviews
    void SubmitReview(const std::string& pluginId,
                      int rating,
                      const std::string& title,
                      const std::string& content);
    void UpdateReview(const std::string& reviewId,
                      const std::optional<int>& rating,
                      const std::optional<std::string>& title,
                      const std::optional<std::string>& content);
    void DeleteReview(const std::string& reviewId);
    
    // Publishing
    void PublishPlugin(const PluginManifest& manifest,
                       const std::string& pluginPackage);
    void UpdatePublishedPlugin(const std::string& pluginId,
                                const PluginManifest& manifest);
    void UnpublishPlugin(const std::string& pluginId);
    
    // Categories
    std::vector<std::string> GetCategories() const;
    std::vector<std::string> GetTags() const;
    
private:
    std::string marketplaceUrl_;
    std::shared_ptr<APIClient> apiClient_;
};

// ============================================================================
// Plugin Manager
// ============================================================================

class PluginManager {
public:
    struct Config {
        std::string pluginsDirectory;
        std::string dataDirectory;
        bool enableSandboxing = true;
        bool autoUpdate = false;
        bool verifySignatures = true;
        std::vector<std::string> trustedPublishers;
        std::vector<std::string> blockedPlugins;
    };
    
    explicit PluginManager(const Config& config);
    ~PluginManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Plugin management
    bool LoadPlugin(const std::string& pluginPath);
    bool LoadPlugin(const PluginManifest& manifest);
    void UnloadPlugin(const std::string& pluginId);
    void ReloadPlugin(const std::string& pluginId);
    
    // Activation
    bool ActivatePlugin(const std::string& pluginId);
    void DeactivatePlugin(const std::string& pluginId);
    bool IsPluginActive(const std::string& pluginId) const;
    
    // Discovery
    std::shared_ptr<PluginInstance> GetPlugin(const std::string& pluginId) const;
    std::vector<std::shared_ptr<PluginInstance>> GetLoadedPlugins() const;
    std::vector<std::shared_ptr<PluginInstance>> GetActivePlugins() const;
    std::vector<std::string> GetPluginIds() const;
    bool IsPluginLoaded(const std::string& pluginId) const;
    
    // Extension points
    void RegisterExtensionPoint(std::shared_ptr<ExtensionPoint> extensionPoint);
    void UnregisterExtensionPoint(const std::string& name);
    std::shared_ptr<ExtensionPoint> GetExtensionPoint(const std::string& name) const;
    std::vector<std::shared_ptr<ExtensionPoint>> GetExtensionPoints() const;
    
    // Dependencies
    bool CheckDependencies(const PluginManifest& manifest) const;
    std::vector<std::string> GetMissingDependencies(const PluginManifest& manifest) const;
    std::vector<std::string> GetConflicts(const PluginManifest& manifest) const;
    
    // Configuration
    void UpdatePluginSettings(const std::string& pluginId,
                               const std::map<std::string, std::string>& settings);
    std::map<std::string, std::string> GetPluginSettings(const std::string& pluginId) const;
    
    // Security
    bool VerifyPluginSignature(const std::string& pluginPath);
    bool IsPluginTrusted(const std::string& pluginId) const;
    void TrustPublisher(const std::string& publisher);
    void BlockPlugin(const std::string& pluginId);
    
    // Events
    using PluginEventHandler = std::function<void(const std::string& pluginId,
                                                    const std::string& event)>;
    void OnPluginLoaded(PluginEventHandler handler);
    void OnPluginUnloaded(PluginEventHandler handler);
    void OnPluginActivated(PluginEventHandler handler);
    void OnPluginDeactivated(PluginEventHandler handler);
    void OnPluginError(PluginEventHandler handler);
    
    // Statistics
    struct Stats {
        uint32_t loadedPlugins;
        uint32_t activePlugins;
        uint32_t failedPlugins;
        uint64_t totalApiCalls;
        uint64_t totalEventsHandled;
        std::map<std::string, uint64_t> callsByPlugin;
    };
    Stats GetStats() const;
    
    // Health
    std::vector<std::string> GetUnhealthyPlugins() const;
    void RunHealthChecks();
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, std::shared_ptr<PluginInstance>> plugins_;
    std::map<std::string, std::shared_ptr<ExtensionPoint>> extensionPoints_;
    mutable std::mutex mutex_;
    
    PluginEventHandler onLoaded_;
    PluginEventHandler onUnloaded_;
    PluginEventHandler onActivated_;
    PluginEventHandler onDeactivated_;
    PluginEventHandler onError_;
    
    Stats stats_;
    mutable std::mutex statsMutex_;
    
    void ScanPluginDirectory();
    void ValidatePlugin(const std::string& pluginPath);
    void NotifyEvent(const std::string& pluginId, 
                     const std::string& event,
                     PluginEventHandler handler);
};

// ============================================================================
// Built-in Extension Points
// ============================================================================

// Authentication extension
class IAuthProvider : public IPlugin {
public:
    virtual ~IAuthProvider() = default;
    virtual bool Authenticate(const std::string& credentials) = 0;
    virtual std::string GetUserInfo(const std::string& userId) = 0;
    virtual std::vector<std::string> GetPermissions(const std::string& userId) = 0;
};

// Storage extension
class IStorageProvider : public IPlugin {
public:
    virtual ~IStorageProvider() = default;
    virtual bool Store(const std::string& key, const std::vector<uint8_t>& data) = 0;
    virtual std::optional<std::vector<uint8_t>> Retrieve(const std::string& key) = 0;
    virtual bool Delete(const std::string& key) = 0;
    virtual std::vector<std::string> List(const std::string& prefix) = 0;
};

// Metrics extension
class IMetricsProvider : public IPlugin {
public:
    virtual ~IMetricsProvider() = default;
    virtual void RecordMetric(const std::string& name, double value) = 0;
    virtual void RecordHistogram(const std::string& name, double value) = 0;
    virtual void IncrementCounter(const std::string& name, uint64_t delta = 1) = 0;
    virtual void StartTimer(const std::string& name) = 0;
    virtual void StopTimer(const std::string& name) = 0;
};

// Notification extension
class INotificationProvider : public IPlugin {
public:
    virtual ~INotificationProvider() = default;
    virtual void SendNotification(const std::string& recipient,
                                   const std::string& title,
                                   const std::string& message) = 0;
    virtual void SendBulkNotification(const std::vector<std::string>& recipients,
                                       const std::string& title,
                                       const std::string& message) = 0;
};

// UI extension
class IUIExtension : public IPlugin {
public:
    virtual ~IUIExtension() = default;
    virtual std::string GetComponent(const std::string& componentId) = 0;
    virtual void RegisterRoute(const std::string& path, 
                                const std::string& componentId) = 0;
    virtual void AddMenuItem(const std::string& menuId,
                              const std::string& label,
                              const std::string& action) = 0;
};

} // namespace SDK
