// Phase D.12 Batch 1/5: Plugin System
// Extensible architecture for third-party plugins
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Ecosystem {

// ============================================================================
// Plugin Types
// ============================================================================

enum class PluginType {
    EXTENSION = 0,
    CONNECTOR = 1,
    PROVIDER = 2,
    VISUALIZATION = 3,
    WORKFLOW = 4,
    SECURITY = 5,
    MONITORING = 6,
    STORAGE = 7
};

enum class PluginStatus {
    INSTALLED = 0,
    ENABLED = 1,
    DISABLED = 2,
    ERROR = 3,
    UPDATING = 4,
    UNINSTALLING = 5
};

struct PluginManifest {
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    std::string author_email;
    std::string homepage;
    std::string repository;
    std::string license;
    PluginType type;
    std::vector<std::string> tags;
    std::vector<std::string> categories;
    std::map<std::string, std::string> dependencies;
    std::vector<std::string> sovereign_version_compat;
    std::map<std::string, std::string> config_schema;
    std::vector<std::string> permissions;
    std::map<std::string, std::string> hooks;
    std::chrono::steady_clock::time_point installed_at;
    std::chrono::steady_clock::time_point updated_at;
    int download_count = 0;
    double rating = 0.0;
    int rating_count = 0;
};

// ============================================================================
// Plugin Interface
// ============================================================================

class PluginInterface {
public:
    virtual ~PluginInterface() = default;
    
    // Lifecycle
    virtual bool Initialize(const std::map<std::string, std::string>& config) = 0;
    virtual void Shutdown() = 0;
    
    // Metadata
    virtual std::string GetId() const = 0;
    virtual std::string GetName() const = 0;
    virtual std::string GetVersion() const = 0;
    virtual PluginType GetType() const = 0;
    
    // Capabilities
    virtual std::vector<std::string> GetHooks() const = 0;
    virtual std::vector<std::string> GetCommands() const = 0;
    virtual std::map<std::string, std::string> GetAPIEndpoints() const = 0;
    
    // Execution
    virtual bool ExecuteHook(const std::string& hook_name, 
                               const std::map<std::string, std::any>& context) = 0;
    virtual std::any ExecuteCommand(const std::string& command,
                                     const std::map<std::string, std::any>& args) = 0;
    
    // Health
    virtual bool IsHealthy() const = 0;
    virtual std::map<std::string, std::string> GetHealthDetails() const = 0;
    
    // Configuration
    virtual bool UpdateConfig(const std::map<std::string, std::string>& config) = 0;
    virtual std::map<std::string, std::string> GetConfig() const = 0;
    
    // Events
    virtual void OnEvent(const std::string& event_type,
                         const std::map<std::string, std::any>& event_data) {}
};

// ============================================================================
// Plugin Loader
// ============================================================================

class PluginLoader {
public:
    struct Config {
        std::string plugin_directory;
        std::vector<std::string> allowed_extensions = {".so", ".dll", ".dylib"};
        bool verify_signatures = true;
        std::string trusted_ca_path;
        bool sandbox_plugins = true;
        size_t max_memory_mb = 512;
        std::chrono::seconds load_timeout{30};
    };
    
    explicit PluginLoader(const Config& config);
    ~PluginLoader();
    
    bool Initialize();
    void Shutdown();
    
    // Loading
    std::shared_ptr<PluginInterface> LoadPlugin(const std::string& path);
    bool UnloadPlugin(const std::string& plugin_id);
    bool ReloadPlugin(const std::string& plugin_id);
    
    // Validation
    bool ValidatePlugin(const std::string& path);
    bool VerifySignature(const std::string& path, const std::string& signature);
    std::vector<std::string> CheckDependencies(const PluginManifest& manifest);
    
    // Discovery
    std::vector<std::string> DiscoverPlugins();
    PluginManifest ParseManifest(const std::string& manifest_path);
    
private:
    Config config_;
    std::map<std::string, void*> loaded_libraries_;
    std::map<std::string, std::shared_ptr<PluginInterface>> plugins_;
    mutable std::mutex plugins_mutex_;
    
    void* LoadLibrary(const std::string& path);
    void UnloadLibrary(void* handle);
    std::shared_ptr<PluginInterface> CreatePluginInstance(void* handle);
};

// ============================================================================
// Plugin Manager
// ============================================================================

class PluginManager {
public:
    struct Config {
        std::string data_directory;
        bool auto_enable_new_plugins = false;
        bool auto_update_plugins = false;
        int max_plugins = 100;
        std::chrono::seconds health_check_interval{60};
    };
    
    explicit PluginManager(const Config& config);
    ~PluginManager();
    
    bool Initialize();
    void Shutdown();
    
    // Installation
    bool InstallPlugin(const std::string& package_path);
    bool InstallFromURL(const std::string& url);
    bool UninstallPlugin(const std::string& plugin_id);
    bool UpdatePlugin(const std::string& plugin_id, const std::string& new_version);
    
    // Lifecycle
    bool EnablePlugin(const std::string& plugin_id);
    bool DisablePlugin(const std::string& plugin_id);
    bool RestartPlugin(const std::string& plugin_id);
    
    // Access
    std::shared_ptr<PluginInterface> GetPlugin(const std::string& plugin_id);
    std::vector<std::shared_ptr<PluginInterface>> GetAllPlugins();
    std::vector<std::shared_ptr<PluginInterface>> GetPluginsByType(PluginType type);
    std::vector<std::shared_ptr<PluginInterface>> GetEnabledPlugins();
    
    // Status
    PluginStatus GetPluginStatus(const std::string& plugin_id) const;
    PluginManifest GetPluginManifest(const std::string& plugin_id) const;
    std::vector<std::string> GetPluginErrors(const std::string& plugin_id) const;
    
    // Configuration
    bool SetPluginConfig(const std::string& plugin_id, 
                         const std::map<std::string, std::string>& config);
    std::map<std::string, std::string> GetPluginConfig(const std::string& plugin_id) const;
    
    // Hooks
    bool RegisterHook(const std::string& hook_name, const std::string& plugin_id);
    bool UnregisterHook(const std::string& hook_name, const std::string& plugin_id);
    bool ExecuteHook(const std::string& hook_name,
                     const std::map<std::string, std::any>& context);
    std::vector<std::string> GetHooksForPlugin(const std::string& plugin_id) const;
    
    // Events
    void BroadcastEvent(const std::string& event_type,
                        const std::map<std::string, std::any>& event_data);
    
    // Health
    bool IsPluginHealthy(const std::string& plugin_id) const;
    std::map<std::string, bool> GetAllHealthStatus() const;
    
private:
    Config config_;
    std::unique_ptr<PluginLoader> loader_;
    
    struct PluginEntry {
        PluginManifest manifest;
        std::shared_ptr<PluginInterface> instance;
        PluginStatus status;
        std::vector<std::string> errors;
        std::chrono::steady_clock::time_point enabled_at;
    };
    
    std::map<std::string, PluginEntry> plugins_;
    std::map<std::string, std::vector<std::string>> hook_registrations_;
    mutable std::mutex plugins_mutex_;
    
    std::thread health_check_thread_;
    
    void HealthCheckLoop();
    bool ValidatePluginCompatibility(const PluginManifest& manifest);
    void CleanupPluginData(const std::string& plugin_id);
};

// ============================================================================
// Plugin Sandbox
// ============================================================================

class PluginSandbox {
public:
    struct Config {
        size_t max_memory_mb = 256;
        int max_cpu_percent = 50;
        std::vector<std::string> allowed_syscalls;
        std::vector<std::string> allowed_paths;
        bool network_access = false;
        std::vector<std::string> allowed_hosts;
    };
    
    explicit PluginSandbox(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Execution
    bool ExecuteInSandbox(const std::string& plugin_id,
                          std::function<void()> code);
    
    // Resource limits
    bool SetMemoryLimit(size_t max_mb);
    bool SetCPULimit(int max_percent);
    bool SetFileSystemAccess(const std::vector<std::string>& allowed_paths);
    bool SetNetworkAccess(bool allowed, const std::vector<std::string>& hosts);
    
    // Monitoring
    struct ResourceUsage {
        size_t memory_used_mb = 0;
        double cpu_percent = 0.0;
        int file_descriptors = 0;
        int network_connections = 0;
    };
    
    ResourceUsage GetResourceUsage(const std::string& plugin_id) const;
    bool IsWithinLimits(const std::string& plugin_id) const;
    
    // Security
    bool CheckPermission(const std::string& plugin_id, const std::string& permission);
    bool GrantPermission(const std::string& plugin_id, const std::string& permission);
    bool RevokePermission(const std::string& plugin_id, const std::string& permission);
    
private:
    Config config_;
    std::map<std::string, ResourceUsage> usage_;
    mutable std::mutex usage_mutex_;
};

// ============================================================================
// Plugin API Gateway
// ============================================================================

class PluginAPIGateway {
public:
    struct Config {
        bool enable_rate_limiting = true;
        int requests_per_minute = 100;
        bool require_authentication = true;
        std::map<std::string, std::string> auth_config;
    };
    
    explicit PluginAPIGateway(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Registration
    bool RegisterEndpoint(const std::string& plugin_id,
                          const std::string& path,
                          const std::string& method,
                          std::function<std::string(const std::map<std::string, std::string>&)> handler);
    bool UnregisterEndpoint(const std::string& plugin_id, const std::string& path);
    
    // Execution
    std::string HandleRequest(const std::string& path,
                              const std::string& method,
                              const std::map<std::string, std::string>& headers,
                              const std::string& body);
    
    // Rate limiting
    bool CheckRateLimit(const std::string& plugin_id);
    void ResetRateLimit(const std::string& plugin_id);
    
    // Authentication
    bool AuthenticateRequest(const std::map<std::string, std::string>& headers);
    std::string GenerateAPIToken(const std::string& plugin_id);
    bool ValidateToken(const std::string& token);
    
private:
    Config config_;
    
    struct APIEndpoint {
        std::string plugin_id;
        std::string path;
        std::string method;
        std::function<std::string(const std::map<std::string, std::string>&)> handler;
    };
    
    std::vector<APIEndpoint> endpoints_;
    mutable std::mutex endpoints_mutex_;
    
    std::map<std::string, std::chrono::steady_clock::time_point> rate_limits_;
    mutable std::mutex rate_mutex_;
};

// ============================================================================
// Plugin Runtime
// ============================================================================

class PluginRuntime {
public:
    struct Config {
        PluginLoader::Config loader;
        PluginManager::Config manager;
        PluginSandbox::Config sandbox;
        PluginAPIGateway::Config api_gateway;
    };
    
    explicit PluginRuntime(const Config& config);
    ~PluginRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    PluginLoader* GetLoader();
    PluginManager* GetManager();
    PluginSandbox* GetSandbox();
    PluginAPIGateway* GetAPIGateway();
    
    // Convenience methods
    bool InstallAndEnable(const std::string& package_path);
    bool DisableAndUninstall(const std::string& plugin_id);
    std::vector<std::shared_ptr<PluginInterface>> GetPluginsByCapability(
        const std::string& capability);
    
    // Health
    bool IsHealthy() const;
    std::map<std::string, bool> GetSubsystemHealth() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<PluginLoader> loader_;
    std::unique_ptr<PluginManager> manager_;
    std::unique_ptr<PluginSandbox> sandbox_;
    std::unique_ptr<PluginAPIGateway> api_gateway_;
};

} // namespace Ecosystem
} // namespace Sovereign
