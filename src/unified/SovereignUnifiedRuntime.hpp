// Phase D.9 Batch 1/5: Unified Runtime & Service Registry
// Core runtime that orchestrates all Sovereign components
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <thread>
#include <condition_variable>

namespace Sovereign {
namespace Unified {

// ============================================================================
// Service Registry
// ============================================================================

enum class ServiceState {
    UNREGISTERED = 0,
    REGISTERING = 1,
    REGISTERED = 2,
    STARTING = 3,
    RUNNING = 4,
    STOPPING = 5,
    STOPPED = 6,
    ERROR = 7,
    DEGRADED = 8
};

struct ServiceHealth {
    bool healthy = false;
    std::string status;
    std::chrono::steady_clock::time_point last_check;
    std::map<std::string, std::string> metrics;
    std::vector<std::string> issues;
};

struct ServiceEndpoint {
    std::string protocol;  // http, https, grpc, tcp
    std::string host;
    int port = 0;
    std::string path;
    std::map<std::string, std::string> metadata;
    int weight = 100;
    bool healthy = true;
};

struct ServiceInstance {
    std::string id;
    std::string service_name;
    std::string version;
    std::string node_id;
    ServiceState state = ServiceState::UNREGISTERED;
    ServiceHealth health;
    std::vector<ServiceEndpoint> endpoints;
    std::map<std::string, std::string> metadata;
    std::chrono::steady_clock::time_point registered_at;
    std::chrono::steady_clock::time_point last_heartbeat;
};

class ServiceRegistry {
public:
    struct Config {
        std::string registry_type = "consul";  // consul, etcd, zookeeper, kubernetes
        std::string address;
        int port = 8500;
        std::string datacenter = "dc1";
        std::chrono::seconds heartbeat_interval{10};
        std::chrono::seconds ttl{30};
        bool enable_health_checks = true;
    };
    
    explicit ServiceRegistry(const Config& config);
    ~ServiceRegistry();
    
    bool Initialize();
    void Shutdown();
    
    // Service registration
    bool RegisterService(const ServiceInstance& instance);
    bool DeregisterService(const std::string& instance_id);
    bool UpdateService(const ServiceInstance& instance);
    
    // Service discovery
    std::vector<ServiceInstance> DiscoverServices(const std::string& service_name);
    std::vector<ServiceInstance> DiscoverHealthyServices(const std::string& service_name);
    ServiceInstance GetService(const std::string& instance_id);
    
    // Health management
    bool UpdateHealth(const std::string& instance_id, const ServiceHealth& health);
    bool SendHeartbeat(const std::string& instance_id);
    
    // Watch for changes
    using ServiceChangeHandler = std::function<void(const std::string& service_name,
                                                     const ServiceInstance& instance,
                                                     bool added)>;
    bool WatchService(const std::string& service_name, ServiceChangeHandler handler);
    void UnwatchService(const std::string& service_name);
    
    // Load balancing
    ServiceInstance SelectInstance(const std::string& service_name,
                                    const std::string& strategy = "round_robin");
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::map<std::string, ServiceInstance> services_;
    std::map<std::string, std::vector<ServiceChangeHandler>> watchers_;
    std::mutex services_mutex_;
    
    std::thread heartbeat_thread_;
    std::map<std::string, std::chrono::steady_clock::time_point> heartbeats_;
    
    void HeartbeatLoop();
    void CleanupExpiredServices();
    bool RegisterWithBackend(const ServiceInstance& instance);
    bool DeregisterFromBackend(const std::string& instance_id);
};

// ============================================================================
// Lifecycle Manager
// ============================================================================

enum class LifecyclePhase {
    INITIALIZING = 0,
    CONFIGURING = 1,
    STARTING_SERVICES = 2,
    RUNNING = 3,
    DEGRADED = 4,
    SHUTTING_DOWN = 5,
    TERMINATED = 6
};

class LifecycleManager {
public:
    struct Config {
        std::chrono::seconds startup_timeout{300};
        std::chrono::seconds shutdown_timeout{60};
        bool graceful_shutdown = true;
        int max_startup_attempts = 3;
        bool auto_restart_failed_services = true;
    };
    
    struct ServiceLifecycle {
        std::string service_name;
        std::function<bool()> initialize;
        std::function<bool()> start;
        std::function<void()> stop;
        std::function<bool()> health_check;
        std::vector<std::string> dependencies;
        LifecyclePhase phase = LifecyclePhase::INITIALIZING;
        int startup_attempts = 0;
        std::chrono::steady_clock::time_point phase_entered;
    };
    
    explicit LifecycleManager(const Config& config);
    ~LifecycleManager();
    
    bool Initialize();
    void Shutdown();
    
    // Service registration
    bool RegisterService(const ServiceLifecycle& service);
    bool UnregisterService(const std::string& service_name);
    
    // Lifecycle control
    bool StartAll();
    bool StopAll();
    bool RestartService(const std::string& service_name);
    
    // Phase management
    LifecyclePhase GetCurrentPhase() const;
    bool TransitionTo(LifecyclePhase phase);
    
    // Health monitoring
    bool IsHealthy() const;
    std::map<std::string, bool> GetServiceHealth() const;
    std::vector<std::string> GetUnhealthyServices() const;
    
    // Events
    using PhaseChangeHandler = std::function<void(LifecyclePhase old_phase, LifecyclePhase new_phase)>;
    using ServiceStateHandler = std::function<void(const std::string& service_name, bool healthy)>;
    void OnPhaseChange(PhaseChangeHandler handler);
    void OnServiceStateChange(ServiceStateHandler handler);
    
private:
    Config config_;
    std::atomic<LifecyclePhase> current_phase_{LifecyclePhase::INITIALIZING};
    std::atomic<bool> running_{false};
    
    std::map<std::string, ServiceLifecycle> services_;
    std::mutex services_mutex_;
    
    std::vector<PhaseChangeHandler> phase_handlers_;
    std::vector<ServiceStateHandler> state_handlers_;
    
    std::thread monitor_thread_;
    
    void MonitorLoop();
    bool StartService(const std::string& service_name);
    bool StopService(const std::string& service_name);
    std::vector<std::string> GetStartupOrder();
    std::vector<std::string> GetShutdownOrder();
    void NotifyPhaseChange(LifecyclePhase old_phase, LifecyclePhase new_phase);
    void NotifyServiceStateChange(const std::string& service_name, bool healthy);
};

// ============================================================================
// Configuration Manager
// ============================================================================

class ConfigurationManager {
public:
    struct Config {
        std::string config_source = "file";  // file, etcd, consul, kubernetes
        std::string config_path;
        std::string environment = "development";
        bool hot_reload = true;
        std::chrono::seconds reload_interval{30};
    };
    
    struct ConfigValue {
        std::string key;
        std::string value;
        std::string source;
        std::chrono::steady_clock::time_point updated_at;
        int version = 0;
    };
    
    explicit ConfigurationManager(const Config& config);
    ~ConfigurationManager();
    
    bool Initialize();
    void Shutdown();
    
    // Configuration access
    std::string GetString(const std::string& key, const std::string& default_value = "");
    int GetInt(const std::string& key, int default_value = 0);
    double GetDouble(const std::string& key, double default_value = 0.0);
    bool GetBool(const std::string& key, bool default_value = false);
    std::vector<std::string> GetStringArray(const std::string& key);
    std::map<std::string, std::string> GetObject(const std::string& key);
    
    // Configuration updates
    bool SetValue(const std::string& key, const std::string& value);
    bool SetValues(const std::map<std::string, std::string>& values);
    bool DeleteValue(const std::string& key);
    
    // Bulk operations
    bool LoadFromFile(const std::string& path);
    bool LoadFromEnvironment();
    bool SaveToFile(const std::string& path);
    
    // Validation
    bool ValidateConfig();
    std::vector<std::string> GetValidationErrors();
    
    // Watching
    using ConfigChangeHandler = std::function<void(const std::string& key,
                                                      const std::string& old_value,
                                                      const std::string& new_value)>;
    bool WatchKey(const std::string& key, ConfigChangeHandler handler);
    void UnwatchKey(const std::string& key);
    
    // Environment-specific
    bool IsEnvironment(const std::string& env);
    std::string GetEnvironment() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::map<std::string, ConfigValue> config_values_;
    std::map<std::string, std::vector<ConfigChangeHandler>> watchers_;
    std::mutex config_mutex_;
    
    std::thread reload_thread_;
    
    void ReloadLoop();
    bool LoadConfig();
    void NotifyWatchers(const std::string& key, const std::string& old_value,
                        const std::string& new_value);
    std::string ExpandEnvironmentVariables(const std::string& value);
};

// ============================================================================
// Unified Runtime
// ============================================================================

class UnifiedRuntime {
public:
    struct Config {
        ServiceRegistry::Config registry;
        LifecycleManager::Config lifecycle;
        ConfigurationManager::Config configuration;
        std::string runtime_id;
        std::string runtime_version = "1.0.0";
        std::string node_id;
        std::string cluster_name;
    };
    
    explicit UnifiedRuntime(const Config& config);
    ~UnifiedRuntime();
    
    bool Initialize();
    void Shutdown();
    bool IsRunning() const;
    
    // Subsystem access
    ServiceRegistry* GetServiceRegistry();
    LifecycleManager* GetLifecycleManager();
    ConfigurationManager* GetConfigurationManager();
    
    // Runtime info
    std::string GetRuntimeID() const;
    std::string GetRuntimeVersion() const;
    std::string GetNodeID() const;
    std::string GetClusterName() const;
    LifecyclePhase GetPhase() const;
    
    // Health
    bool IsHealthy() const;
    std::map<std::string, std::string> GetHealthStatus();
    
    // Metrics
    std::map<std::string, double> GetRuntimeMetrics();
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<ServiceRegistry> registry_;
    std::unique_ptr<LifecycleManager> lifecycle_;
    std::unique_ptr<ConfigurationManager> configuration_;
    
    std::chrono::steady_clock::time_point started_at_;
};

} // namespace Unified
} // namespace Sovereign
