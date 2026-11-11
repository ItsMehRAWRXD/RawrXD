// Phase D.9 Batch 5/5: System Orchestrator
// Master orchestrator that unifies all Sovereign components
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>

namespace Sovereign {
namespace Unified {

// Forward declarations
class UnifiedRuntime;
class IntegrationRuntime;
class GatewayRuntime;
class MonitoringControlPlaneRuntime;

// ============================================================================
// System State
// ============================================================================

enum class SystemPhase {
    UNINITIALIZED = 0,
    INITIALIZING = 1,
    CONFIGURING = 2,
    STARTING = 3,
    RUNNING = 4,
    DEGRADED = 5,
    MAINTENANCE = 6,
    SHUTTING_DOWN = 7,
    TERMINATED = 8
};

struct SystemState {
    SystemPhase phase = SystemPhase::UNINITIALIZED;
    std::string version;
    std::string build_hash;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point phase_changed_at;
    std::map<std::string, std::string> metadata;
    bool healthy = false;
    std::vector<std::string> active_alerts;
};

// ============================================================================
// Component Status
// ============================================================================

struct ComponentStatus {
    std::string name;
    std::string version;
    bool initialized = false;
    bool running = false;
    bool healthy = false;
    std::chrono::steady_clock::time_point started_at;
    std::map<std::string, std::any> metrics;
    std::vector<std::string> issues;
};

// ============================================================================
// Orchestrator Configuration
// ============================================================================

struct OrchestratorConfig {
    // Runtime configurations
    UnifiedRuntime::Config unified;
    IntegrationRuntime::Config integration;
    GatewayRuntime::Config gateway;
    MonitoringControlPlaneRuntime::Config monitoring;
    
    // System settings
    std::string system_name = "sovereign";
    std::string environment = "production";
    std::string region = "us-east-1";
    std::string cluster_id;
    std::string node_id;
    
    // Feature flags
    bool enable_distributed_runtime = true;
    bool enable_cloud_deployment = true;
    bool enable_federation = true;
    bool enable_intelligence = true;
    bool enable_security = true;
    bool enable_devtools = true;
    bool enable_api_gateway = true;
    bool enable_monitoring = true;
    
    // Operational settings
    std::chrono::seconds startup_timeout{300};
    std::chrono::seconds shutdown_timeout{60};
    bool graceful_shutdown = true;
    bool auto_restart_failed_components = true;
    int max_restart_attempts = 3;
};

// ============================================================================
// System Orchestrator
// ============================================================================

class SystemOrchestrator {
public:
    explicit SystemOrchestrator(const OrchestratorConfig& config);
    ~SystemOrchestrator();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsRunning() const;
    
    // Phase management
    SystemPhase GetCurrentPhase() const;
    bool TransitionToPhase(SystemPhase phase);
    
    // Component access
    UnifiedRuntime* GetUnifiedRuntime();
    IntegrationRuntime* GetIntegrationRuntime();
    GatewayRuntime* GetGatewayRuntime();
    MonitoringControlPlaneRuntime* GetMonitoringRuntime();
    
    // Component status
    std::vector<ComponentStatus> GetComponentStatuses() const;
    ComponentStatus GetComponentStatus(const std::string& name) const;
    bool IsComponentHealthy(const std::string& name) const;
    std::vector<std::string> GetUnhealthyComponents() const;
    
    // System operations
    bool RestartComponent(const std::string& name);
    bool RestartAllComponents();
    bool EnterMaintenanceMode();
    bool ExitMaintenanceMode();
    
    // Health and metrics
    bool IsHealthy() const;
    SystemState GetSystemState() const;
    std::map<std::string, std::any> GetSystemMetrics() const;
    
    // Events
    using PhaseChangeHandler = std::function<void(SystemPhase old_phase, SystemPhase new_phase)>;
    using ComponentStatusHandler = std::function<void(const std::string& name, bool healthy)>;
    using SystemAlertHandler = std::function<void(const std::string& alert, const std::string& severity)>;
    
    void OnPhaseChange(PhaseChangeHandler handler);
    void OnComponentStatusChange(ComponentStatusHandler handler);
    void OnSystemAlert(SystemAlertHandler handler);
    
    // API endpoints
    std::map<std::string, std::function<std::string(const std::map<std::string, std::string>&)>> GetAPIHandlers();
    
private:
    OrchestratorConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<SystemPhase> current_phase_{SystemPhase::UNINITIALIZED};
    
    std::unique_ptr<UnifiedRuntime> unified_runtime_;
    std::unique_ptr<IntegrationRuntime> integration_runtime_;
    std::unique_ptr<GatewayRuntime> gateway_runtime_;
    std::unique_ptr<MonitoringControlPlaneRuntime> monitoring_runtime_;
    
    std::vector<PhaseChangeHandler> phase_handlers_;
    std::vector<ComponentStatusHandler> status_handlers_;
    std::vector<SystemAlertHandler> alert_handlers_;
    mutable std::mutex handlers_mutex_;
    
    std::thread health_monitor_thread_;
    
    void HealthMonitorLoop();
    bool InitializeComponents();
    void ShutdownComponents();
    void NotifyPhaseChange(SystemPhase old_phase, SystemPhase new_phase);
    void NotifyComponentStatusChange(const std::string& name, bool healthy);
    void NotifySystemAlert(const std::string& alert, const std::string& severity);
    bool CanTransitionTo(SystemPhase new_phase);
};

// ============================================================================
// Deployment Manifest
// ============================================================================

struct DeploymentManifest {
    std::string api_version = "v1";
    std::string kind = "SovereignDeployment";
    
    struct Metadata {
        std::string name;
        std::string namespace_ = "default";
        std::map<std::string, std::string> labels;
        std::map<std::string, std::string> annotations;
    } metadata;
    
    struct Spec {
        struct ComponentSpec {
            std::string name;
            std::string image;
            std::string version;
            int replicas = 1;
            std::map<std::string, std::string> resources;
            std::map<std::string, std::string> env;
            std::vector<std::string> ports;
            std::vector<std::string> volumes;
            std::map<std::string, std::string> config;
            bool enabled = true;
        };
        
        struct NetworkSpec {
            std::string service_mesh = "istio";
            bool mtls = true;
            std::vector<std::string> ingress_rules;
            std::vector<std::string> egress_rules;
        };
        
        struct StorageSpec {
            std::string storage_class = "standard";
            std::map<std::string, std::string> volumes;
        };
        
        std::vector<ComponentSpec> components;
        NetworkSpec network;
        StorageSpec storage;
        std::map<std::string, std::string> global_config;
    } spec;
    
    struct Status {
        std::string phase;
        std::string message;
        std::chrono::steady_clock::time_point deployed_at;
        std::map<std::string, std::string> component_statuses;
    } status;
};

class ManifestManager {
public:
    bool LoadFromFile(const std::string& path);
    bool LoadFromYAML(const std::string& yaml);
    bool SaveToFile(const std::string& path) const;
    std::string ToYAML() const;
    
    DeploymentManifest GetManifest() const;
    bool UpdateManifest(const DeploymentManifest& manifest);
    
    bool Validate() const;
    std::vector<std::string> GetValidationErrors() const;
    
    bool Apply(SystemOrchestrator* orchestrator);
    bool Destroy(SystemOrchestrator* orchestrator);
    
private:
    DeploymentManifest manifest_;
};

// ============================================================================
// CLI Interface
// ============================================================================

class OrchestratorCLI {
public:
    struct Command {
        std::string name;
        std::string description;
        std::vector<std::string> args;
        std::map<std::string, std::string> flags;
        std::function<int(const std::map<std::string, std::string>& args,
                         const std::map<std::string, std::string>& flags)> handler;
    };
    
    explicit OrchestratorCLI(SystemOrchestrator* orchestrator);
    
    bool Initialize();
    void Shutdown();
    
    // Command registration
    void RegisterCommand(const Command& command);
    void RegisterDefaultCommands();
    
    // Execution
    int Execute(int argc, char* argv[]);
    int ExecuteCommand(const std::string& command, 
                       const std::map<std::string, std::string>& args = {},
                       const std::map<std::string, std::string>& flags = {});
    
    // Interactive mode
    void RunInteractive();
    
    // Help
    void PrintHelp() const;
    void PrintCommandHelp(const std::string& command) const;
    
private:
    SystemOrchestrator* orchestrator_;
    std::map<std::string, Command> commands_;
    bool running_ = false;
    
    void RegisterStartCommand();
    void RegisterStopCommand();
    void RegisterStatusCommand();
    void RegisterRestartCommand();
    void RegisterConfigCommand();
    void RegisterDeployCommand();
    void RegisterLogsCommand();
    void RegisterMetricsCommand();
    void RegisterHealthCommand();
};

// ============================================================================
// Bootstrap
// ============================================================================

class SystemBootstrap {
public:
    struct Config {
        std::string config_path;
        std::string manifest_path;
        bool daemon_mode = false;
        bool enable_cli = true;
        int api_port = 8080;
        int grpc_port = 9090;
    };
    
    static int Run(const Config& config);
    static std::unique_ptr<SystemOrchestrator> CreateOrchestrator(const Config& config);
    static bool LoadConfiguration(const std::string& path, OrchestratorConfig& config);
    static bool LoadManifest(const std::string& path, DeploymentManifest& manifest);
    
private:
    static void SetupSignalHandlers(SystemOrchestrator* orchestrator);
    static void SetupLogging();
    static void PrintBanner();
};

} // namespace Unified
} // namespace Sovereign
