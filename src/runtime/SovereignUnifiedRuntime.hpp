// SovereignUnifiedRuntime.hpp
// Phase D.4 Batch 1/5 — Unified Runtime Integration
// The orchestration layer that unifies all sovereign components

#ifndef SOVEREIGN_UNIFIED_RUNTIME_HPP
#define SOVEREIGN_UNIFIED_RUNTIME_HPP

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <thread>
#include <condition_variable>

// Forward declarations for all sovereign components
namespace Autonomy {
    class AutonomousController;
    class StabilityEnvelope;
}

namespace Predictive {
    class WorkloadForecaster;
}

namespace Scheduler {
    class AdaptiveScheduler;
    class DistributedScheduler;
}

namespace SEG {
    class SEGSchedulerBridge;
}

namespace Interface {
    class SovereignAPIGateway;
    class SovereignQueryEngine;
    class HumanInteractionProtocol;
}

namespace Telemetry {
    class TelemetryCollector;
    class PerformanceStore;
}

namespace Swarm {
    class SwarmCoordinator;
}

namespace Checkpoint {
    class CheckpointManager;
}

namespace Autonomy {
    class DecisionMemory;
}

namespace RawrXD {

// ============================================================================
// Runtime State
// ============================================================================

enum class RuntimePhase {
    UNINITIALIZED,
    INITIALIZING,
    BOOTING,
    RUNNING,
    PAUSED,
    SHUTTING_DOWN,
    SHUTDOWN,
    ERROR
};

enum class RuntimeMode {
    STANDALONE,       // Single node, no external dependencies
    IDE_INTEGRATED,   // Running as VS Code extension
    SERVER,           // Headless server mode
    DISTRIBUTED       // Multi-node cluster (future)
};

struct RuntimeState {
    RuntimePhase phase;
    RuntimeMode mode;
    
    std::chrono::steady_clock::time_point boot_time;
    std::chrono::steady_clock::time_point last_state_change;
    
    // Component health
    std::map<std::string, bool> component_health;
    std::map<std::string, std::string> component_status;
    
    // Current metrics
    double cpu_utilization;
    double memory_utilization;
    double gpu_utilization;
    size_t active_agents;
    size_t pending_tasks;
    double current_tps;
    
    // Autonomy state
    bool autonomy_enabled;
    std::string current_autonomy_mode;
    uint32_t decisions_today;
    
    RuntimeState()
        : phase(RuntimePhase::UNINITIALIZED)
        , mode(RuntimeMode::STANDALONE)
        , cpu_utilization(0.0)
        , memory_utilization(0.0)
        , gpu_utilization(0.0)
        , active_agents(0)
        , pending_tasks(0)
        , current_tps(0.0)
        , autonomy_enabled(false)
        , decisions_today(0)
    {}
};

// ============================================================================
// Component Configuration
// ============================================================================

struct ComponentConfig {
    // Autonomy
    bool enable_autonomy;
    bool enable_stability_envelope;
    bool enable_learning;
    
    // Scheduling
    bool enable_adaptive_scheduler;
    bool enable_distributed_scheduler;
    bool enable_predictive_scheduling;
    
    // Interface
    bool enable_api_gateway;
    bool enable_query_engine;
    bool enable_human_protocol;
    uint16_t api_port;
    
    // Telemetry
    bool enable_telemetry;
    bool enable_performance_store;
    std::chrono::seconds telemetry_interval;
    
    // Swarm
    bool enable_swarm;
    uint32_t max_swarm_size;
    
    // Checkpoint
    bool enable_checkpoints;
    std::chrono::seconds checkpoint_interval;
    
    // SEG
    bool enable_seg;
    
    ComponentConfig()
        : enable_autonomy(true)
        , enable_stability_envelope(true)
        , enable_learning(true)
        , enable_adaptive_scheduler(true)
        , enable_distributed_scheduler(false)
        , enable_predictive_scheduling(true)
        , enable_api_gateway(true)
        , enable_query_engine(true)
        , enable_human_protocol(true)
        , api_port(8080)
        , enable_telemetry(true)
        , enable_performance_store(true)
        , telemetry_interval(std::chrono::seconds(5))
        , enable_swarm(true)
        , max_swarm_size(16)
        , enable_checkpoints(true)
        , checkpoint_interval(std::chrono::minutes(5))
        , enable_seg(true)
    {}
};

// ============================================================================
// Lifecycle Events
// ============================================================================

enum class LifecycleEvent {
    PRE_INIT,
    POST_INIT,
    PRE_BOOT,
    POST_BOOT,
    PRE_SHUTDOWN,
    POST_SHUTDOWN,
    ERROR_OCCURRED,
    STATE_CHANGE
};

using LifecycleCallback = std::function<void(LifecycleEvent, const std::string&)>;

// ============================================================================
// Health Report
// ============================================================================

struct HealthReport {
    bool overall_healthy;
    std::string overall_status;
    
    struct ComponentHealth {
        std::string name;
        bool healthy;
        std::string status;
        std::chrono::steady_clock::time_point last_check;
        std::string error_message;
    };
    
    std::vector<ComponentHealth> components;
    std::chrono::steady_clock::time_point generated_at;
    
    HealthReport() : overall_healthy(true) {}
};

// ============================================================================
// Unified State Export
// ============================================================================

struct UnifiedState {
    RuntimeState runtime;
    
    // Component states (serialized)
    std::string autonomy_state;
    std::string scheduler_state;
    std::string swarm_state;
    std::string telemetry_state;
    std::string seg_state;
    
    // Aggregated metrics
    std::map<std::string, double> metrics;
    
    // Recent events
    std::vector<std::string> recent_events;
    
    // Export timestamp
    std::chrono::steady_clock::time_point timestamp;
};

// ============================================================================
// Sovereign Unified Runtime
// ============================================================================

class SovereignUnifiedRuntime {
public:
    SovereignUnifiedRuntime();
    ~SovereignUnifiedRuntime();
    
    // Delete copy/move to enforce singleton pattern
    SovereignUnifiedRuntime(const SovereignUnifiedRuntime&) = delete;
    SovereignUnifiedRuntime& operator=(const SovereignUnifiedRuntime&) = delete;
    SovereignUnifiedRuntime(SovereignUnifiedRuntime&&) = delete;
    SovereignUnifiedRuntime& operator=(SovereignUnifiedRuntime&&) = delete;
    
    // Singleton access
    static SovereignUnifiedRuntime& Instance();
    
    // Configuration
    void Configure(const ComponentConfig& config);
    ComponentConfig GetConfiguration() const;
    
    // Lifecycle
    bool Initialize();
    bool Boot(RuntimeMode mode = RuntimeMode::STANDALONE);
    bool Pause();
    bool Resume();
    bool Shutdown();
    bool EmergencyShutdown(const std::string& reason);
    
    // State queries
    RuntimeState GetState() const;
    RuntimePhase GetPhase() const;
    RuntimeMode GetMode() const;
    bool IsRunning() const;
    bool IsHealthy() const;
    
    // Health
    HealthReport GenerateHealthReport() const;
    std::vector<std::string> GetUnhealthyComponents() const;
    
    // Unified state export
    UnifiedState ExportUnifiedState() const;
    std::string ExportStateAsJson() const;
    bool ImportState(const UnifiedState& state);
    
    // Component access (typed)
    Autonomy::AutonomousController* GetAutonomyController();
    Autonomy::StabilityEnvelope* GetStabilityEnvelope();
    Predictive::WorkloadForecaster* GetWorkloadForecaster();
    Scheduler::AdaptiveScheduler* GetAdaptiveScheduler();
    Interface::SovereignAPIGateway* GetAPIGateway();
    Interface::SovereignQueryEngine* GetQueryEngine();
    Telemetry::TelemetryCollector* GetTelemetryCollector();
    Swarm::SwarmCoordinator* GetSwarmCoordinator();
    Checkpoint::CheckpointManager* GetCheckpointManager();
    
    // Event handling
    void RegisterLifecycleCallback(LifecycleCallback callback);
    void NotifyEvent(LifecycleEvent event, const std::string& details);
    
    // Health monitoring
    void StartHealthMonitoring();
    void StopHealthMonitoring();
    
    // Statistics
    struct RuntimeStatistics {
        uint64_t total_boots;
        uint64_t total_shutdowns;
        uint64_t total_errors;
        std::chrono::seconds total_uptime;
        std::chrono::seconds current_session_uptime;
        uint64_t total_decisions;
        uint64_t total_mutations;
        uint64_t total_checkpoints;
    };
    
    RuntimeStatistics GetStatistics() const;
    void ResetStatistics();
    
    // CLI integration
    bool ExecuteCommand(const std::string& command, std::string& output);
    std::vector<std::string> GetAvailableCommands() const;
    
    // Signal handling
    void HandleSignal(int signal);
    void RegisterSignalHandlers();
    
private:
    // Configuration
    ComponentConfig config_;
    mutable std::mutex config_mutex_;
    
    // State
    RuntimeState state_;
    mutable std::mutex state_mutex_;
    
    // Components
    std::unique_ptr<Autonomy::AutonomousController> autonomy_controller_;
    std::unique_ptr<Autonomy::StabilityEnvelope> stability_envelope_;
    std::unique_ptr<Predictive::WorkloadForecaster> workload_forecaster_;
    std::unique_ptr<Scheduler::AdaptiveScheduler> adaptive_scheduler_;
    std::unique_ptr<Scheduler::DistributedScheduler> distributed_scheduler_;
    std::unique_ptr<SEG::SEGSchedulerBridge> seg_bridge_;
    std::unique_ptr<Interface::SovereignAPIGateway> api_gateway_;
    std::unique_ptr<Interface::SovereignQueryEngine> query_engine_;
    std::unique_ptr<Interface::HumanInteractionProtocol> human_protocol_;
    std::unique_ptr<Telemetry::TelemetryCollector> telemetry_collector_;
    std::unique_ptr<Telemetry::PerformanceStore> performance_store_;
    std::unique_ptr<Swarm::SwarmCoordinator> swarm_coordinator_;
    std::unique_ptr<Checkpoint::CheckpointManager> checkpoint_manager_;
    std::unique_ptr<Autonomy::DecisionMemory> decision_memory_;
    
    // Lifecycle
    std::vector<LifecycleCallback> lifecycle_callbacks_;
    mutable std::mutex callback_mutex_;
    
    // Health monitoring
    std::atomic<bool> health_monitoring_running_{false};
    std::thread health_monitor_thread_;
    
    // Statistics
    RuntimeStatistics stats_;
    mutable std::mutex stats_mutex_;
    
    // Internal methods
    bool InitializeComponents();
    bool BootComponents();
    bool ShutdownComponents();
    void UpdateComponentHealth();
    void HealthMonitorLoop();
    void TransitionToPhase(RuntimePhase new_phase);
    bool ValidateConfiguration() const;
    
    // Component factory methods
    bool CreateAutonomyComponents();
    bool CreateSchedulerComponents();
    bool CreateInterfaceComponents();
    bool CreateTelemetryComponents();
    bool CreateSwarmComponents();
    bool CreateCheckpointComponents();
    bool CreateSEGComponents();
};

// ============================================================================
// Runtime Facade
// ============================================================================

// Simplified facade for common operations
class RuntimeFacade {
public:
    // Quick access methods
    static bool Start(RuntimeMode mode = RuntimeMode::STANDALONE);
    static bool Stop();
    static bool Restart();
    static RuntimeState GetCurrentState();
    static HealthReport GetHealth();
    static std::string GetStatusJson();
    
    // Component shortcuts
    static bool EnableAutonomy(bool enable);
    static bool TriggerCheckpoint();
    static bool RestoreCheckpoint(const std::string& checkpoint_id);
    static std::vector<std::string> GetActiveAgents();
    static bool SpawnAgent(const std::string& agent_type);
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace RuntimeUtils {
    std::string PhaseToString(RuntimePhase phase);
    std::string ModeToString(RuntimeMode mode);
    RuntimePhase StringToPhase(const std::string& str);
    RuntimeMode StringToMode(const std::string& str);
    
    bool IsTerminalPhase(RuntimePhase phase);
    bool IsOperationalPhase(RuntimePhase phase);
    
    std::string GenerateRuntimeId();
    std::string GetVersionString();
    std::string GetBuildInfo();
} // namespace RuntimeUtils

} // namespace RawrXD

#endif // SOVEREIGN_UNIFIED_RUNTIME_HPP
