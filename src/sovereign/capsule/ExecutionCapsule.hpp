// ExecutionCapsule.hpp
// The Execution Capsule - binds all 10 coordination primitives into unified organism
// This is the "body" that gives the system coherent behavior

#pragma once
#include "../spine/ExecutionSpine.hpp"
#include "../terminal/TerminalOwnership.hpp"
#include "../build/BuildStateGraph.hpp"
#include "../agent/AgentLease.hpp"
#include "../bus/BeaconBus.hpp"
#include "../compression/IntentCompression.hpp"
#include "../awareness/SystemAwareness.hpp"
#include "../validator/RealityValidator.hpp"
#include "../recovery/AutonomousRecovery.hpp"
#include "../control/SovereignControlPlane.hpp"

#include <memory>
#include <thread>
#include <atomic>

namespace Sovereign {

// Capsule configuration
struct CapsuleConfig {
    bool enable_spine = true;
    bool enable_terminal_ownership = true;
    bool enable_build_graph = true;
    bool enable_agent_leases = true;
    bool enable_beacon_bus = true;
    bool enable_intent_compression = true;
    bool enable_awareness = true;
    bool enable_validator = true;
    bool enable_recovery = true;
    bool enable_control_plane = true;
    
    uint32_t heartbeat_interval_ms = 1000;
    uint32_t validation_interval_ms = 5000;
    uint32_t recovery_check_interval_ms = 1000;
};

// Capsule state
enum class CapsuleState {
    UNINITIALIZED,
    INITIALIZING,
    ACTIVE,
    DEGRADED,
    SHUTTING_DOWN,
    SHUTDOWN
};

// The Execution Capsule - unified coordination system
class ExecutionCapsule {
public:
    static ExecutionCapsule& Instance();
    
    // Lifecycle
    bool Initialize(const CapsuleConfig& config = CapsuleConfig{});
    void Shutdown();
    bool IsInitialized() const { return state_ != CapsuleState::UNINITIALIZED; }
    bool IsActive() const { return state_ == CapsuleState::ACTIVE || state_ == CapsuleState::DEGRADED; }
    CapsuleState GetState() const { return state_; }
    
    // Core operations - these use ALL 10 primitives
    
    // Execute an intent through the full coordination pipeline
    ExecutionResult ExecuteIntent(const FullIntent& intent);
    ExecutionResult ExecuteIntent(const std::string& prompt);
    
    // Execute with terminal ownership
    ExecutionResult ExecuteWithTerminal(const FullIntent& intent, const std::string& terminal_id);
    
    // Build with full state tracking
    bool ExecuteBuild(const std::string& target, const BuildConfiguration& config);
    bool CancelBuild();
    
    // Spawn agent with lease
    std::optional<std::string> SpawnAgent(const AgentDescriptor& descriptor);
    bool TerminateAgent(const std::string& lease_id);
    
    // Event subscription
    using CapsuleEventCallback = std::function<void(const Beacon&)>;
    std::string Subscribe(CapsuleEventCallback callback);
    std::string Subscribe(BeaconType type, CapsuleEventCallback callback);
    void Unsubscribe(const std::string& subscription_id);
    
    // Queries
    SystemSnapshot GetSystemSnapshot() const;
    std::vector<ValidationResult> ValidateSystem() const;
    BuildStateGraph::CurrentBuild GetBuildStatus() const;
    std::vector<AgentLease> GetActiveAgents() const;
    
    // Control
    void Pause();
    void Resume();
    void EnterDegradedMode(const std::string& reason);
    void RecoverFromDegradedMode();
    
    // Statistics
    struct CapsuleStats {
        uint64_t intents_executed;
        uint64_t intents_failed;
        uint64_t agents_spawned;
        uint64_t agents_terminated;
        uint64_t builds_triggered;
        uint64_t builds_completed;
        uint64_t recoveries_attempted;
        uint64_t recoveries_successful;
        double average_execution_time_ms;
        double uptime_seconds;
    };
    CapsuleStats GetStats() const;

private:
    ExecutionCapsule() = default;
    ~ExecutionCapsule();
    
    ExecutionCapsule(const ExecutionCapsule&) = delete;
    ExecutionCapsule& operator=(const ExecutionCapsule&) = delete;
    
    // Background threads
    void HeartbeatThread();
    void ValidationThread();
    void RecoveryThread();
    void EventProcessingThread();
    
    // Coordination helpers
    bool AcquireResources(const FullIntent& intent);
    void ReleaseResources();
    bool ValidateExecution(const ExecutionResult& result);
    void EmitExecutionBeacon(const ExecutionResult& result);
    
    CapsuleConfig config_;
    CapsuleState state_ = CapsuleState::UNINITIALIZED;
    std::chrono::time_point<std::chrono::steady_clock> initialized_at_;
    
    // Background threads
    std::unique_ptr<std::thread> heartbeat_thread_;
    std::unique_ptr<std::thread> validation_thread_;
    std::unique_ptr<std::thread> recovery_thread_;
    std::unique_ptr<std::thread> event_thread_;
    
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    
    // Current execution context
    std::optional<std::string> current_agent_lease_;
    std::optional<std::string> current_terminal_lease_;
    std::optional<std::string> current_build_subscription_;
    
    // Statistics
    CapsuleStats stats_;
    mutable std::mutex stats_mutex_;
};

// Convenience function to get the global capsule
ExecutionCapsule& GetCapsule();

// RAII capsule guard
class CapsuleGuard {
public:
    CapsuleGuard();
    ~CapsuleGuard();
    
    CapsuleGuard(const CapsuleGuard&) = delete;
    CapsuleGuard& operator=(const CapsuleGuard&) = delete;
    
    bool IsActive() const;
    ExecutionCapsule* operator->() { return &ExecutionCapsule::Instance(); }
    const ExecutionCapsule* operator->() const { return &ExecutionCapsule::Instance(); }

private:
    bool initialized_;
};

} // namespace Sovereign
