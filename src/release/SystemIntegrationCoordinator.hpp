// RawrXD System Integration Coordinator
// Phase U.1: Final system integration and validation
// Coordinates all subsystems for production readiness

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>

namespace RawrXD {
namespace Release {

// Forward declarations
class HealthCheckSystem;
class ConfigurationManager;
class AuditLogger;

// Integration checkpoint
struct IntegrationCheckpoint {
    std::string name;
    std::string description;
    std::vector<std::string> dependencies;
    std::function<bool()> validator;
    bool isComplete{false};
    std::chrono::steady_clock::time_point completedAt;
    std::string errorMessage;
};

// Subsystem status
struct SubsystemStatus {
    std::string name;
    std::string version;
    bool isInitialized{false};
    bool isHealthy{false};
    std::chrono::steady_clock::time_point initializedAt;
    std::chrono::steady_clock::time_point lastHealthCheck;
    std::map<std::string, std::string> metrics;
    std::vector<std::string> activeAlerts;
};

// Integration report
struct IntegrationReport {
    std::chrono::system_clock::time_point generatedAt;
    bool overallSuccess{false};
    
    struct CheckpointResult {
        std::string name;
        bool passed;
        std::string message;
        std::chrono::milliseconds duration;
    };
    std::vector<CheckpointResult> checkpointResults;
    
    struct SubsystemSummary {
        std::string name;
        bool healthy;
        std::string version;
    };
    std::vector<SubsystemSummary> subsystemSummaries;
    
    uint32_t totalCheckpoints{0};
    uint32_t passedCheckpoints{0};
    uint32_t failedCheckpoints{0};
    uint32_t totalSubsystems{0};
    uint32_t healthySubsystems{0};
    
    std::vector<std::string> blockers;
    std::vector<std::string> warnings;
    std::vector<std::string> recommendations;
};

// System integration coordinator
class SystemIntegrationCoordinator {
public:
    SystemIntegrationCoordinator(HealthCheckSystem* health,
                                ConfigurationManager* config,
                                AuditLogger* audit);
    ~SystemIntegrationCoordinator();
    
    // Lifecycle
    bool initialize();
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Checkpoint management
    void registerCheckpoint(const IntegrationCheckpoint& checkpoint);
    bool completeCheckpoint(const std::string& name);
    bool isCheckpointComplete(const std::string& name) const;
    std::vector<std::string> getPendingCheckpoints() const;
    
    // Subsystem registration
    void registerSubsystem(const std::string& name, const std::string& version);
    void updateSubsystemStatus(const std::string& name, const SubsystemStatus& status);
    SubsystemStatus getSubsystemStatus(const std::string& name) const;
    std::vector<SubsystemStatus> getAllSubsystemStatuses() const;
    
    // Integration validation
    bool validateIntegration();
    bool validateSubsystem(const std::string& name);
    bool validateDependencies(const std::string& name);
    
    // Integration report
    IntegrationReport generateReport() const;
    bool exportReport(const std::string& path) const;
    
    // Pre-flight checks
    bool runPreflightChecks();
    std::vector<std::string> getPreflightErrors() const;
    
    // System readiness
    bool isSystemReady() const;
    std::vector<std::string> getReadinessBlockers() const;
    
    // Coordination
    void coordinateStartup();
    void coordinateShutdown();
    void coordinateRestart();
    
    // Event handling
    using IntegrationEventCallback = std::function<void(const std::string& event, 
                                                         const std::map<std::string, std::string>& data)>;
    void setEventCallback(IntegrationEventCallback callback);
    
    // Statistics
    struct IntegrationStats {
        uint32_t totalCheckpoints;
        uint32_t completedCheckpoints;
        uint32_t totalSubsystems;
        uint32_t initializedSubsystems;
        uint32_t healthySubsystems;
        std::chrono::milliseconds totalIntegrationTime;
    };
    IntegrationStats getStats() const;

private:
    void notifyEvent(const std::string& event, const std::map<std::string, std::string>& data);
    bool runCheckpoint(const IntegrationCheckpoint& checkpoint);
    
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    mutable std::mutex mutex_;
    
    HealthCheckSystem* health_;
    ConfigurationManager* config_;
    AuditLogger* audit_;
    
    std::map<std::string, IntegrationCheckpoint> checkpoints_;
    std::map<std::string, SubsystemStatus> subsystems_;
    std::vector<std::string> preflightErrors_;
    
    IntegrationEventCallback eventCallback_;
    
    std::chrono::steady_clock::time_point startupTime_;
};

// Startup orchestrator
class StartupOrchestrator {
public:
    StartupOrchestrator(SystemIntegrationCoordinator* coordinator);
    
    // Startup phases
    enum class StartupPhase {
        INITIALIZE_CORE,
        LOAD_CONFIGURATION,
        INITIALIZE_SECURITY,
        INITIALIZE_STORAGE,
        INITIALIZE_NETWORK,
        START_SERVICES,
        VERIFY_HEALTH,
        READY
    };
    
    bool executeStartup();
    bool executePhase(StartupPhase phase);
    StartupPhase getCurrentPhase() const { return currentPhase_; }
    
    // Phase callbacks
    using PhaseCallback = std::function<bool()>;
    void setPhaseCallback(StartupPhase phase, PhaseCallback callback);
    
    // Rollback
    bool rollbackToPhase(StartupPhase phase);
    
private:
    SystemIntegrationCoordinator* coordinator_;
    std::atomic<StartupPhase> currentPhase_{StartupPhase::INITIALIZE_CORE};
    std::map<StartupPhase, PhaseCallback> phaseCallbacks_;
};

// Shutdown coordinator
class ShutdownCoordinator {
public:
    ShutdownCoordinator(SystemIntegrationCoordinator* coordinator);
    
    // Shutdown phases
    enum class ShutdownPhase {
        DRAIN_REQUESTS,
        STOP_SERVICES,
        FLUSH_DATA,
        RELEASE_RESOURCES,
        SHUTDOWN_CORE,
        COMPLETE
    };
    
    bool executeShutdown(bool graceful = true);
    bool executePhase(ShutdownPhase phase);
    ShutdownPhase getCurrentPhase() const { return currentPhase_; }
    
private:
    SystemIntegrationCoordinator* coordinator_;
    std::atomic<ShutdownPhase> currentPhase_{ShutdownPhase::DRAIN_REQUESTS};
};

} // namespace Release
} // namespace RawrXD
