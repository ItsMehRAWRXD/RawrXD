/**
 * SovereignOrchestrator.hpp
 *
 * Phase D.1 Batch 1/5: Master Runtime Coordinator
 *
 * Owns lifecycle ordering, initializes every subsystem,
 * coordinates shutdown, and enforces contracts.
 *
 * Startup Order:
 *   Runtime → SEG → Engine → Swarm → Telemetry → 
 *   Emergent Layer → Autonomy Controller
 */

#pragma once

#include "SovereignState.hpp"
#include "../runtime/SovereignRuntime.hpp"
#include "../seg/ExecutionGraph.hpp"
#include "../engine/Engine.hpp"
#include "../swarm/SwarmCoordinator.hpp"
#include "../telemetry/TelemetryCollector.hpp"
#include "../emergent/EmergentPatternDetector.hpp"
#include "../autonomy/AutonomousController.hpp"

#include <memory>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>

namespace Core {

/**
 * Orchestrator configuration
 */
struct OrchestratorConfig {
    // Startup timeouts
    int runtimeInitTimeoutMs{5000};
    int segInitTimeoutMs{3000};
    int engineInitTimeoutMs{5000};
    int swarmInitTimeoutMs{3000};
    int telemetryInitTimeoutMs{2000};
    int emergentInitTimeoutMs{3000};
    int autonomyInitTimeoutMs{5000};
    
    // Shutdown timeouts
    int shutdownTimeoutMs{10000};
    
    // Health check
    int healthCheckIntervalMs{1000};
    int maxConsecutiveHealthFailures{3};
    
    // Recovery
    bool enableAutoRecovery{true};
    int recoveryAttempts{3};
    
    std::string ToJson() const;
};

/**
 * Subsystem descriptor
 */
struct SubsystemInfo {
    std::string name;
    std::string version;
    bool initialized{false};
    bool running{false};
    int64_t initTimeMs{0};
    int64_t startTimeMs{0};
    std::string lastError;
    
    std::string ToJson() const;
};

/**
 * Lifecycle phases
 */
enum class LifecyclePhase {
    UNINITIALIZED,
    INITIALIZING,
    INITIALIZED,
    STARTING,
    RUNNING,
    PAUSING,
    PAUSED,
    RESUMING,
    STOPPING,
    STOPPED,
    SHUTTING_DOWN,
    SHUTDOWN,
    ERROR
};

std::string LifecyclePhaseToString(LifecyclePhase phase);

/**
 * Sovereign Orchestrator
 *
 * The master coordinator that manages the entire system lifecycle.
 * Ensures proper initialization order, monitors health, and coordinates shutdown.
 */
class SovereignOrchestrator {
public:
    SovereignOrchestrator();
    ~SovereignOrchestrator();

    // Disable copy, enable move
    SovereignOrchestrator(const SovereignOrchestrator&) = delete;
    SovereignOrchestrator& operator=(const SovereignOrchestrator&) = delete;
    SovereignOrchestrator(SovereignOrchestrator&&) noexcept;
    SovereignOrchestrator& operator=(SovereignOrchestrator&&) noexcept;

    /**
     * Initialize the orchestrator and all subsystems
     * 
     * Startup order:
     *   1. Runtime
     *   2. SEG
     *   3. Engine
     *   4. Swarm
     *   5. Telemetry
     *   6. Emergent Layer
     *   7. Autonomy Controller
     */
    bool Initialize(const OrchestratorConfig& config);

    /**
     * Start all subsystems
     */
    bool Start();

    /**
     * Pause execution (maintain state)
     */
    bool Pause();

    /**
     * Resume from pause
     */
    bool Resume();

    /**
     * Stop all subsystems
     */
    bool Stop();

    /**
     * Full shutdown
     */
    void Shutdown();

    /**
     * Emergency shutdown
     */
    void EmergencyShutdown();

    /**
     * Get current lifecycle phase
     */
    LifecyclePhase GetPhase() const;

    /**
     * Get unified system state
     */
    SovereignState GetSystemState() const;

    /**
     * Get subsystem information
     */
    std::vector<SubsystemInfo> GetSubsystemInfo() const;

    /**
     * Check if all subsystems are healthy
     */
    bool IsHealthy() const;

    /**
     * Get health report
     */
    std::string GetHealthReport() const;

    /**
     * Wait for phase transition
     */
    bool WaitForPhase(LifecyclePhase phase, int timeoutMs = 30000);

    /**
     * Set phase change callback
     */
    using PhaseChangeCallback = std::function<void(LifecyclePhase oldPhase, LifecyclePhase newPhase)>;
    void SetPhaseChangeCallback(PhaseChangeCallback callback);

    /**
     * Set error callback
     */
    using ErrorCallback = std::function<void(const std::string& subsystem, const std::string& error)>;
    void SetErrorCallback(ErrorCallback callback);

    /**
     * Print status
     */
    void PrintStatus() const;

    /**
     * Get singleton instance
     */
    static SovereignOrchestrator& Instance();

private:
    // Configuration
    OrchestratorConfig config_;
    
    // State
    std::atomic<LifecyclePhase> phase_{LifecyclePhase::UNINITIALIZED};
    SovereignState systemState_;
    std::vector<SubsystemInfo> subsystems_;
    
    // Subsystem instances
    std::shared_ptr<Runtime::SovereignRuntime> runtime_;
    std::shared_ptr<SEG::ExecutionGraph> segGraph_;
    std::shared_ptr<Engine::Engine> engine_;
    std::shared_ptr<Swarm::SwarmCoordinator> swarm_;
    std::shared_ptr<Telemetry::TelemetryCollector> telemetry_;
    std::shared_ptr<Emergent::EmergentPatternDetector> emergent_;
    std::shared_ptr<Autonomy::AutonomousController> autonomy_;
    
    // Threading
    std::unique_ptr<std::thread> healthMonitorThread_;
    std::atomic<bool> shutdownRequested_{false};
    mutable std::mutex mutex_;
    std::condition_variable phaseCv_;
    
    // Callbacks
    PhaseChangeCallback phaseCallback_;
    ErrorCallback errorCallback_;
    
    // Lifecycle methods
    bool InitializeRuntime();
    bool InitializeSEG();
    bool InitializeEngine();
    bool InitializeSwarm();
    bool InitializeTelemetry();
    bool InitializeEmergent();
    bool InitializeAutonomy();
    
    bool StartRuntime();
    bool StartSEG();
    bool StartEngine();
    bool StartSwarm();
    bool StartTelemetry();
    bool StartEmergent();
    bool StartAutonomy();
    
    bool StopRuntime();
    bool StopSEG();
    bool StopEngine();
    bool StopSwarm();
    bool StopTelemetry();
    bool StopEmergent();
    bool StopAutonomy();
    
    void ShutdownRuntime();
    void ShutdownSEG();
    void ShutdownEngine();
    void ShutdownSwarm();
    void ShutdownTelemetry();
    void ShutdownEmergent();
    void ShutdownAutonomy();
    
    // Health monitoring
    void HealthMonitorLoop();
    bool CheckSubsystemHealth(const std::string& name);
    
    // State management
    void UpdateSystemState();
    void TransitionPhase(LifecyclePhase newPhase);
    void ReportError(const std::string& subsystem, const std::string& error);
    
    // Helpers
    int64_t GetCurrentTimeMs() const;
    SubsystemInfo* FindSubsystem(const std::string& name);
};

/**
 * CLI for testing the orchestrator
 */
class SovereignOrchestratorCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static OrchestratorConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Core
