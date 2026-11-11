/**
 * AutonomousController.hpp
 *
 * Phase C.3 Batch 4/5: Autonomous Runtime Loop
 *
 * Integrates SovereignRuntime → AutonomousController → DecisionEngine → SEG → Swarm
 * Supports runtime modes: MANUAL, ASSISTED, AUTONOMOUS, SELF_OPTIMIZING
 */

#pragma once

#include "AutonomousDecisionEngine.hpp"
#include "SEGMutationEngine.hpp"
#include "DecisionMemory.hpp"
#include "../runtime/SovereignRuntime.hpp"
#include "../seg/ExecutionGraph.hpp"
#include "../swarm/SwarmCoordinator.hpp"

#include <memory>
#include <thread>
#include <atomic>
#include <condition_variable>

namespace Autonomy {

/**
 * Runtime modes for autonomous operation
 */
enum class RuntimeMode {
    MANUAL,           // Human control only
    ASSISTED,         // Suggestions, human approval
    AUTONOMOUS,       // Full autonomous with governance
    SELF_OPTIMIZING   // Autonomous + self-modification
};

std::string RuntimeModeToString(RuntimeMode mode);

/**
 * Controller configuration
 */
struct AutonomousControllerConfig {
    RuntimeMode mode{RuntimeMode::ASSISTED};
    int decisionIntervalMs{1000};        // How often to generate decisions
    int executionIntervalMs{100};          // Control loop frequency
    double stabilityThreshold{0.3};          // Min stability before intervention
    int maxConsecutiveFailures{3};         // Failures before mode downgrade
    bool enableSelfOptimization{false};    // Allow SEG mutations
    bool enableEmergencyStop{true};        // Auto-stop on critical issues
    
    std::string ToJson() const;
};

/**
 * Controller state
 */
struct ControllerState {
    RuntimeMode currentMode{RuntimeMode::MANUAL};
    bool isRunning{false};
    bool isPaused{false};
    int cycleCount{0};
    int decisionsThisCycle{0};
    int consecutiveFailures{0};
    double currentStability{1.0};
    int64_t startTimeMs{0};
    int64_t lastDecisionTimeMs{0};
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Control loop metrics
 */
struct ControlLoopMetrics {
    int totalCycles{0};
    int decisionsGenerated{0};
    int decisionsExecuted{0};
    int decisionsRejected{0};
    double averageCycleTimeMs{0.0};
    double averageStability{1.0};
    std::map<RuntimeMode, int64_t> timeInModeMs;
    
    void RecordCycle(double cycleTimeMs);
    void RecordDecision(bool executed);
    void Print() const;
};

/**
 * Autonomous Controller
 *
 * The central integration point that closes the autonomous control loop:
 *
 *   Telemetry
 *       ↓
 *   Pattern Detection
 *       ↓
 *   Role Formation
 *       ↓
 *   Intent Generation
 *       ↓
 *   Decision Engine ←── [AutonomousController]
 *       ↓
 *   SEG Plan Mutation
 *       ↓
 *   Execution
 *       ↓
 *   Performance Feedback
 *       └───────────────┘
 */
class AutonomousController {
public:
    AutonomousController();
    ~AutonomousController();

    // Disable copy
    AutonomousController(const AutonomousController&) = delete;
    AutonomousController& operator=(const AutonomousController&) = delete;

    /**
     * Initialize the controller
     */
    bool Initialize(const AutonomousControllerConfig& config);

    /**
     * Shutdown
     */
    void Shutdown();

    /**
     * Set runtime components
     */
    void SetRuntime(std::shared_ptr<Runtime::SovereignRuntime> runtime);
    void SetDecisionEngine(std::shared_ptr<AutonomousDecisionEngine> engine);
    void SetMutationEngine(std::shared_ptr<SEGMutationEngine> mutationEngine);
    void SetSwarmCoordinator(std::shared_ptr<Swarm::SwarmCoordinator> swarm);

    /**
     * Start the autonomous control loop
     */
    bool Start();

    /**
     * Stop the control loop
     */
    void Stop();

    /**
     * Pause/resume
     */
    void Pause();
    void Resume();
    bool IsPaused() const;

    /**
     * Set runtime mode
     */
    void SetMode(RuntimeMode mode);
    RuntimeMode GetMode() const;

    /**
     * Emergency stop
     */
    void EmergencyStop();
    void ClearEmergency();
    bool IsEmergencyStopped() const;

    /**
     * Get current state
     */
    ControllerState GetState() const;

    /**
     * Get metrics
     */
    ControlLoopMetrics GetMetrics() const;

    /**
     * Execute single control cycle (for testing)
     */
    void ExecuteControlCycle();

    /**
     * Wait for specific condition (for testing)
     */
    bool WaitForStableState(int timeoutMs = 5000);

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    // Configuration
    AutonomousControllerConfig config_;
    
    // State
    ControllerState state_;
    ControlLoopMetrics metrics_;
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdownRequested_{false};
    
    // Components
    std::shared_ptr<Runtime::SovereignRuntime> runtime_;
    std::shared_ptr<AutonomousDecisionEngine> decisionEngine_;
    std::shared_ptr<SEGMutationEngine> mutationEngine_;
    std::shared_ptr<Swarm::SwarmCoordinator> swarm_;
    
    // Threading
    std::unique_ptr<std::thread> controlThread_;
    mutable std::mutex stateMutex_;
    std::condition_variable stateCv_;
    
    // Control loop
    void ControlLoop();
    void ProcessTelemetry();
    void GenerateAndExecuteDecisions();
    void ApplyMutations(const std::vector<Decision>& decisions);
    void UpdateModeBasedOnStability();
    
    // Safety
    bool ValidateDecisionSafety(const Decision& decision) const;
    void HandleDecisionFailure(const Decision& decision);
    
    // Helpers
    int64_t GetCurrentTimeMs() const;
    void RecordCycleTime(int64_t startMs);
};

/**
 * Mode transition manager
 */
class ModeTransitionManager {
public:
    struct Transition {
        RuntimeMode from;
        RuntimeMode to;
        std::string reason;
        int64_t timestampMs;
    };
    
    bool CanTransition(RuntimeMode from, RuntimeMode to) const;
    std::vector<Transition> GetTransitionHistory() const;
    void RecordTransition(RuntimeMode from, RuntimeMode to, const std::string& reason);
    
private:
    std::vector<Transition> history_;
    mutable std::mutex mutex_;
};

/**
 * Safety envelope - prevents dangerous decisions
 */
class SafetyEnvelope {
public:
    struct Constraint {
        std::string name;
        std::function<bool(const Decision&, const ControllerState&)> check;
        RuntimeMode minMode;  // Minimum mode required to bypass
    };
    
    void AddConstraint(const Constraint& constraint);
    bool CheckDecision(const Decision& decision, 
                      const ControllerState& state,
                      std::string& violation) const;
    
private:
    std::vector<Constraint> constraints_;
};

/**
 * CLI for testing
 */
class AutonomousControllerCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static AutonomousControllerConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Autonomy
