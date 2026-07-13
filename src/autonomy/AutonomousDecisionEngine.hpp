/**
 * AutonomousDecisionEngine.hpp
 *
 * Phase C.3 Batch 1/5: Autonomous Decision Layer - Decision Engine Core
 *
 * The central decision-making component that consumes emergent patterns,
 * runtime state, and performance metrics to produce actionable decisions.
 */

#pragma once

#include "DecisionTypes.hpp"
#include "../emergent/EmergentPatternDetector.hpp"
#include "../emergent/EmergentIntentModel.hpp"
#include "../telemetry/TelemetryCollector.hpp"
#include "../swarm/SwarmCoordinator.hpp"

#include <memory>
#include <queue>
#include <functional>
#include <mutex>

namespace Autonomy {

// Forward declarations
class DecisionMemory;
class DecisionGovernance;

/**
 * Callback for decision execution
 */
using DecisionExecutor = std::function<bool(const Decision&)>;

/**
 * Callback for decision notifications
 */
using DecisionCallback = std::function<void(const Decision&)>;

/**
 * Autonomous Decision Engine
 *
 * Consumes:
 *   - Emergent patterns (from PatternDetector)
 *   - Runtime state (from SovereignRuntime)
 *   - Performance metrics (from Telemetry)
 *   - Swarm state (from SwarmCoordinator)
 *
 * Produces:
 *   - Decisions with confidence scores
 *   - Action sequences
 *   - Risk assessments
 */
class AutonomousDecisionEngine {
public:
    AutonomousDecisionEngine();
    ~AutonomousDecisionEngine();

    // Disable copy, enable move
    AutonomousDecisionEngine(const AutonomousDecisionEngine&) = delete;
    AutonomousDecisionEngine& operator=(const AutonomousDecisionEngine&) = delete;
    AutonomousDecisionEngine(AutonomousDecisionEngine&&) noexcept;
    AutonomousDecisionEngine& operator=(AutonomousDecisionEngine&&) noexcept;

    /**
     * Initialize the decision engine
     */
    bool Initialize(const DecisionEngineConfig& config);

    /**
     * Shutdown and cleanup
     */
    void Shutdown();

    /**
     * Feed emergent patterns for decision consideration
     */
    void FeedPatterns(const std::vector<Emergent::Pattern>& patterns);

    /**
     * Feed runtime telemetry
     */
    void FeedTelemetry(const Telemetry::TelemetrySnapshot& snapshot);

    /**
     * Feed swarm state
     */
    void FeedSwarmState(const Swarm::SwarmState& state);

    /**
     * Feed intent models
     */
    void FeedIntents(const std::vector<Emergent::Intent>& intents);

    /**
     * Generate decisions based on current state
     * Returns list of pending decisions
     */
    std::vector<Decision> GenerateDecisions();

    /**
     * Evaluate a specific decision
     */
    double EvaluateDecision(const Decision& decision) const;

    /**
     * Approve or reject a pending decision
     */
    bool ApproveDecision(const std::string& decisionId);
    bool RejectDecision(const std::string& decisionId, const std::string& reason);

    /**
     * Execute an approved decision
     */
    bool ExecuteDecision(const std::string& decisionId);

    /**
     * Record outcome of executed decision
     */
    void RecordOutcome(const std::string& decisionId, const DecisionOutcome& outcome);

    /**
     * Get pending decisions
     */
    std::vector<Decision> GetPendingDecisions() const;

    /**
     * Get recent decisions
     */
    std::vector<Decision> GetRecentDecisions(int count = 10) const;

    /**
     * Get decision by ID
     */
    std::optional<Decision> GetDecision(const std::string& decisionId) const;

    /**
     * Get statistics
     */
    DecisionStatistics GetStatistics() const;

    /**
     * Set decision executor callback
     */
    void SetDecisionExecutor(DecisionExecutor executor);

    /**
     * Set decision callback (for notifications)
     */
    void SetDecisionCallback(DecisionCallback callback);

    /**
     * Enable/disable autonomous mode
     */
    void SetAutonomousMode(bool enabled);
    bool IsAutonomousMode() const;

    /**
     * Emergency stop - halt all autonomous decisions
     */
    void EmergencyStop();
    void ResumeAutonomy();
    bool IsEmergencyStopped() const;

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    // Core components
    std::unique_ptr<DecisionMemory> memory_;
    std::unique_ptr<DecisionGovernance> governance_;
    
    // State
    DecisionEngineConfig config_;
    bool initialized_{false};
    bool autonomousMode_{false};
    bool emergencyStopped_{false};
    
    // Input buffers
    std::vector<Emergent::Pattern> recentPatterns_;
    std::optional<Telemetry::TelemetrySnapshot> latestTelemetry_;
    std::optional<Swarm::SwarmState> latestSwarmState_;
    std::vector<Emergent::Intent> activeIntents_;
    
    // Decision storage
    std::map<std::string, Decision> decisions_;
    std::queue<std::string> pendingQueue_;
    std::vector<std::string> recentDecisionIds_;
    
    // Statistics
    DecisionStatistics statistics_;
    
    // Callbacks
    DecisionExecutor executor_;
    DecisionCallback callback_;
    
    // Threading
    mutable std::mutex mutex_;
    
    // Decision generation helpers
    std::vector<Decision> GenerateOptimizationDecisions();
    std::vector<Decision> GenerateScalingDecisions();
    std::vector<Decision> GenerateRecoveryDecisions();
    std::vector<Decision> GenerateExplorationDecisions();
    
    Decision CreateDecision(DecisionType type, 
                           const std::string& rationale,
                           const std::vector<Action>& actions);
    
    double CalculateConfidence(DecisionType type, const DecisionContext& context) const;
    double CalculateExpectedUtility(DecisionType type, const DecisionContext& context) const;
    double CalculateRisk(DecisionType type, const DecisionContext& context) const;
    
    DecisionContext BuildContext() const;
    std::string GenerateDecisionId() const;
};

/**
 * Decision governance - validates decisions against constraints
 */
class DecisionGovernance {
public:
    struct Constraint {
        std::string name;
        std::function<bool(const Decision&)> check;
        std::string violationMessage;
    };
    
    void AddConstraint(const Constraint& constraint);
    bool ValidateDecision(const Decision& decision, std::string& violation) const;
    
private:
    std::vector<Constraint> constraints_;
};

/**
 * CLI for testing the decision engine
 */
class AutonomousDecisionEngineCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static DecisionEngineConfig ParseArgs(int argc, char* argv[]);
    static void SimulatePatterns(AutonomousDecisionEngine& engine);
    static void SimulateTelemetry(AutonomousDecisionEngine& engine);
};

} // namespace Autonomy
