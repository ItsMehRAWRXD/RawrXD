/**
 * DecisionTypes.hpp
 *
 * Phase C.3 Batch 1/5: Autonomous Decision Layer - Decision Types
 *
 * Defines the decision structures and types for the autonomous control loop.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <optional>

namespace Autonomy {

/**
 * Decision types that the autonomous engine can make
 */
enum class DecisionType {
    OPTIMIZE_PATH,           // Reorder or parallelize execution path
    SPAWN_WORKERS,           // Add worker threads/agents
    MERGE_TASKS,            // Combine related tasks
    REBALANCE_RESOURCES,    // Redistribute compute/memory
    RECOVER_STATE,          // Recover from checkpoint
    EXPLORE_ALTERNATIVE,    // Try alternative execution strategy
    FREEZE_UNSTABLE_COMPONENT, // Isolate unstable component
    ADJUST_HARMONICS,       // Modify harmonic weights
    SCALE_UP,               // Increase capacity
    SCALE_DOWN,             // Decrease capacity
    PAUSE_EXECUTION,        // Temporarily halt
    RESUME_EXECUTION,       // Resume from pause
    TERMINATE_GRACEFULLY,   // Controlled shutdown
    NONE                    // No decision
};

/**
 * Decision priority levels
 */
enum class DecisionPriority {
    CRITICAL,    // Immediate action required
    HIGH,        // Action within 1 cycle
    MEDIUM,      // Action within 5 cycles
    LOW,         // Action when convenient
    DEFERRED     // Queue for later
};

/**
 * Decision status tracking
 */
enum class DecisionStatus {
    PENDING,      // Awaiting execution
    APPROVED,     // Approved by governance
    REJECTED,     // Rejected by governance
    EXECUTING,    // Currently being executed
    COMPLETED,    // Successfully completed
    FAILED,       // Execution failed
    ROLLED_BACK   // Rolled back due to issues
};

/**
 * Context information for decision making
 */
struct DecisionContext {
    double systemStability{1.0};           // Current stability (0-1)
    double resourceUtilization{0.5};       // Resource usage (0-1)
    double performanceTrend{0.0};          // Performance delta
    int activeTasks{0};                    // Currently executing tasks
    int pendingTasks{0};                   // Queued tasks
    double errorRate{0.0};                 // Recent error rate
    int64_t timestampMs{0};                // Decision timestamp
    std::map<std::string, double> metrics; // Additional metrics
    
    std::string ToJson() const;
};

/**
 * Action to be taken as part of a decision
 */
struct Action {
    std::string actionId;
    std::string description;
    std::string targetComponent;          // Component to act upon
    std::map<std::string, std::string> parameters;
    double estimatedDurationMs{0.0};       // Expected execution time
    double rollbackProbability{0.0};       // Likelihood of needing rollback
    
    std::string ToJson() const;
};

/**
 * Decision outcome tracking
 */
struct DecisionOutcome {
    bool success{false};
    double actualUtility{0.0};             // Measured utility
    double executionTimeMs{0.0};            // Actual execution time
    std::string errorMessage;               // If failed
    std::map<std::string, double> beforeMetrics;
    std::map<std::string, double> afterMetrics;
    int64_t completedTimestampMs{0};
    
    std::string ToJson() const;
};

/**
 * Core decision structure
 */
struct Decision {
    std::string decisionId;
    DecisionType type{DecisionType::NONE};
    DecisionPriority priority{DecisionPriority::MEDIUM};
    DecisionStatus status{DecisionStatus::PENDING};
    
    double confidence{0.0};                 // Confidence in decision (0-1)
    double expectedUtility{0.0};            // Predicted utility gain
    double riskScore{0.0};                  // Risk assessment (0-1)
    
    std::string rationale;                  // Natural language explanation
    std::vector<Action> actions;            // Actions to execute
    
    DecisionContext context;                // Context at decision time
    std::optional<DecisionOutcome> outcome;  // Outcome after execution
    
    int64_t createdTimestampMs{0};
    int64_t executedTimestampMs{0};
    
    // Methods
    std::string ToJson() const;
    std::string ToNaturalLanguage() const;
    bool RequiresApproval() const;
    bool CanExecute() const;
};

/**
 * Decision configuration
 */
struct DecisionEngineConfig {
    double minConfidenceThreshold{0.6};     // Minimum confidence to act
    double maxRiskThreshold{0.8};            // Maximum acceptable risk
    bool requireApprovalForCritical{true};  // Governance check
    int maxPendingDecisions{100};            // Backlog limit
    double utilityThreshold{0.1};            // Minimum expected utility
    int decisionTimeoutMs{5000};            // Max time to decide
    
    std::string ToJson() const;
};

/**
 * Decision statistics
 */
struct DecisionStatistics {
    int totalDecisions{0};
    int approvedDecisions{0};
    int rejectedDecisions{0};
    int completedDecisions{0};
    int failedDecisions{0};
    int rolledBackDecisions{0};
    
    double averageConfidence{0.0};
    double averageUtility{0.0};
    double averageRisk{0.0};
    double successRate{0.0};
    
    std::map<DecisionType, int> decisionsByType;
    
    void RecordDecision(const Decision& decision);
    std::string ToJson() const;
    void PrintSummary() const;
};

/**
 * Utility functions
 */
std::string DecisionTypeToString(DecisionType type);
DecisionType StringToDecisionType(const std::string& str);
std::string DecisionPriorityToString(DecisionPriority priority);
std::string DecisionStatusToString(DecisionStatus status);

} // namespace Autonomy
