/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <optional>
#include <nlohmann/json.hpp>

namespace RawrXD {

/**
 * @enum AutonomousState
 * Explicit state machine for deterministic replay and debugging.
 * Every transition is logged with timestamp and artifacts.
 */
enum class AutonomousState {
    Idle,           // Waiting for goal
    GoalReceived,   // Goal parsed and validated
    Planning,       // Creating execution plan
    ContextLoading, // Loading project context
    Executing,      // Executing plan steps
    Building,       // Build in progress
    Testing,        // Running tests
    Repairing,      // Attempting automatic repair
    Completed,      // Task completed successfully
    Failed,         // Task failed (unrecoverable)
    Cancelled       // User cancelled
};

/**
 * @struct StateTransition
 * Records every state change for deterministic replay.
 */
struct StateTransition {
    AutonomousState from;
    AutonomousState to;
    std::chrono::system_clock::time_point timestamp;
    std::string trigger;      // What caused the transition
    std::string input;        // Input artifact (file path or data)
    std::string output;       // Output artifact (file path or data)
    
    nlohmann::json toJson() const {
        nlohmann::json j;
        j["from"] = stateToString(from);
        j["to"] = stateToString(to);
        j["timestamp"] = std::chrono::system_clock::to_time_t(timestamp);
        j["trigger"] = trigger;
        j["input"] = input;
        j["output"] = output;
        return j;
    }
    
    static std::string stateToString(AutonomousState state) {
        switch (state) {
            case AutonomousState::Idle: return "IDLE";
            case AutonomousState::GoalReceived: return "GOAL_RECEIVED";
            case AutonomousState::Planning: return "PLANNING";
            case AutonomousState::ContextLoading: return "CONTEXT_LOADING";
            case AutonomousState::Executing: return "EXECUTING";
            case AutonomousState::Building: return "BUILDING";
            case AutonomousState::Testing: return "TESTING";
            case AutonomousState::Repairing: return "REPAIRING";
            case AutonomousState::Completed: return "COMPLETED";
            case AutonomousState::Failed: return "FAILED";
            case AutonomousState::Cancelled: return "CANCELLED";
        }
        return "UNKNOWN";
    }
};

/**
 * @struct UserGoal
 * Natural language goal from user
 */
struct UserGoal {
    std::string id;           // UUID
    std::string description; // Natural language
    std::string type;        // "feature", "fix", "refactor", etc.
    std::chrono::system_clock::time_point receivedAt;
    
    nlohmann::json toJson() const {
        nlohmann::json j;
        j["id"] = id;
        j["description"] = description;
        j["type"] = type;
        j["received_at"] = std::chrono::system_clock::to_time_t(receivedAt);
        return j;
    }
};

/**
 * @struct Plan
 * Execution plan generated from goal
 */
struct Plan {
    std::string id;
    std::vector<std::string> steps;
    std::vector<std::string> dependencies;
    std::chrono::system_clock::time_point createdAt;
    
    nlohmann::json toJson() const {
        nlohmann::json j;
        j["id"] = id;
        j["steps"] = steps;
        j["dependencies"] = dependencies;
        j["created_at"] = std::chrono::system_clock::to_time_t(createdAt);
        return j;
    }
};

/**
 * @struct FileChange
 * Single file modification
 */
struct FileChange {
    std::string path;
    std::string operation;  // "modify", "create", "delete"
    std::string diff;       // Unified diff
    int linesAdded;
    int linesRemoved;
};

/**
 * @struct BuildResult
 * Build execution result
 */
struct BuildResult {
    bool success;
    int exitCode;
    std::string log;
    std::chrono::milliseconds duration;
    std::vector<std::string> targetsBuilt;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

/**
 * @struct TestResult
 * Single test execution
 */
struct TestResult {
    std::string name;
    bool passed;
    std::string output;
    std::chrono::milliseconds duration;
    std::optional<std::string> failureReason;
};

/**
 * @struct RepairAttempt
 * Automatic repair attempt
 */
struct RepairAttempt {
    std::string failureType;
    std::string strategy;
    bool success;
    std::vector<FileChange> changes;
    std::string log;
};

/**
 * @struct CompletionReport
 * Final task completion report
 */
struct CompletionReport {
    bool success;
    std::string goalId;
    int stepsCompleted;
    int totalSteps;
    std::vector<std::string> filesModified;
    bool buildSucceeded;
    int testsPassed;
    int testsFailed;
    int repairsAttempted;
    std::chrono::milliseconds duration;
    std::string errorMessage;
    bool humanInterventionRequired;
    std::string humanInterventionReason;
    
    nlohmann::json toJson() const {
        nlohmann::json j;
        j["success"] = success;
        j["goal_id"] = goalId;
        j["steps_completed"] = stepsCompleted;
        j["total_steps"] = totalSteps;
        j["files_modified"] = filesModified;
        j["build_succeeded"] = buildSucceeded;
        j["tests_passed"] = testsPassed;
        j["tests_failed"] = testsFailed;
        j["repairs_attempted"] = repairsAttempted;
        j["duration_ms"] = duration.count();
        j["error"] = errorMessage;
        j["human_intervention_required"] = humanInterventionRequired;
        j["human_intervention_reason"] = humanInterventionReason;
        return j;
    }
};

/**
 * @struct AutonomousRunContext
 * Shared execution object - the single source of truth for an autonomous run.
 * Every component receives and updates this object.
 * The trace is a serialization of this object.
 */
struct AutonomousRunContext {
    // Identity
    std::string runId;
    std::string commitHash;
    std::string binarySha256;
    std::chrono::system_clock::time_point startedAt;
    
    // Input
    UserGoal goal;
    
    // Planning
    std::optional<Plan> plan;
    
    // Execution
    std::vector<FileChange> changes;
    
    // Validation
    std::optional<BuildResult> build;
    std::vector<TestResult> tests;
    
    // Recovery
    std::vector<RepairAttempt> repairs;
    
    // Completion
    std::optional<CompletionReport> completion;
    
    // State machine
    AutonomousState currentState = AutonomousState::Idle;
    std::vector<StateTransition> transitions;
    
    // Telemetry
    std::vector<nlohmann::json> events;
    
    void transitionTo(AutonomousState newState, const std::string& trigger, 
                      const std::string& input = "", const std::string& output = "");
    
    void addEvent(const std::string& component, const std::string& event,
                  const nlohmann::json& data);
    
    nlohmann::json toJson() const;
    bool save(const std::string& evidenceDir) const;
    
    static std::string generateRunId();
};

/**
 * @class AutonomyController
 * The missing product layer that coordinates all autonomous capabilities.
 * 
 * This is the centerpiece that transforms individual components into an
 * autonomous engineering system.
 * 
 * Evidence Required:
 * - [ ] Compiles (C)
 * - [ ] Instantiates with components (B)
 * - [ ] Executes goal end-to-end (A)
 * - [ ] Produces completion trace (A)
 */
class AutonomyController {
public:
    // Component references (existing subsystems)
    struct Components {
        class PlanOrchestrator* planner;
        class AgenticExecutor* executor;
        class AgenticMemorySystem* memory;
        class ErrorRecoverySystem* errorRecovery;
        // Build and test systems (existing infrastructure)
    };
    
    explicit AutonomyController(const Components& components);
    ~AutonomyController();
    
    /**
     * Execute a user goal autonomously
     * 
     * This is the main entry point for VAL-012.
     * 
     * @param goal Natural language goal
     * @param evidenceDir Directory to save execution trace
     * @return Completion report with full trace
     */
    CompletionReport execute(const UserGoal& goal, 
                            const std::string& evidenceDir = "evidence/val-012");
    
    /**
     * Execute with human approval gates
     * Level 1: Approve plan
     * Level 2: Approve patch
     * Level 3: Fully autonomous
     */
    CompletionReport executeWithApproval(const UserGoal& goal,
                                        int autonomyLevel,  // 1, 2, or 3
                                        const std::string& evidenceDir = "evidence/val-012");
    
    /**
     * Get current execution context (for monitoring)
     */
    const AutonomousRunContext* getCurrentContext() const { return currentRun_.get(); }
    
    /**
     * Get state machine transitions (for debugging)
     */
    std::vector<StateTransition> getTransitions() const;

private:
    Components components_;
    std::unique_ptr<AutonomousRunContext> currentRun_;
    
    // State handlers
    void handleGoalReceived();
    void handlePlanning();
    void handleContextLoading();
    void handleExecuting();
    void handleBuilding();
    void handleTesting();
    void handleRepairing();
    void handleCompleted();
    void handleFailed();
    
    // Integration points
    bool executePlanStep(const std::string& step);
    bool triggerBuild();
    bool runTests();
    bool attemptRepair(const std::string& failure);
    
    // Validation
    void validateComponents();
};

} // namespace RawrXD
