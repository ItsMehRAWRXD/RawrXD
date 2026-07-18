/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

#include "../plan_orchestrator.h"
#include "../agentic_executor.h"
#include "../error_recovery_system.h"
#include "../agentic_memory_system.h"
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
#include <functional>

namespace RawrXD {

/**
 * @struct ExecutionTrace
 * Records every step of autonomous execution for validation
 */
struct ExecutionTrace {
    std::string goal;
    std::string planJson;
    std::vector<std::string> stepsExecuted;
    std::vector<std::string> filesModified;
    std::string buildLog;
    std::string testLog;
    std::vector<std::string> repairsAttempted;
    bool success = false;
    std::string errorMessage;
    int64_t executionTimeMs = 0;
    
    nlohmann::json toJson() const {
        nlohmann::json j;
        j["goal"] = goal;
        j["plan"] = nlohmann::json::parse(planJson);
        j["steps_executed"] = stepsExecuted;
        j["files_modified"] = filesModified;
        j["build_log"] = buildLog;
        j["test_log"] = testLog;
        j["repairs_attempted"] = repairsAttempted;
        j["success"] = success;
        j["error"] = errorMessage;
        j["execution_time_ms"] = executionTimeMs;
        return j;
    }
    
    bool save(const std::string& path) const {
        std::ofstream ofs(path);
        if (!ofs) return false;
        ofs << toJson().dump(2);
        return ofs.good();
    }
};

/**
 * @struct AutonomousExecutionResult
 * Result of one autonomous task execution
 */
struct AutonomousExecutionResult {
    bool success = false;
    std::string goal;
    int stepsCompleted = 0;
    int totalSteps = 0;
    std::vector<std::string> filesModified;
    bool buildSucceeded = false;
    bool testsPassed = false;
    int repairsAttempted = 0;
    std::string errorMessage;
    ExecutionTrace trace;
    
    bool isComplete() const {
        return success && buildSucceeded && testsPassed;
    }
};

/**
 * @class PlannerExecutorBridge
 * Connects PlanOrchestrator to AgenticExecutor with error recovery and memory
 * 
 * This is the critical integration point that closes the autonomy loop.
 * 
 * Evidence Required:
 * - [ ] Compiles (C)
 * - [ ] Plan flows from Planner to Executor (B)
 * - [ ] Execution results captured (B)
 * - [ ] Error recovery triggered on failure (A)
 * - [ ] Memory updated with outcomes (A)
 */
class PlannerExecutorBridge {
public:
    PlannerExecutorBridge(
        PlanOrchestrator* planner,
        AgenticExecutor* executor,
        ErrorRecoverySystem* errorRecovery,
        AgenticMemorySystem* memory);
    
    /**
     * Execute a goal autonomously
     * 
     * @param goal Natural language goal (e.g., "Fix the off-by-one error")
     * @return Execution result with complete trace
     */
    AutonomousExecutionResult executeGoal(const std::string& goal);
    
    /**
     * Execute with explicit evidence collection
     * Saves trace to evidence/ directory for validation
     */
    AutonomousExecutionResult executeGoalWithEvidence(
        const std::string& goal,
        const std::string& evidenceDir = "evidence/val-012");

private:
    PlanOrchestrator* planner_;
    AgenticExecutor* executor_;
    ErrorRecoverySystem* errorRecovery_;
    AgenticMemorySystem* memory_;
    
    // Execution state
    ExecutionTrace currentTrace_;
    std::chrono::steady_clock::time_point startTime_;
    
    // Step handlers
    bool executeStep(const PlanOrchestrator::Step& step);
    bool handleBuildStep();
    bool handleTestStep();
    bool handleRepairStep(const std::string& failure);
    
    // Recovery
    bool attemptRecovery(const std::string& step, const std::string& error);
    
    // Memory
    void recordSuccess(const std::string& goal, const ExecutionTrace& trace);
    void recordFailure(const std::string& goal, const std::string& error);
    
    // Validation
    void validateIntegrationPoints();
};

} // namespace RawrXD
