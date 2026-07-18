/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * VAL-019 Autonomous Execution Framework
 * 
 * Validates the complete autonomous execution chain:
 *   Agentic Engine → Planner → Tool Dispatch → Code Modification → Build → Test → Repair Loop → Evidence Archive
 * 
 * Architecture:
 *   - Inherits VAL-016 repair pipeline as a trusted primitive
 *   - Adds autonomous task planning and execution
 *   - Provides evidence integrity through hash chains
 *   - Supports long-run stability validation
 */

#ifndef VAL019_AUTONOMOUS_EXECUTION_H
#define VAL019_AUTONOMOUS_EXECUTION_H

#include "val016_repair_orchestrator.h"
#include "val014_execution_result.h"
#include <string>
#include <vector>
#include <functional>
#include <future>
#include <chrono>

namespace RawrXD {
namespace VAL019 {

// Forward declarations
struct AutonomousTask;
struct ExecutionPlan;
struct ExecutionContext;
struct EvidenceChain;

/**
 * @enum TaskType
 * Types of autonomous tasks the system can execute
 */
enum class TaskType {
    Unknown,
    FeatureAddition,      // "Add feature X"
    BugFix,              // "Fix bug Y"
    Refactoring,         // "Refactor Z"
    TestAddition,        // "Add tests for W"
    FailureRecovery      // Autonomous recovery from build/test failures
};

/**
 * @enum ExecutionPhase
 * Phases in the autonomous execution lifecycle
 */
enum class ExecutionPhase {
    Pending,             // Task received, not yet started
    Planning,          // Generating execution plan
    Dispatching,       // Dispatching tools/actions
    Modifying,         // Modifying code
    Building,          // Building modified code
    Testing,           // Running tests
    Repairing,          // VAL-016 repair loop if needed
    Verifying,         // Final verification
    Archiving,         // Evidence archival
    Completed,         // Success
    Failed             // Terminal failure
};

/**
 * @struct TaskRequest
 * Input request for autonomous execution
 */
struct TaskRequest {
    std::string taskId;
    TaskType type;
    std::string description;
    std::string targetFiles;
    std::vector<std::string> constraints;
    std::chrono::milliseconds timeout{300000};  // 5 min default
    
    val012::json toJson() const {
        val012::json j;
        j["task_id"] = taskId;
        j["type"] = static_cast<int>(type);
        j["description"] = description;
        j["target_files"] = targetFiles;
        j["constraints"] = constraints;
        j["timeout_ms"] = static_cast<int>(timeout.count());
        return j;
    }
};

/**
 * @struct ExecutionPlan
 * Generated plan for task execution
 */
struct ExecutionPlan {
    std::string planId;
    std::vector<std::string> steps;
    std::vector<std::string> filesToModify;
    std::vector<std::string> expectedOutcomes;
    int estimatedDurationMs = 0;
    bool requiresRepair = false;
    
    val012::json toJson() const {
        val012::json j;
        j["plan_id"] = planId;
        j["steps"] = steps;
        j["files_to_modify"] = filesToModify;
        j["expected_outcomes"] = expectedOutcomes;
        j["estimated_duration_ms"] = estimatedDurationMs;
        j["requires_repair"] = requiresRepair;
        return j;
    }
};

/**
 * @struct ExecutionStep
 * Individual step in execution
 */
struct ExecutionStep {
    std::string stepId;
    std::string description;
    std::function<bool(ExecutionContext&)> action;
    bool canRollback = false;
    std::string rollbackCommand;
    
    val012::json toJson() const {
        val012::json j;
        j["step_id"] = stepId;
        j["description"] = description;
        j["can_rollback"] = canRollback;
        j["rollback_command"] = rollbackCommand;
        return j;
    }
};

/**
 * @struct ExecutionContext
 * Mutable context during execution
 */
struct ExecutionContext {
    TaskRequest request;
    ExecutionPlan plan;
    ExecutionPhase currentPhase = ExecutionPhase::Pending;
    std::vector<std::string> modifiedFiles;
    std::vector<VAL014::ExecutionResult> executionHistory;
    std::vector<VAL016::RepairSession> repairHistory;
    std::string workingDirectory;
    int currentStep = 0;
    bool success = false;
    std::string errorMessage;
    
    val012::json toJson() const {
        val012::json j;
        j["request"] = request.toJson();
        j["plan"] = plan.toJson();
        j["current_phase"] = static_cast<int>(currentPhase);
        j["modified_files"] = modifiedFiles;
        j["current_step"] = currentStep;
        j["success"] = success;
        j["error"] = errorMessage;
        return j;
    }
};

/**
 * @struct EvidenceHash
 * Hash component for evidence integrity
 */
struct EvidenceHash {
    std::string component;   // "request", "source_diff", "binary", "test_result"
    std::string algorithm;   // "SHA256"
    std::string hash;
    std::string timestamp;
    
    val012::json toJson() const {
        val012::json j;
        j["component"] = component;
        j["algorithm"] = algorithm;
        j["hash"] = hash;
        j["timestamp"] = timestamp;
        return j;
    }
};

/**
 * @struct EvidenceChain
 * Immutable execution record with hash chain
 */
struct EvidenceChain {
    std::string chainId;
    std::vector<EvidenceHash> hashes;
    std::string combinedHash;  // Hash of all component hashes
    
    val012::json toJson() const {
        val012::json j;
        j["chain_id"] = chainId;
        val012::json hashesArray = val012::json::array();
        for (const auto& h : hashes) {
            hashesArray.push_back(h.toJson());
        }
        j["hashes"] = hashesArray;
        j["combined_hash"] = combinedHash;
        return j;
    }
};

/**
 * @struct AutonomousResult
 * Complete result of autonomous execution
 */
struct AutonomousResult {
    std::string taskId;
    bool success = false;
    ExecutionPhase finalPhase;
    std::chrono::milliseconds duration{0};
    std::vector<std::string> modifiedFiles;
    EvidenceChain evidence;
    std::string errorMessage;
    
    // VAL-016 integration
    bool repairInvoked = false;
    int repairAttempts = 0;
    bool repairSuccessful = false;
    
    val012::json toJson() const {
        val012::json j;
        j["task_id"] = taskId;
        j["success"] = success;
        j["final_phase"] = static_cast<int>(finalPhase);
        j["duration_ms"] = static_cast<int>(duration.count());
        j["modified_files"] = modifiedFiles;
        j["evidence"] = evidence.toJson();
        j["error"] = errorMessage;
        j["repair_invoked"] = repairInvoked;
        j["repair_attempts"] = repairAttempts;
        j["repair_successful"] = repairSuccessful;
        return j;
    }
};

/**
 * @class AutonomousExecutor
 * Main executor for autonomous tasks
 */
class AutonomousExecutor {
public:
    AutonomousExecutor();
    ~AutonomousExecutor();
    
    // Core execution
    AutonomousResult execute(const TaskRequest& request);
    std::future<AutonomousResult> executeAsync(const TaskRequest& request);
    
    // Planning
    ExecutionPlan generatePlan(const TaskRequest& request);
    
    // Phase execution
    bool executePlanningPhase(ExecutionContext& ctx);
    bool executeDispatchPhase(ExecutionContext& ctx);
    bool executeModificationPhase(ExecutionContext& ctx);
    bool executeBuildPhase(ExecutionContext& ctx);
    bool executeTestPhase(ExecutionContext& ctx);
    bool executeRepairPhase(ExecutionContext& ctx);  // VAL-016 integration
    bool executeVerificationPhase(ExecutionContext& ctx);
    bool executeArchivalPhase(ExecutionContext& ctx);
    
    // Evidence integrity
    EvidenceChain generateEvidenceChain(const ExecutionContext& ctx);
    bool verifyEvidenceChain(const EvidenceChain& chain);
    
    // Long-run stability
    bool validateStability(const std::vector<AutonomousResult>& history);
    
    // Configuration
    void setWorkingDirectory(const std::string& path);
    void setRepairEnabled(bool enabled);
    void setEvidencePath(const std::string& path);
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @class StabilityValidator
 * Validates long-run stability of autonomous execution
 */
class StabilityValidator {
public:
    struct StabilityMetrics {
        int totalTasks = 0;
        int successfulTasks = 0;
        int failedTasks = 0;
        int repairInvocations = 0;
        int repairSuccesses = 0;
        double averageDurationMs = 0.0;
        double successRate = 0.0;
        double repairSuccessRate = 0.0;
        
        val012::json toJson() const {
            val012::json j;
            j["total_tasks"] = totalTasks;
            j["successful_tasks"] = successfulTasks;
            j["failed_tasks"] = failedTasks;
            j["repair_invocations"] = repairInvocations;
            j["repair_successes"] = repairSuccesses;
            j["average_duration_ms"] = averageDurationMs;
            j["success_rate"] = successRate;
            j["repair_success_rate"] = repairSuccessRate;
            return j;
        }
    };
    
    StabilityMetrics calculateMetrics(const std::vector<AutonomousResult>& results);
    bool isStable(const StabilityMetrics& metrics, double minSuccessRate = 0.95);
    std::vector<std::string> identifyFailurePatterns(const std::vector<AutonomousResult>& results);
};

} // namespace VAL019
} // namespace RawrXD

#endif // VAL019_AUTONOMOUS_EXECUTION_H
