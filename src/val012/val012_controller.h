/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

/**
 * VAL-012: Autonomous Loop Closure - Vertical Slice Implementation
 * 
 * This is a focused, minimal implementation that proves one complete autonomous workflow.
 * It is not a general solution; it is a proof of concept that demonstrates:
 * 
 * 1. Goal → Plan → Change → Build → Test → Report
 * 2. Every transition is logged
 * 3. Evidence is captured at each step
 * 4. The loop closes
 * 
 * Scope: Minimal viable autonomy
 * - Single task type: "Add --version command"
 * - Deterministic expected output
 * - Few unknown dependencies
 * - Easy test assertion
 * 
 * Evidence Levels Target:
 * - [D] Source exists (this file)
 * - [C] Compiles and links
 * - [B] Test executes with mock goal
 * - [A] Real task produces completion.json
 */

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include "json_minimal.hpp"
#include <fstream>
#include <filesystem>

namespace RawrXD {
namespace VAL012 {

/**
 * @enum Val012State
 * Minimal state machine for vertical slice.
 * Each transition produces an event log.
 */
enum class Val012State {
    Idle,
    GoalReceived,
    Planning,
    Executing,
    Building,
    Testing,
    Completed,
    Failed
};

inline std::string stateToString(Val012State s) {
    switch(s) {
        case Val012State::Idle: return "IDLE";
        case Val012State::GoalReceived: return "GOAL_RECEIVED";
        case Val012State::Planning: return "PLANNING";
        case Val012State::Executing: return "EXECUTING";
        case Val012State::Building: return "BUILDING";
        case Val012State::Testing: return "TESTING";
        case Val012State::Completed: return "COMPLETED";
        case Val012State::Failed: return "FAILED";
    }
    return "UNKNOWN";
}

/**
 * @struct Val012Event
 * Every state transition emits an event.
 * This creates a deterministic replay log.
 */
struct Val012Event {
    std::string eventType;
    Val012State state;
    std::chrono::system_clock::time_point timestamp;
    std::string input;
    std::string output;
    val012::json metadata;
    
    val012::json toJson() const {
        val012::json j;
        j["event"] = eventType;
        j["state"] = stateToString(state);
        j["timestamp"] = static_cast<long long>(std::chrono::system_clock::to_time_t(timestamp));
        j["input"] = input;
        j["output"] = output;
        j["metadata"] = metadata;
        return j;
    }
};

/**
 * @struct Val012Goal
 * The input to the system.
 */
struct Val012Goal {
    std::string id;
    std::string description;
    std::chrono::system_clock::time_point receivedAt;
    
    val012::json toJson() const {
        val012::json j;
        j["id"] = id;
        j["description"] = description;
        j["received_at"] = static_cast<long long>(std::chrono::system_clock::to_time_t(receivedAt));
        return j;
    }
};

/**
 * @struct Val012Plan
 * The plan generated from the goal.
 * For VAL-012, this is intentionally simple.
 */
struct Val012Plan {
    std::string goalId;
    std::vector<std::string> steps;
    
    val012::json toJson() const {
        val012::json j;
        j["goal_id"] = goalId;
        j["steps"] = steps;
        return j;
    }
};

/**
 * @struct Val012Change
 * A file modification.
 */
struct Val012Change {
    std::string filePath;
    std::string operation;
    std::string description;
    
    val012::json toJson() const {
        val012::json j;
        j["file"] = filePath;
        j["operation"] = operation;
        j["description"] = description;
        return j;
    }
};

/**
 * @struct Val012BuildResult
 * Build output.
 */
struct Val012BuildResult {
    bool success = false;
    int exitCode = -1;
    std::string log;
    std::chrono::milliseconds duration{0};
    
    val012::json toJson() const {
        val012::json j;
        j["success"] = success;
        j["exit_code"] = exitCode;
        j["log"] = log;
        j["duration_ms"] = static_cast<long long>(duration.count());
        return j;
    }
};

/**
 * @struct Val012TestResult
 * Test execution output.
 */
struct Val012TestResult {
    int totalTests = 0;
    int passedTests = 0;
    int failedTests = 0;
    std::string log;
    
    val012::json toJson() const {
        val012::json j;
        j["total"] = totalTests;
        j["passed"] = passedTests;
        j["failed"] = failedTests;
        j["log"] = log;
        return j;
    }
};

/**
 * @struct Val012Completion
 * Final report.
 */
struct Val012Completion {
    bool success = false;
    std::string goalId;
    std::string summary;
    int stepsCompleted = 0;
    int totalSteps = 0;
    std::vector<std::string> filesModified;
    bool buildSucceeded = false;
    int testsPassed = 0;
    int testsFailed = 0;
    std::chrono::milliseconds totalDuration{0};
    std::string evidencePath;
    
    val012::json toJson() const {
        val012::json j;
        j["success"] = success;
        j["goal_id"] = goalId;
        j["summary"] = summary;
        j["steps_completed"] = stepsCompleted;
        j["total_steps"] = totalSteps;
        j["files_modified"] = filesModified;
        j["build_succeeded"] = buildSucceeded;
        j["tests_passed"] = testsPassed;
        j["tests_failed"] = testsFailed;
        j["total_duration_ms"] = static_cast<long long>(totalDuration.count());
        j["evidence_path"] = evidencePath;
        return j;
    }
};

/**
 * @class Val012Controller
 * Minimal controller for VAL-012 vertical slice.
 * 
 * This is intentionally simple. It proves the concept, not production scale.
 * 
 * Usage:
 *   Val012Controller controller;
 *   auto result = controller.execute("Add --version command");
 *   // result contains completion.json data
 */
class Val012Controller {
public:
    Val012Controller();
    
    /**
     * Execute a goal through the autonomous loop.
     * 
     * @param goalDescription Natural language goal
     * @param evidenceDir Where to store evidence (default: evidence/val-012)
     * @return Completion report
     */
    Val012Completion execute(
        const std::string& goalDescription,
        const std::string& evidenceDir = "evidence/val-012");
    
    /**
     * Get execution events for debugging.
     */
    const std::vector<Val012Event>& getEvents() const { return events_; }

private:
    // State
    Val012State currentState_ = Val012State::Idle;
    std::vector<Val012Event> events_;
    
    // Execution context
    Val012Goal goal_;
    Val012Plan plan_;
    std::vector<Val012Change> changes_;
    Val012BuildResult buildResult_;
    Val012TestResult testResult_;
    Val012Completion completion_;
    
    std::chrono::steady_clock::time_point startTime_;
    
    // State handlers
    void transitionTo(Val012State newState, const std::string& input = "", const std::string& output = "");
    void emitEvent(const std::string& eventType, const val012::json& metadata = {});
    
    bool handleGoalReceived(const std::string& description);
    bool handlePlanning();
    bool handleExecuting();
    bool handleBuilding();
    bool handleTesting();
    
    // Evidence collection
    void saveEvidence(const std::string& dir);
    void saveGoal(const std::string& dir);
    void savePlan(const std::string& dir);
    void saveChanges(const std::string& dir);
    void saveBuildLog(const std::string& dir);
    void saveTestLog(const std::string& dir);
    void saveCompletion(const std::string& dir);
    void saveEvents(const std::string& dir);
    void saveManifest(const std::string& dir);
    
    // Utilities
    std::string generateId();
    std::string getCommitHash();
    std::string getHardwareInfo();
};

} // namespace VAL012
} // namespace RawrXD
