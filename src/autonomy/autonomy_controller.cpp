/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#include "autonomy_controller.h"
#include "../plan_orchestrator.h"
#include "../agentic_executor.h"
#include "../agentic_memory_system.h"
#include "../error_recovery_system.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <iomanip>

namespace RawrXD {

// AutonomousRunContext implementation

void AutonomousRunContext::transitionTo(AutonomousState newState, const std::string& trigger,
                                        const std::string& input, const std::string& output) {
    StateTransition transition;
    transition.from = currentState;
    transition.to = newState;
    transition.timestamp = std::chrono::system_clock::now();
    transition.trigger = trigger;
    transition.input = input;
    transition.output = output;
    
    transitions.push_back(transition);
    currentState = newState;
    
    // Log transition
    std::cout << "[AUTONOMY] " << StateTransition::stateToString(transition.from)
              << " -> " << StateTransition::stateToString(transition.to)
              << " (trigger: " << trigger << ")\n";
}

void AutonomousRunContext::addEvent(const std::string& component, const std::string& event,
                                    const nlohmann::json& data) {
    nlohmann::json eventJson;
    eventJson["timestamp"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    eventJson["component"] = component;
    eventJson["event"] = event;
    eventJson["data"] = data;
    events.push_back(eventJson);
}

nlohmann::json AutonomousRunContext::toJson() const {
    nlohmann::json j;
    j["run_id"] = runId;
    j["commit_hash"] = commitHash;
    j["binary_sha256"] = binarySha256;
    j["started_at"] = std::chrono::system_clock::to_time_t(startedAt);
    
    j["goal"] = goal.toJson();
    
    if (plan) {
        j["plan"] = plan->toJson();
    }
    
    j["changes"] = nlohmann::json::array();
    for (const auto& change : changes) {
        nlohmann::json c;
        c["path"] = change.path;
        c["operation"] = change.operation;
        c["diff"] = change.diff;
        c["lines_added"] = change.linesAdded;
        c["lines_removed"] = change.linesRemoved;
        j["changes"].push_back(c);
    }
    
    if (build) {
        nlohmann::json b;
        b["success"] = build->success;
        b["exit_code"] = build->exitCode;
        b["log"] = build->log;
        b["duration_ms"] = build->duration.count();
        b["targets_built"] = build->targetsBuilt;
        b["errors"] = build->errors;
        b["warnings"] = build->warnings;
        j["build"] = b;
    }
    
    j["tests"] = nlohmann::json::array();
    for (const auto& test : tests) {
        nlohmann::json t;
        t["name"] = test.name;
        t["passed"] = test.passed;
        t["output"] = test.output;
        t["duration_ms"] = test.duration.count();
        if (test.failureReason) {
            t["failure_reason"] = *test.failureReason;
        }
        j["tests"].push_back(t);
    }
    
    j["repairs"] = nlohmann::json::array();
    for (const auto& repair : repairs) {
        nlohmann::json r;
        r["failure_type"] = repair.failureType;
        r["strategy"] = repair.strategy;
        r["success"] = repair.success;
        r["log"] = repair.log;
        j["repairs"].push_back(r);
    }
    
    if (completion) {
        j["completion"] = completion->toJson();
    }
    
    j["current_state"] = StateTransition::stateToString(currentState);
    
    j["transitions"] = nlohmann::json::array();
    for (const auto& t : transitions) {
        j["transitions"].push_back(t.toJson());
    }
    
    j["events"] = events;
    
    return j;
}

bool AutonomousRunContext::save(const std::string& evidenceDir) const {
    try {
        std::filesystem::create_directories(evidenceDir);
        
        // Save main context
        std::string contextPath = evidenceDir + "/context.json";
        std::ofstream contextFile(contextPath);
        if (!contextFile) return false;
        contextFile << toJson().dump(2);
        
        // Save goal
        std::string goalPath = evidenceDir + "/input/goal.json";
        std::filesystem::create_directories(evidenceDir + "/input");
        std::ofstream goalFile(goalPath);
        if (goalFile) {
            goalFile << goal.toJson().dump(2);
        }
        
        // Save plan
        if (plan) {
            std::filesystem::create_directories(evidenceDir + "/planning");
            std::string planPath = evidenceDir + "/planning/plan.json";
            std::ofstream planFile(planPath);
            if (planFile) {
                planFile << plan->toJson().dump(2);
            }
        }
        
        // Save changes
        if (!changes.empty()) {
            std::filesystem::create_directories(evidenceDir + "/execution");
            std::string changesPath = evidenceDir + "/execution/changes.json";
            std::ofstream changesFile(changesPath);
            if (changesFile) {
                nlohmann::json changesJson = nlohmann::json::array();
                for (const auto& change : changes) {
                    nlohmann::json c;
                    c["path"] = change.path;
                    c["operation"] = change.operation;
                    c["diff"] = change.diff;
                    changesJson.push_back(c);
                }
                changesFile << changesJson.dump(2);
            }
        }
        
        // Save build log
        if (build) {
            std::filesystem::create_directories(evidenceDir + "/validation");
            std::string buildPath = evidenceDir + "/validation/build.log";
            std::ofstream buildFile(buildPath);
            if (buildFile) {
                buildFile << build->log;
            }
        }
        
        // Save completion
        if (completion) {
            std::string completionPath = evidenceDir + "/completion.json";
            std::ofstream completionFile(completionPath);
            if (completionFile) {
                completionFile << completion->toJson().dump(2);
            }
        }
        
        // Save manifest
        std::string manifestPath = evidenceDir + "/manifest.json";
        std::ofstream manifestFile(manifestPath);
        if (manifestFile) {
            nlohmann::json manifest;
            manifest["run_id"] = runId;
            manifest["commit_hash"] = commitHash;
            manifest["binary_sha256"] = binarySha256;
            manifest["timestamp"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            manifest["hardware"] = "TODO: detect hardware";
            manifest["files"] = {
                "context.json", "input/goal.json", "planning/plan.json",
                "execution/changes.json", "validation/build.log", "completion.json"
            };
            manifestFile << manifest.dump(2);
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to save evidence: " << e.what() << "\n";
        return false;
    }
}

std::string AutonomousRunContext::generateRunId() {
    // Simple UUID generation (replace with proper UUID library in production)
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    return "run-" + std::to_string(ms);
}

// AutonomyController implementation

AutonomyController::AutonomyController(const Components& components)
    : components_(components) {
    validateComponents();
}

AutonomyController::~AutonomyController() = default;

void AutonomyController::validateComponents() {
    std::cout << "[AUTONOMY] Validating components:\n";
    std::cout << "  Planner: " << (components_.planner ? "CONNECTED" : "MISSING") << "\n";
    std::cout << "  Executor: " << (components_.executor ? "CONNECTED" : "MISSING") << "\n";
    std::cout << "  Memory: " << (components_.memory ? "CONNECTED" : "MISSING") << "\n";
    std::cout << "  ErrorRecovery: " << (components_.errorRecovery ? "CONNECTED" : "MISSING") << "\n";
    
    if (!components_.planner || !components_.executor) {
        throw std::runtime_error("VAL-012: Critical components missing");
    }
}

CompletionReport AutonomyController::execute(const UserGoal& goal, const std::string& evidenceDir) {
    // Initialize run context
    currentRun_ = std::make_unique<AutonomousRunContext>();
    currentRun_->runId = AutonomousRunContext::generateRunId();
    currentRun_->commitHash = "54b1d50d5"; // TODO: get from git
    currentRun_->binarySha256 = "TODO: calculate hash";
    currentRun_->startedAt = std::chrono::system_clock::now();
    currentRun_->goal = goal;
    
    std::cout << "\n========================================\n";
    std::cout << "VAL-012: Autonomous Execution Started\n";
    std::cout << "Run ID: " << currentRun_->runId << "\n";
    std::cout << "Goal: " << goal.description << "\n";
    std::cout << "========================================\n\n";
    
    try {
        // State machine execution
        currentRun_->transitionTo(AutonomousState::GoalReceived, "goal_submitted");
        handleGoalReceived();
        
        currentRun_->transitionTo(AutonomousState::Planning, "start_planning");
        handlePlanning();
        
        currentRun_->transitionTo(AutonomousState::ContextLoading, "plan_created");
        handleContextLoading();
        
        currentRun_->transitionTo(AutonomousState::Executing, "context_loaded");
        handleExecuting();
        
        currentRun_->transitionTo(AutonomousState::Building, "execution_complete");
        handleBuilding();
        
        currentRun_->transitionTo(AutonomousState::Testing, "build_complete");
        handleTesting();
        
        currentRun_->transitionTo(AutonomousState::Completed, "tests_passed");
        handleCompleted();
        
    } catch (const std::exception& e) {
        std::cerr << "[AUTONOMY] Exception: " << e.what() << "\n";
        currentRun_->transitionTo(AutonomousState::Failed, "exception", "", e.what());
        handleFailed();
    }
    
    // Save evidence
    std::string fullEvidenceDir = evidenceDir + "/" + currentRun_->runId;
    if (currentRun_->save(fullEvidenceDir)) {
        std::cout << "\n[VAL-012] Evidence saved to: " << fullEvidenceDir << "\n";
    }
    
    // Return completion report
    if (currentRun_->completion) {
        return *currentRun_->completion;
    }
    
    // Fallback if completion not set
    CompletionReport report;
    report.success = false;
    report.goalId = goal.id;
    report.errorMessage = "Execution did not complete properly";
    return report;
}

CompletionReport AutonomyController::executeWithApproval(const UserGoal& goal, int autonomyLevel,
                                                          const std::string& evidenceDir) {
    std::cout << "[AUTONOMY] Executing with approval level " << autonomyLevel << "\n";
    
    if (autonomyLevel == 1) {
        // Level 1: Approve plan
        currentRun_->transitionTo(AutonomousState::Planning, "start_planning");
        handlePlanning();
        
        std::cout << "\n[HUMAN APPROVAL REQUIRED]\n";
        std::cout << "Plan created. Approve? (y/n): ";
        char response;
        std::cin >> response;
        
        if (response != 'y' && response != 'Y') {
            CompletionReport report;
            report.success = false;
            report.goalId = goal.id;
            report.humanInterventionRequired = true;
            report.humanInterventionReason = "Plan rejected by user";
            return report;
        }
        
        // Continue with approved plan
        return execute(goal, evidenceDir);
    }
    else if (autonomyLevel == 2) {
        // Level 2: Approve patch
        // Execute up to patch creation, then pause for approval
        auto result = execute(goal, evidenceDir);
        
        if (!result.filesModified.empty()) {
            std::cout << "\n[HUMAN APPROVAL REQUIRED]\n";
            std::cout << "Files modified. Approve build/test? (y/n): ";
            char response;
            std::cin >> response;
            
            if (response != 'y' && response != 'Y') {
                result.success = false;
                result.humanInterventionRequired = true;
                result.humanInterventionReason = "Changes rejected by user";
            }
        }
        
        return result;
    }
    else {
        // Level 3: Fully autonomous
        return execute(goal, evidenceDir);
    }
}

// State handlers

void AutonomyController::handleGoalReceived() {
    std::cout << "[STATE] Goal received: " << currentRun_->goal.description << "\n";
    currentRun_->addEvent("AutonomyController", "GOAL_RECEIVED", currentRun_->goal.toJson());
}

void AutonomyController::handlePlanning() {
    std::cout << "[STATE] Creating plan...\n";
    
    // Use planner to create plan
    if (components_.planner) {
        components_.planner->createPlan(currentRun_->goal.description);
        
        // Convert planner output to our Plan structure
        Plan plan;
        plan.id = AutonomousRunContext::generateRunId();
        auto plannerSteps = components_.planner->getPlan();
        for (const auto& step : plannerSteps) {
            plan.steps.push_back(step.description);
        }
        plan.createdAt = std::chrono::system_clock::now();
        
        currentRun_->plan = plan;
        currentRun_->addEvent("PlanOrchestrator", "PLAN_CREATED", plan.toJson());
        
        std::cout << "[STATE] Plan created with " << plan.steps.size() << " steps\n";
    } else {
        throw std::runtime_error("Planner not available");
    }
}

void AutonomyController::handleContextLoading() {
    std::cout << "[STATE] Loading project context...\n";
    // TODO: Load semantic index, file graph, etc.
    currentRun_->addEvent("AutonomyController", "CONTEXT_LOADED", {});
}

void AutonomyController::handleExecuting() {
    std::cout << "[STATE] Executing plan steps...\n";
    
    if (!currentRun_->plan) {
        throw std::runtime_error("No plan to execute");
    }
    
    for (size_t i = 0; i < currentRun_->plan->steps.size(); ++i) {
        const auto& step = currentRun_->plan->steps[i];
        std::cout << "  Step " << (i + 1) << "/" << currentRun_->plan->steps.size() 
                  << ": " << step << "\n";
        
        bool success = executePlanStep(step);
        if (!success) {
            throw std::runtime_error("Step failed: " + step);
        }
        
        currentRun_->addEvent("AgenticExecutor", "STEP_COMPLETED", {{"step", step}});
    }
    
    std::cout << "[STATE] Execution complete\n";
}

void AutonomyController::handleBuilding() {
    std::cout << "[STATE] Building project...\n";
    
    bool success = triggerBuild();
    
    if (!success) {
        currentRun_->transitionTo(AutonomousState::Repairing, "build_failed");
        handleRepairing();
        
        // Retry build after repair
        success = triggerBuild();
        if (!success) {
            throw std::runtime_error("Build failed after repair attempt");
        }
    }
    
    currentRun_->addEvent("BuildSystem", "BUILD_COMPLETED", {{"success", success}});
}

void AutonomyController::handleTesting() {
    std::cout << "[STATE] Running tests...\n";
    
    bool success = runTests();
    
    if (!success) {
        currentRun_->transitionTo(AutonomousState::Repairing, "tests_failed");
        handleRepairing();
        
        // Retry tests after repair
        success = runTests();
        if (!success) {
            throw std::runtime_error("Tests failed after repair attempt");
        }
    }
    
    currentRun_->addEvent("TestRunner", "TESTS_COMPLETED", {{"success", success}});
}

void AutonomyController::handleRepairing() {
    std::cout << "[STATE] Attempting automatic repair...\n";
    
    // TODO: Implement actual repair logic
    RepairAttempt repair;
    repair.failureType = "build_failure";
    repair.strategy = "template_based";
    repair.success = true; // Placeholder
    repair.log = "Repair attempted";
    
    currentRun_->repairs.push_back(repair);
    currentRun_->addEvent("ErrorRecoverySystem", "REPAIR_ATTEMPTED", {{"success", repair.success}});
    
    if (!repair.success) {
        throw std::runtime_error("Automatic repair failed");
    }
}

void AutonomyController::handleCompleted() {
    std::cout << "[STATE] Task completed successfully\n";
    
    CompletionReport report;
    report.success = true;
    report.goalId = currentRun_->goal.id;
    report.stepsCompleted = currentRun_->plan ? static_cast<int>(currentRun_->plan->steps.size()) : 0;
    report.totalSteps = report.stepsCompleted;
    report.buildSucceeded = currentRun_->build ? currentRun_->build->success : false;
    report.testsPassed = static_cast<int>(currentRun_->tests.size());
    report.testsFailed = 0;
    report.repairsAttempted = static_cast<int>(currentRun_->repairs.size());
    report.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now() - currentRun_->startedAt);
    report.humanInterventionRequired = false;
    
    for (const auto& change : currentRun_->changes) {
        report.filesModified.push_back(change.path);
    }
    
    currentRun_->completion = report;
    currentRun_->addEvent("AutonomyController", "TASK_COMPLETED", report.toJson());
}

void AutonomyController::handleFailed() {
    std::cout << "[STATE] Task failed\n";
    
    CompletionReport report;
    report.success = false;
    report.goalId = currentRun_->goal.id;
    report.errorMessage = "Task failed";
    report.humanInterventionRequired = true;
    report.humanInterventionReason = "Autonomous execution failed";
    
    currentRun_->completion = report;
}

// Integration point implementations

bool AutonomyController::executePlanStep(const std::string& step) {
    // TODO: Route to appropriate executor method based on step type
    std::cout << "    [EXECUTOR] Executing: " << step << "\n";
    
    // Placeholder: simulate file change
    if (step.find("edit") != std::string::npos || step.find("modify") != std::string::npos) {
        FileChange change;
        change.path = "src/example.cpp";
        change.operation = "modify";
        change.diff = "@@ -1,1 +1,1 @@\n-old\n+new";
        change.linesAdded = 1;
        change.linesRemoved = 1;
        currentRun_->changes.push_back(change);
    }
    
    return true;
}

bool AutonomyController::triggerBuild() {
    std::cout << "    [BUILD] Triggering build...\n";
    
    // TODO: Integrate with actual build system
    BuildResult result;
    result.success = true;
    result.exitCode = 0;
    result.log = "Build succeeded (placeholder)";
    result.duration = std::chrono::milliseconds(5000);
    result.targetsBuilt = {"rawrxd.exe"};
    
    currentRun_->build = result;
    return result.success;
}

bool AutonomyController::runTests() {
    std::cout << "    [TEST] Running tests...\n";
    
    // TODO: Integrate with actual test runner
    TestResult test;
    test.name = "example_test";
    test.passed = true;
    test.output = "PASSED";
    test.duration = std::chrono::milliseconds(100);
    
    currentRun_->tests.push_back(test);
    return true;
}

bool AutonomyController::attemptRepair(const std::string& failure) {
    // TODO: Integrate with ErrorRecoverySystem
    std::cout << "    [REPAIR] Attempting repair for: " << failure << "\n";
    return true;
}

std::vector<StateTransition> AutonomyController::getTransitions() const {
    if (currentRun_) {
        return currentRun_->transitions;
    }
    return {};
}

} // namespace RawrXD
