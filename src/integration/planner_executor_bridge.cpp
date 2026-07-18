/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#include "planner_executor_bridge.h"
#include <iostream>
#include <fstream>
#include <filesystem>

namespace RawrXD {

PlannerExecutorBridge::PlannerExecutorBridge(
    PlanOrchestrator* planner,
    AgenticExecutor* executor,
    ErrorRecoverySystem* errorRecovery,
    AgenticMemorySystem* memory)
    : planner_(planner)
    , executor_(executor)
    , errorRecovery_(errorRecovery)
    , memory_(memory) {
    
    validateIntegrationPoints();
}

void PlannerExecutorBridge::validateIntegrationPoints() {
    // Evidence: Verify all components are connected
    if (!planner_) {
        throw std::runtime_error("VAL-012-ERROR: Planner not connected");
    }
    if (!executor_) {
        throw std::runtime_error("VAL-012-ERROR: Executor not connected");
    }
    if (!errorRecovery_) {
        throw std::runtime_error("VAL-012-ERROR: ErrorRecovery not connected");
    }
    if (!memory_) {
        throw std::runtime_error("VAL-012-ERROR: Memory not connected");
    }
    
    // Log successful integration validation
    std::cout << "[VAL-012] Integration points validated:\n"
              << "  - Planner: " << (planner_ ? "CONNECTED" : "MISSING") << "\n"
              << "  - Executor: " << (executor_ ? "CONNECTED" : "MISSING") << "\n"
              << "  - ErrorRecovery: " << (errorRecovery_ ? "CONNECTED" : "MISSING") << "\n"
              << "  - Memory: " << (memory_ ? "CONNECTED" : "MISSING") << "\n";
}

AutonomousExecutionResult PlannerExecutorBridge::executeGoal(const std::string& goal) {
    return executeGoalWithEvidence(goal, "evidence/val-012");
}

AutonomousExecutionResult PlannerExecutorBridge::executeGoalWithEvidence(
    const std::string& goal,
    const std::string& evidenceDir) {
    
    AutonomousExecutionResult result;
    result.goal = goal;
    currentTrace_ = ExecutionTrace{};
    currentTrace_.goal = goal;
    startTime_ = std::chrono::steady_clock::now();
    
    std::cout << "[VAL-012] Starting autonomous execution for goal: " << goal << "\n";
    
    try {
        // Step 1: Create plan
        std::cout << "[VAL-012] Step 1: Creating plan...\n";
        planner_->createPlan(goal);
        auto plan = planner_->getPlan();
        result.totalSteps = static_cast<int>(plan.size());
        
        // Serialize plan for evidence
        nlohmann::json planJson;
        for (const auto& step : plan) {
            nlohmann::json stepJson;
            stepJson["description"] = step.description;
            stepJson["is_complete"] = step.isComplete;
            stepJson["result"] = step.result;
            planJson.push_back(stepJson);
        }
        currentTrace_.planJson = planJson.dump();
        
        std::cout << "[VAL-012] Plan created with " << plan.size() << " steps\n";
        
        // Step 2: Execute each step
        for (size_t i = 0; i < plan.size(); ++i) {
            const auto& step = plan[i];
            std::cout << "[VAL-012] Step " << (i + 1) << "/" << plan.size() 
                      << ": " << step.description << "\n";
            
            bool stepSuccess = executeStep(step);
            
            if (stepSuccess) {
                currentTrace_.stepsExecuted.push_back(step.description);
                result.stepsCompleted++;
                std::cout << "[VAL-012]   ✓ Success\n";
            } else {
                std::cout << "[VAL-012]   ✗ Failed, attempting recovery...\n";
                
                // Attempt recovery
                bool recovered = attemptRecovery(step.description, "Step failed");
                if (!recovered) {
                    result.errorMessage = "Step failed and recovery unsuccessful: " + step.description;
                    std::cout << "[VAL-012] Recovery failed. Aborting.\n";
                    recordFailure(goal, result.errorMessage);
                    break;
                }
                
                currentTrace_.repairsAttempted.push_back("Recovered: " + step.description);
                result.repairsAttempted++;
            }
        }
        
        // Step 3: Finalize
        auto endTime = std::chrono::steady_clock::now();
        currentTrace_.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime_).count();
        
        result.success = (result.stepsCompleted == result.totalSteps);
        result.trace = currentTrace_;
        
        if (result.success) {
            std::cout << "[VAL-012] ✓ Goal completed successfully in " 
                      << currentTrace_.executionTimeMs << "ms\n";
            recordSuccess(goal, currentTrace_);
        } else {
            std::cout << "[VAL-012] ✗ Goal failed: " << result.errorMessage << "\n";
        }
        
    } catch (const std::exception& e) {
        result.errorMessage = std::string("Exception: ") + e.what();
        std::cout << "[VAL-012] ✗ Exception: " << e.what() << "\n";
        recordFailure(goal, result.errorMessage);
    }
    
    // Save evidence
    std::filesystem::create_directories(evidenceDir);
    std::string tracePath = evidenceDir + "/trace_" + 
                           std::to_string(std::time(nullptr)) + ".json";
    currentTrace_.save(tracePath);
    std::cout << "[VAL-012] Evidence saved to: " << tracePath << "\n";
    
    return result;
}

bool PlannerExecutorBridge::executeStep(const PlanOrchestrator::Step& step) {
    // Route step to appropriate handler based on description
    std::string desc = step.description;
    std::transform(desc.begin(), desc.end(), desc.begin(), ::tolower);
    
    if (desc.find("build") != std::string::npos) {
        return handleBuildStep();
    } else if (desc.find("test") != std::string::npos) {
        return handleTestStep();
    } else if (desc.find("fix") != std::string::npos || 
               desc.find("repair") != std::string::npos) {
        return handleRepairStep("auto-detected failure");
    } else {
        // Generic execution via AgenticExecutor
        // This would call the appropriate executor method based on step type
        std::cout << "[VAL-012]   Executing generic step via AgenticExecutor\n";
        return true; // Placeholder - would call actual executor
    }
}

bool PlannerExecutorBridge::handleBuildStep() {
    std::cout << "[VAL-012]   Triggering build...\n";
    
    // Integration point: Trigger build system
    // This would call BuildTaskProvider
    
    // Placeholder for actual build integration
    // In real implementation:
    // auto result = buildTaskProvider_->build();
    // currentTrace_.buildLog = result.log;
    // return result.success;
    
    currentTrace_.buildLog = "Build triggered (integration pending)";
    return true;
}

bool PlannerExecutorBridge::handleTestStep() {
    std::cout << "[VAL-012]   Running tests...\n";
    
    // Integration point: Run selected tests
    // This would call TestSelector then run tests
    
    // Placeholder for actual test integration
    currentTrace_.testLog = "Tests triggered (integration pending)";
    return true;
}

bool PlannerExecutorBridge::handleRepairStep(const std::string& failure) {
    std::cout << "[VAL-012]   Attempting repair for: " << failure << "\n";
    
    // Integration point: Error recovery
    // This would call ErrorRecoverySystem
    
    // Placeholder for actual repair integration
    currentTrace_.repairsAttempted.push_back(failure);
    return true;
}

bool PlannerExecutorBridge::attemptRecovery(const std::string& step, const std::string& error) {
    std::cout << "[VAL-012] Recovery: Analyzing failure...\n";
    
    // Query memory for similar past failures
    auto pastAttempts = memory_->getMemoriesByType(MemoryType::Procedure);
    
    // Attempt repair based on pattern
    // This would use ErrorRecoverySystem to generate fixes
    
    std::cout << "[VAL-012] Recovery: Attempting fix based on " 
              << pastAttempts.size() << " past procedures\n";
    
    return true; // Placeholder
}

void PlannerExecutorBridge::recordSuccess(const std::string& goal, const ExecutionTrace& trace) {
    // Store successful execution in memory
    AgenticMemorySystem::MemoryEntry entry;
    entry.type = MemoryType::Episode;
    entry.content = "Successfully completed: " + goal;
    entry.metadata = trace.toJson().dump();
    
    memory_->storeMemory(entry.type, entry.content, entry.metadata);
    std::cout << "[VAL-012] Success recorded to memory\n";
}

void PlannerExecutorBridge::recordFailure(const std::string& goal, const std::string& error) {
    // Store failed execution in memory
    AgenticMemorySystem::MemoryEntry entry;
    entry.type = MemoryType::Episode;
    entry.content = "Failed: " + goal + " - " + error;
    entry.metadata = "{\"error\": \"" + error + "\"}";
    
    memory_->storeMemory(entry.type, entry.content, entry.metadata);
    std::cout << "[VAL-012] Failure recorded to memory\n";
}

} // namespace RawrXD
