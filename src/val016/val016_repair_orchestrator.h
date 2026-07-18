/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

/**
 * VAL-016 Repair Orchestrator
 * 
 * Autonomous repair loop that consumes structured ExecutionResult
 * and generates targeted repairs based on failure categorization.
 */

#include "val014_execution_result.h"
#include "val012_build_executor_v2.h"
#include "val012_test_executor_v2.h"
#include "val016_repair_policy.h"
#include <memory>
#include <string>

namespace RawrXD {
namespace VAL016 {

/**
 * @struct RepairSession
 * Complete repair session with all attempts and details
 */
struct RepairSession {
    std::string sessionId;
    VAL014::ExecutionResult originalFailure;
    Diagnosis diagnosis;
    RepairPlan plan;
    std::vector<VAL014::RepairAttempt> attempts;
    bool success = false;
    std::string errorMessage;
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point completedAt;
};

/**
 * @class VAL016RepairOrchestrator
 * Orchestrates autonomous repair based on structured failures
 */
class VAL016RepairOrchestrator {
public:
    VAL016RepairOrchestrator();
    ~VAL016RepairOrchestrator();
    
    /**
     * Set maximum repair attempts
     */
    void setMaxAttempts(int maxAttempts);
    
    /**
     * Set evidence directory
     */
    void setEvidenceDirectory(const std::string& path);
    
    /**
     * Attempt to repair a failed execution
     * 
     * @param failedResult The failed execution result
     * @param maxAttempts Maximum repair attempts
     * @return RepairSession with all attempts
     */
    RepairSession repair(
        const VAL014::ExecutionResult& failedResult,
        int maxAttempts = 3);
    
    /**
     * Generate repair plan for a specific failure
     */
    RepairPlan generatePlan(
        const VAL014::ExecutionResult& failedResult);
    
    /**
     * Execute a repair plan
     */
    bool executePlan(
        const RepairPlan& plan,
        VAL014::RepairAttempt& attempt);
    
    /**
     * Verify repair by re-running execution
     */
    VAL014::ExecutionResult verifyRepair(
        const std::string& buildDir,
        const std::string& testExecutable);
    
    /**
     * Get last repair session
     */
    const RepairSession& getLastSession() const { return lastSession_; }
    
    /**
     * Save repair evidence
     */
    void saveEvidence(const std::string& evidenceDir);

private:
    RepairSession lastSession_;
    std::unique_ptr<RepairPolicyRegistry> registry_;
    int maxAttempts_;
    int currentAttempt_;
    RepairState state_;
    RepairLifecycle lifecycle_;
    std::string evidenceDir_;
    
    // Execution helpers
    std::string generateSessionId();
    
    // Plan execution
    bool applyCreateBuildDirectory(const RepairPlan& plan, VAL014::RepairAttempt& attempt);
    bool applyConfigureCMake(const RepairPlan& plan, VAL014::RepairAttempt& attempt);
    bool applyFixCompileError(const RepairPlan& plan, VAL014::RepairAttempt& attempt);
    bool applyFixLinkError(const RepairPlan& plan, VAL014::RepairAttempt& attempt);
    bool applyFixTestFailure(const RepairPlan& plan, VAL014::RepairAttempt& attempt);
};

} // namespace VAL016
} // namespace RawrXD
