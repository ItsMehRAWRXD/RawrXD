/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

/**
 * VAL-014 Orchestrator
 * 
 * Validates real toolchain execution using V2 executor contract.
 * Produces universal ExecutionResult for consumption by VAL-016.
 */

#include "val014_execution_result.h"
#include "val012_build_executor_v2.h"
#include "val012_test_executor_v2.h"

namespace RawrXD {
namespace VAL014 {

/**
 * @class VAL014Orchestrator
 * Orchestrates real toolchain validation
 */
class VAL014Orchestrator {
public:
    VAL014Orchestrator();
    
    /**
     * Execute complete validation workflow
     * 
     * @param buildDir Directory containing build files
     * @param testExecutable Path to test binary
     * @param config Release/Debug
     * @return Universal ExecutionResult
     */
    ExecutionResult execute(
        const std::string& buildDir,
        const std::string& testExecutable,
        const std::string& config = "Release");
    
    /**
     * Execute build only
     */
    ExecutionResult executeBuild(
        const std::string& buildDir,
        const std::string& target = "",
        const std::string& config = "Release");
    
    /**
     * Execute tests only
     */
    ExecutionResult executeTests(
        const std::string& testExecutable,
        const std::string& testFilter = "");
    
    /**
     * Get last execution result
     */
    const ExecutionResult& getLastResult() const { return lastResult_; }
    
    /**
     * Save evidence to directory
     */
    void saveEvidence(const std::string& evidenceDir);

private:
    ExecutionResult lastResult_;
    
    std::string generateExecutionId();
    std::string getHostname();
    std::string getUsername();
};

/**
 * @struct VAL014ValidationReport
 * Summary report for VAL-014 validation
 */
struct VAL014ValidationReport {
    bool realToolchainValidated = false;
    bool compilerDiscovered = false;
    bool configureStepValidated = false;
    bool buildStepValidated = false;
    bool testInvocationValidated = false;
    bool artifactCollectionValidated = false;
    bool failureClassificationValidated = false;
    
    std::string cmakeVersion;
    std::string ninjaVersion;
    std::string compiler;
    std::string compilerVersion;
    
    int totalExecutions = 0;
    int successfulExecutions = 0;
    int failedExecutions = 0;
    
    val012::json toJson() const {
        val012::json j;
        j["real_toolchain_validated"] = realToolchainValidated;
        j["compiler_discovered"] = compilerDiscovered;
        j["configure_step_validated"] = configureStepValidated;
        j["build_step_validated"] = buildStepValidated;
        j["test_invocation_validated"] = testInvocationValidated;
        j["artifact_collection_validated"] = artifactCollectionValidated;
        j["failure_classification_validated"] = failureClassificationValidated;
        
        val012::json toolchain;
        toolchain["cmake_version"] = cmakeVersion;
        toolchain["ninja_version"] = ninjaVersion;
        toolchain["compiler"] = compiler;
        toolchain["compiler_version"] = compilerVersion;
        j["toolchain"] = toolchain;
        
        j["total_executions"] = totalExecutions;
        j["successful_executions"] = successfulExecutions;
        j["failed_executions"] = failedExecutions;
        
        return j;
    }
};

} // namespace VAL014
} // namespace RawrXD
