/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

/**
 * VAL-014 Universal Execution Result
 * 
 * Universal execution contract that wraps V2 executor results.
 * This is the substrate for both VAL-014 (real toolchain) and VAL-016 (repair).
 */

#include "val012_result_types.h"
#include <optional>

namespace RawrXD {
namespace VAL014 {

using VAL012::ExecutionMode;
using VAL012::DetailedBuildResult;
using VAL012::DetailedTestResult;
using VAL012::buildFailureReasonToString;
using VAL012::testFailureReasonToString;

/**
 * @struct ExecutionResult
 * Universal execution result - the contract between executors and repair loop
 */
struct ExecutionResult {
    // Identity
    std::string validationId;           // "VAL-014", "VAL-016", etc.
    std::string executionId;              // Unique execution instance
    
    // Mode
    ExecutionMode mode;                  // real vs simulated
    
    // Environment
    bool environmentReady = false;
    std::string environmentDetails;      // Why ready or not ready
    
    // Build
    std::optional<DetailedBuildResult> buildResult;
    
    // Test
    std::optional<DetailedTestResult> testResult;
    
    // Provenance
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point completedAt;
    std::string hostname;
    std::string user;
    
    // Overall status
    bool overallSuccess() const {
        if (!buildResult.has_value() || !testResult.has_value()) {
            return false;
        }
        return buildResult->buildSuccess && testResult->allTestsPassed;
    }
    
    // Get primary failure reason (for repair loop)
    std::string primaryFailureReason() const {
        if (!environmentReady) {
            if (buildResult.has_value()) {
                return buildFailureReasonToString(buildResult->failureReason);
            }
            return "EnvironmentNotReady";
        }
        if (buildResult.has_value() && !buildResult->buildSuccess) {
            return buildFailureReasonToString(buildResult->failureReason);
        }
        if (testResult.has_value() && !testResult->allTestsPassed) {
            return testFailureReasonToString(testResult->failureReason);
        }
        return "None";
    }
    
    val012::json toJson() const {
        val012::json j;
        j["validation_id"] = validationId;
        j["execution_id"] = executionId;
        j["mode"] = mode.toJson();
        j["environment_ready"] = environmentReady;
        j["environment_details"] = environmentDetails;
        
        if (buildResult.has_value()) {
            j["build_result"] = buildResult->toJson();
        }
        
        if (testResult.has_value()) {
            j["test_result"] = testResult->toJson();
        }
        
        j["started_at"] = static_cast<long long>(
            std::chrono::system_clock::to_time_t(startedAt));
        j["completed_at"] = static_cast<long long>(
            std::chrono::system_clock::to_time_t(completedAt));
        j["hostname"] = hostname;
        j["user"] = user;
        j["overall_success"] = overallSuccess();
        j["primary_failure_reason"] = primaryFailureReason();
        
        return j;
    }
};

/**
 * @struct RepairAttempt
 * Contract for VAL-016 autonomous repair
 */
struct RepairAttempt {
    int attemptNumber = 0;
    
    // Original failure
    std::string originalFailureCategory;
    std::string originalFailureDetails;
    
    // Diagnosis
    std::string diagnosis;
    std::vector<std::string> diagnostics;
    
    // Action
    std::string actionTaken;
    std::string patchApplied;           // Diff or description
    std::vector<std::string> filesModified;
    
    // Outcome
    bool retrySuccess = false;
    std::string retryExecutionId;       // Link to retry result
    
    // Metrics
    std::chrono::milliseconds diagnosisDuration{0};
    std::chrono::milliseconds repairDuration{0};
    std::chrono::milliseconds verificationDuration{0};
    std::chrono::milliseconds totalDuration{0};
    
    val012::json toJson() const {
        val012::json j;
        j["attempt_number"] = attemptNumber;
        j["original_failure_category"] = originalFailureCategory;
        j["original_failure_details"] = originalFailureDetails;
        j["diagnosis"] = diagnosis;
        
        val012::json diagnosticsJson = val012::json::array();
        for (const auto& d : diagnostics) {
            diagnosticsJson.push_back(d);
        }
        j["diagnostics"] = diagnosticsJson;
        
        j["action_taken"] = actionTaken;
        j["patch_applied"] = patchApplied;
        
        val012::json filesJson = val012::json::array();
        for (const auto& f : filesModified) {
            filesJson.push_back(f);
        }
        j["files_modified"] = filesJson;
        
        j["retry_success"] = retrySuccess;
        j["retry_execution_id"] = retryExecutionId;
        
        j["diagnosis_duration_ms"] = static_cast<long long>(diagnosisDuration.count());
        j["repair_duration_ms"] = static_cast<long long>(repairDuration.count());
        j["verification_duration_ms"] = static_cast<long long>(verificationDuration.count());
        j["total_duration_ms"] = static_cast<long long>(totalDuration.count());
        
        return j;
    }
};

/**
 * @struct RepairSession
 * Complete repair session with all attempts
 */
struct RepairSession {
    std::string sessionId;
    std::string originalExecutionId;
    std::vector<RepairAttempt> attempts;
    bool resolved = false;
    int finalAttemptNumber = 0;
    
    val012::json toJson() const {
        val012::json j;
        j["session_id"] = sessionId;
        j["original_execution_id"] = originalExecutionId;
        j["resolved"] = resolved;
        j["final_attempt_number"] = finalAttemptNumber;
        
        val012::json attemptsJson = val012::json::array();
        for (const auto& a : attempts) {
            attemptsJson.push_back(a.toJson());
        }
        j["attempts"] = attemptsJson;
        
        return j;
    }
};

} // namespace VAL014
} // namespace RawrXD
