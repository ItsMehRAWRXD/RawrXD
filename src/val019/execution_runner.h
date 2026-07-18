/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * VAL-019 Execution Runner
 * 
 * Real build/test execution bridge that invokes CMake/Ninja
 * and captures structured evidence for VAL-016 diagnosis.
 */

#ifndef VAL019_EXECUTION_RUNNER_H
#define VAL019_EXECUTION_RUNNER_H

#include "val014_execution_result.h"
#include <string>
#include <vector>
#include <chrono>
#include <functional>
#include <optional>

namespace RawrXD {
namespace VAL019 {

/**
 * @enum ExecutionType
 * Type of execution to perform
 */
enum class ExecutionType {
    Build,      // cmake --build
    Test,       // ctest or test executable
    Configure,  // cmake configuration
    Custom      // Custom command
};

/**
 * @struct ExecutionConfig
 * Configuration for execution
 */
struct ExecutionConfig {
    ExecutionType type = ExecutionType::Build;
    std::string workingDirectory;
    std::string buildDirectory = "build";
    std::string target;              // Specific target (optional)
    std::vector<std::string> extraArgs;
    std::chrono::milliseconds timeout{300000};  // 5 minutes default
    bool captureOutput = true;
    bool hashOutput = true;
    
    val012::json toJson() const {
        val012::json j;
        j["type"] = static_cast<int>(type);
        j["working_directory"] = workingDirectory;
        j["build_directory"] = buildDirectory;
        j["target"] = target;
        j["extra_args"] = extraArgs;
        j["timeout_ms"] = static_cast<int>(timeout.count());
        j["capture_output"] = captureOutput;
        j["hash_output"] = hashOutput;
        return j;
    }
};

/**
 * @struct ExecutionOutput
 * Captured output from execution
 */
struct ExecutionOutput {
    std::string stdoutLog;
    std::string stderrLog;
    std::string stdoutHash;
    std::string stderrHash;
    int exitCode = -1;
    bool timedOut = false;
    std::chrono::milliseconds duration{0};
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point completedAt;
    
    val012::json toJson() const {
        val012::json j;
        j["stdout_log"] = stdoutLog;
        j["stderr_log"] = stderrLog;
        j["stdout_hash"] = stdoutHash;
        j["stderr_hash"] = stderrHash;
        j["exit_code"] = exitCode;
        j["timed_out"] = timedOut;
        j["duration_ms"] = static_cast<int>(duration.count());
        return j;
    }
};

/**
 * @struct BuildExecutorResult
 * Result from build execution with VAL-016 compatible structure
 */
struct BuildExecutorResult {
    bool success = false;
    ExecutionOutput output;
    VAL012::BuildFailureReason failureReason = VAL012::BuildFailureReason::None;
    std::string failureDetails;
    std::vector<std::string> affectedFiles;
    
    // Convert to VAL014 ExecutionResult for VAL-016 integration
    VAL014::ExecutionResult toExecutionResult(const ExecutionConfig& config) const;
    
    val012::json toJson() const {
        val012::json j;
        j["success"] = success;
        j["output"] = output.toJson();
        j["failure_reason"] = static_cast<int>(failureReason);
        j["failure_details"] = failureDetails;
        j["affected_files"] = affectedFiles;
        return j;
    }
};

/**
 * @struct TestExecutorResult
 * Result from test execution
 */
struct TestExecutorResult {
    bool success = false;
    ExecutionOutput output;
    VAL012::TestFailureReason failureReason = VAL012::TestFailureReason::None;
    std::string failureDetails;
    int totalTests = 0;
    int passedTests = 0;
    int failedTests = 0;
    
    VAL014::ExecutionResult toExecutionResult(const ExecutionConfig& config) const;
    
    val012::json toJson() const {
        val012::json j;
        j["success"] = success;
        j["output"] = output.toJson();
        j["failure_reason"] = static_cast<int>(failureReason);
        j["failure_details"] = failureDetails;
        j["total_tests"] = totalTests;
        j["passed_tests"] = passedTests;
        j["failed_tests"] = failedTests;
        return j;
    }
};

/**
 * @class ExecutionRunner
 * Executes real build/test commands and captures evidence
 */
class ExecutionRunner {
public:
    ExecutionRunner();
    ~ExecutionRunner();
    
    // Core execution methods
    BuildExecutorResult executeBuild(const ExecutionConfig& config);
    TestExecutorResult executeTests(const ExecutionConfig& config);
    ExecutionOutput executeConfigure(const ExecutionConfig& config);
    ExecutionOutput executeCustom(const std::string& command, const ExecutionConfig& config);
    
    // Evidence generation
    std::string generateEvidenceArtifact(const std::string& evidenceDir, 
                                          const std::string& name,
                                          const val012::json& data);
    
    // Configuration
    void setCMakePath(const std::string& path);
    void setNinjaPath(const std::string& path);
    void setCTestPath(const std::string& path);
    void setDefaultTimeout(std::chrono::milliseconds timeout);
    
    // Utilities
    static std::string calculateHash(const std::string& input);
    static std::string classifyBuildFailure(const std::string& stderrLog);
    static std::string classifyTestFailure(const std::string& stderrLog);
    static std::vector<std::string> extractErrorFiles(const std::string& stderrLog);
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @class RealBuildExecutor
 * High-level interface for VAL-019 integration
 */
class RealBuildExecutor {
public:
    RealBuildExecutor();
    ~RealBuildExecutor();
    
    // Execute build and return VAL-016 compatible result
    VAL014::ExecutionResult build(const std::string& sourceDir,
                                   const std::string& buildDir,
                                   const std::string& target = "");
    
    // Execute tests and return VAL-016 compatible result
    VAL014::ExecutionResult test(const std::string& buildDir,
                                  const std::string& testName = "");
    
    // Full pipeline: build + test with repair loop
    struct PipelineResult {
        bool buildSuccess = false;
        bool testSuccess = false;
        bool repairInvoked = false;
        int repairAttempts = 0;
        std::vector<VAL014::ExecutionResult> executionHistory;
        std::string evidenceDir;
        
        val012::json toJson() const {
            val012::json j;
            j["build_success"] = buildSuccess;
            j["test_success"] = testSuccess;
            j["repair_invoked"] = repairInvoked;
            j["repair_attempts"] = repairAttempts;
            j["evidence_dir"] = evidenceDir;
            return j;
        }
    };
    
    PipelineResult executePipeline(const std::string& sourceDir,
                                    const std::string& buildDir,
                                    bool enableRepair = true);
    
private:
    ExecutionRunner runner_;
};

} // namespace VAL019
} // namespace RawrXD

#endif // VAL019_EXECUTION_RUNNER_H
