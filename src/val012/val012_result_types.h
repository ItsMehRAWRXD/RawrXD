/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

/**
 * VAL-012 Result Types
 * 
 * Structured execution results with explicit failure categorization.
 * These objects become evidence directly.
 */

#include <string>
#include <vector>
#include <chrono>
#include <optional>
#include "json_minimal.hpp"

namespace RawrXD {
namespace VAL012 {

/**
 * @enum BuildFailureReason
 * Explicit categorization of why a build failed
 */
enum class BuildFailureReason {
    None,                   // Build succeeded
    ToolMissing,            // cmake/ninja not found
    BuildDirectoryMissing,  // No CMakeCache.txt or build.ninja
    ConfigureFailed,        // cmake configuration failed
    CompileFailed,          // Compilation errors
    LinkFailed,             // Linking errors
    Timeout,                // Build exceeded time limit
    Unknown                 // Unclassified failure
};

inline std::string buildFailureReasonToString(BuildFailureReason r) {
    switch(r) {
        case BuildFailureReason::None: return "None";
        case BuildFailureReason::ToolMissing: return "ToolMissing";
        case BuildFailureReason::BuildDirectoryMissing: return "BuildDirectoryMissing";
        case BuildFailureReason::ConfigureFailed: return "ConfigureFailed";
        case BuildFailureReason::CompileFailed: return "CompileFailed";
        case BuildFailureReason::LinkFailed: return "LinkFailed";
        case BuildFailureReason::Timeout: return "Timeout";
        case BuildFailureReason::Unknown: return "Unknown";
    }
    return "Unknown";
}

/**
 * @enum TestFailureReason
 * Explicit categorization of why tests failed
 */
enum class TestFailureReason {
    None,                   // All tests passed
    ExecutableMissing,      // Test binary not found
    NoTestsFound,           // No tests in executable
    TestsFailed,            // Some tests failed
    Timeout,                // Test execution timed out
    Crash,                  // Test executable crashed
    Unknown                 // Unclassified failure
};

inline std::string testFailureReasonToString(TestFailureReason r) {
    switch(r) {
        case TestFailureReason::None: return "None";
        case TestFailureReason::ExecutableMissing: return "ExecutableMissing";
        case TestFailureReason::NoTestsFound: return "NoTestsFound";
        case TestFailureReason::TestsFailed: return "TestsFailed";
        case TestFailureReason::Timeout: return "Timeout";
        case TestFailureReason::Crash: return "Crash";
        case TestFailureReason::Unknown: return "Unknown";
    }
    return "Unknown";
}

/**
 * @struct ExecutionMode
 * Tracks whether execution was real or simulated
 */
struct ExecutionMode {
    std::string mode = "simulated";  // "real" or "simulated"
    std::string reason;               // Why this mode was chosen
    
    val012::json toJson() const {
        val012::json j;
        j["mode"] = mode;
        j["reason"] = reason;
        return j;
    }
};

/**
 * @struct BuildArtifact
 * Represents a file produced by the build
 */
struct BuildArtifact {
    std::string path;
    std::string type;           // "executable", "library", "object", "other"
    size_t sizeBytes = 0;
    std::string sha256;         // Hash of the file
    
    val012::json toJson() const {
        val012::json j;
        j["path"] = path;
        j["type"] = type;
        j["size_bytes"] = static_cast<long long>(sizeBytes);
        j["sha256"] = sha256;
        return j;
    }
};

/**
 * @struct ToolchainInfo
 * Information about the build toolchain
 */
struct ToolchainInfo {
    std::string tool;               // "cmake+ninja", "cmake+make", "msbuild"
    std::string cmakeVersion;
    std::string ninjaVersion;
    std::string compiler;
    std::string compilerVersion;
    std::string targetArchitecture;
    std::string buildType;          // Release, Debug, etc.
    
    val012::json toJson() const {
        val012::json j;
        j["tool"] = tool;
        j["cmake_version"] = cmakeVersion;
        j["ninja_version"] = ninjaVersion;
        j["compiler"] = compiler;
        j["compiler_version"] = compilerVersion;
        j["target_architecture"] = targetArchitecture;
        j["build_type"] = buildType;
        return j;
    }
};

/**
 * @struct DetailedBuildResult
 * Complete build execution result - becomes evidence directly
 */
struct DetailedBuildResult {
    // Execution tracking
    ExecutionMode executionMode;
    bool executorSuccess = false;     // Did the executor run without crashing?
    bool environmentReady = false;    // Was the build environment valid?
    bool buildSuccess = false;          // Did the build succeed?
    
    // Failure categorization
    BuildFailureReason failureReason = BuildFailureReason::None;
    std::string failureDetails;         // Human-readable details
    
    // Build metrics
    int exitCode = -1;
    std::chrono::milliseconds duration{0};
    std::string workingDirectory;
    
    // Outputs
    std::string stdoutLog;
    std::string stderrLog;
    std::vector<BuildArtifact> artifacts;
    
    // Toolchain
    ToolchainInfo toolchain;
    
    // Provenance
    std::optional<std::string> gitCommit;
    std::chrono::system_clock::time_point executedAt;
    
    val012::json toJson() const {
        val012::json j;
        
        // Execution status
        j["execution"] = executionMode.toJson();
        j["executor_success"] = executorSuccess;
        j["environment_ready"] = environmentReady;
        j["build_success"] = buildSuccess;
        
        // Failure categorization
        j["failure_reason"] = buildFailureReasonToString(failureReason);
        j["failure_details"] = failureDetails;
        
        // Metrics
        j["exit_code"] = exitCode;
        j["duration_ms"] = static_cast<long long>(duration.count());
        j["working_directory"] = workingDirectory;
        
        // Outputs
        j["stdout"] = stdoutLog;
        j["stderr"] = stderrLog;
        
        // Artifacts
        val012::json artifactsJson = val012::json::array();
        for (const auto& art : artifacts) {
            artifactsJson.push_back(art.toJson());
        }
        j["artifacts"] = artifactsJson;
        
        // Toolchain
        j["toolchain"] = toolchain.toJson();
        
        // Provenance
        if (gitCommit.has_value()) {
            j["git_commit"] = *gitCommit;
        }
        j["executed_at"] = static_cast<long long>(
            std::chrono::system_clock::to_time_t(executedAt));
        
        return j;
    }
};

/**
 * @struct TestCaseResult
 * Individual test case result
 */
struct TestCaseResult {
    std::string name;
    bool passed = false;
    std::chrono::milliseconds duration{0};
    std::string errorMessage;
    std::string output;
    
    val012::json toJson() const {
        val012::json j;
        j["name"] = name;
        j["passed"] = passed;
        j["duration_ms"] = static_cast<long long>(duration.count());
        j["error"] = errorMessage;
        j["output"] = output;
        return j;
    }
};

/**
 * @struct TestFrameworkInfo
 * Information about the test framework
 */
struct TestFrameworkInfo {
    std::string framework;          // "gtest", "catch2", "custom"
    std::string frameworkVersion;
    std::string executable;
    
    val012::json toJson() const {
        val012::json j;
        j["framework"] = framework;
        j["framework_version"] = frameworkVersion;
        j["executable"] = executable;
        return j;
    }
};

/**
 * @struct DetailedTestResult
 * Complete test execution result - becomes evidence directly
 */
struct DetailedTestResult {
    // Execution tracking
    ExecutionMode executionMode;
    bool executorSuccess = false;     // Did the executor run without crashing?
    bool environmentReady = false;    // Was the test environment valid?
    bool allTestsPassed = false;      // Did all tests pass?
    
    // Failure categorization
    TestFailureReason failureReason = TestFailureReason::None;
    std::string failureDetails;
    
    // Test metrics
    int totalTests = 0;
    int passedTests = 0;
    int failedTests = 0;
    int skippedTests = 0;
    int exitCode = -1;
    std::chrono::milliseconds duration{0};
    
    // Outputs
    std::string stdoutLog;
    std::string stderrLog;
    std::vector<TestCaseResult> testCases;
    
    // Framework
    TestFrameworkInfo framework;
    
    // Timeout tracking
    bool timedOut = false;
    int timeoutMs = 300000;  // 5 minutes default
    
    // Provenance
    std::chrono::system_clock::time_point executedAt;
    
    val012::json toJson() const {
        val012::json j;
        
        // Execution status
        j["execution"] = executionMode.toJson();
        j["executor_success"] = executorSuccess;
        j["environment_ready"] = environmentReady;
        j["all_tests_passed"] = allTestsPassed;
        
        // Failure categorization
        j["failure_reason"] = testFailureReasonToString(failureReason);
        j["failure_details"] = failureDetails;
        
        // Metrics
        j["total"] = totalTests;
        j["passed"] = passedTests;
        j["failed"] = failedTests;
        j["skipped"] = skippedTests;
        j["exit_code"] = exitCode;
        j["duration_ms"] = static_cast<long long>(duration.count());
        
        // Timeout
        j["timed_out"] = timedOut;
        j["timeout_ms"] = timeoutMs;
        
        // Outputs
        j["stdout"] = stdoutLog;
        j["stderr"] = stderrLog;
        
        // Test cases
        val012::json casesJson = val012::json::array();
        for (const auto& tc : testCases) {
            casesJson.push_back(tc.toJson());
        }
        j["test_cases"] = casesJson;
        
        // Framework
        j["framework"] = framework.toJson();
        
        // Provenance
        j["executed_at"] = static_cast<long long>(
            std::chrono::system_clock::to_time_t(executedAt));
        
        return j;
    }
};

} // namespace VAL012
} // namespace RawrXD
