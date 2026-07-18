/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

/**
 * VAL-012 Test Executor
 * 
 * Executes real test binaries and captures:
 * - Pass/fail status
 * - Runtime
 * - Failed assertions
 * - Logs
 * - Generated evidence
 */

#include <string>
#include <vector>
#include <chrono>
#include "json_minimal.hpp"

namespace RawrXD {
namespace VAL012 {

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
 * @struct TestProvenance
 * Test framework and environment information
 */
struct TestProvenance {
    std::string mode = "real";           // "real" or "simulated"
    std::string framework;               // "gtest", "catch2", "custom", etc.
    std::string frameworkVersion;
    std::string testExecutable;
    std::chrono::system_clock::time_point executedAt;
    
    val012::json toJson() const {
        val012::json j;
        j["mode"] = mode;
        j["framework"] = framework;
        j["framework_version"] = frameworkVersion;
        j["test_executable"] = testExecutable;
        j["executed_at"] = static_cast<long long>(
            std::chrono::system_clock::to_time_t(executedAt));
        return j;
    }
};

/**
 * @struct RealTestResult
 * Complete test execution result with provenance
 */
struct RealTestResult {
    bool success = false;
    int totalTests = 0;
    int passedTests = 0;
    int failedTests = 0;
    int skippedTests = 0;
    std::chrono::milliseconds duration{0};
    std::string stdoutLog;
    std::string stderrLog;
    std::vector<TestCaseResult> testCases;
    TestProvenance provenance;
    
    val012::json toJson() const {
        val012::json j;
        j["success"] = success;
        j["total"] = totalTests;
        j["passed"] = passedTests;
        j["failed"] = failedTests;
        j["skipped"] = skippedTests;
        j["duration_ms"] = static_cast<long long>(duration.count());
        j["stdout"] = stdoutLog;
        j["stderr"] = stderrLog;
        
        val012::json casesJson = val012::json::array();
        for (const auto& tc : testCases) {
            casesJson.push_back(tc.toJson());
        }
        j["test_cases"] = casesJson;
        j["provenance"] = provenance.toJson();
        return j;
    }
};

/**
 * @class TestExecutor
 * Executes real tests and captures all relevant data
 */
class TestExecutor {
public:
    TestExecutor();
    
    /**
     * Execute real tests
     * 
     * @param testExecutable Path to test binary
     * @param testFilter Optional filter for test selection
     * @param timeoutMs Maximum execution time
     * @return Complete test result with provenance
     */
    RealTestResult execute(
        const std::string& testExecutable,
        const std::string& testFilter = "",
        int timeoutMs = 300000);  // 5 minute default
    
    /**
     * Detect test framework from executable
     */
    std::string detectFramework(const std::string& testExecutable);
    
    /**
     * Parse test output based on framework
     */
    std::vector<TestCaseResult> parseResults(
        const std::string& output,
        const std::string& framework);
    
    /**
     * Gather test provenance information
     */
    TestProvenance gatherProvenance(const std::string& testExecutable);

private:
    std::string executeCommand(
        const std::string& cmd,
        int& exitCode,
        std::string& stdoutOut,
        std::string& stderrOut,
        int timeoutMs);
    
    std::vector<TestCaseResult> parseGTestOutput(const std::string& output);
    std::vector<TestCaseResult> parseCatch2Output(const std::string& output);
    std::vector<TestCaseResult> parseGenericOutput(const std::string& output);
};

} // namespace VAL012
} // namespace RawrXD
