/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

/**
 * VAL-012 Test Executor V2
 * 
 * Executes real test binaries with structured results.
 * Returns DetailedTestResult with explicit failure categorization.
 */

#include "val012_result_types.h"

namespace RawrXD {
namespace VAL012 {

/**
 * @class TestExecutorV2
 * Enhanced test executor with structured results
 */
class TestExecutorV2 {
public:
    TestExecutorV2();
    
    /**
     * Execute tests with full result structure
     * 
     * @param testExecutable Path to test binary
     * @param testFilter Optional filter for test selection
     * @param timeoutMs Maximum execution time
     * @return DetailedTestResult with full categorization
     */
    DetailedTestResult execute(
        const std::string& testExecutable,
        const std::string& testFilter = "",
        int timeoutMs = 300000);  // 5 minute default
    
    /**
     * Check if test environment is ready
     */
    bool isEnvironmentReady(const std::string& testExecutable);
    
    /**
     * Get detailed environment status
     */
    struct EnvironmentStatus {
        bool ready = false;
        bool executableExists = false;
        bool executableReadable = false;
        size_t executableSize = 0;
        std::string detectedFramework;
    };
    EnvironmentStatus checkEnvironment(const std::string& testExecutable);

private:
    // Execution
    std::string executeCommand(
        const std::string& cmd,
        int& exitCode,
        std::string& stdoutOut,
        std::string& stderrOut,
        int timeoutMs,
        bool& timedOut);
    
    // Detection
    std::string detectFramework(const std::string& testExecutable);
    TestFrameworkInfo gatherFrameworkInfo(const std::string& testExecutable);
    
    // Parsing
    std::vector<TestCaseResult> parseResults(
        const std::string& output,
        const std::string& framework);
    std::vector<TestCaseResult> parseGTestOutput(const std::string& output);
    std::vector<TestCaseResult> parseCatch2Output(const std::string& output);
    std::vector<TestCaseResult> parseGenericOutput(const std::string& output);
    
    // Failure analysis
    TestFailureReason categorizeFailure(
        int exitCode,
        bool timedOut,
        const std::string& stderrOutput,
        const EnvironmentStatus& env);
};

} // namespace VAL012
} // namespace RawrXD
