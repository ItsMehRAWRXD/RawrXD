/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#include "val012_test_executor_v2.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <thread>
#include <chrono>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#endif

namespace RawrXD {
namespace VAL012 {

TestExecutorV2::TestExecutorV2() {}

DetailedTestResult TestExecutorV2::execute(
    const std::string& testExecutable,
    const std::string& testFilter,
    int timeoutMs) {
    
    DetailedTestResult result;
    result.framework.executable = testExecutable;
    result.timeoutMs = timeoutMs;
    result.executedAt = std::chrono::system_clock::now();
    
    std::cout << "[TestExecutorV2] Starting test execution...\n";
    
    // Phase 1: Environment Check
    auto envStatus = checkEnvironment(testExecutable);
    result.environmentReady = envStatus.ready;
    
    if (!envStatus.ready) {
        std::cout << "[TestExecutorV2] Environment not ready\n";
        result.executorSuccess = true;  // Executor worked correctly
        result.allTestsPassed = false;
        result.failureReason = TestFailureReason::ExecutableMissing;
        
        std::ostringstream oss;
        oss << "Test environment not ready:";
        if (!envStatus.executableExists) oss << " Executable not found;";
        if (!envStatus.executableReadable) oss << " Executable not readable;";
        result.failureDetails = oss.str();
        
        result.executionMode.mode = "real";
        result.executionMode.reason = "Environment check failed";
        
        return result;
    }
    
    // Phase 2: Framework Detection
    result.framework.framework = detectFramework(testExecutable);
    result.executionMode.mode = "real";
    result.executionMode.reason = "Environment ready, executing real tests";
    
    std::cout << "[TestExecutorV2] Framework: " << result.framework.framework << "\n";
    std::cout << "[TestExecutorV2] Executable: " << testExecutable << "\n";
    
    // Phase 3: Test Execution
    auto startTime = std::chrono::steady_clock::now();
    
    std::string cmd = testExecutable;
    if (result.framework.framework == "gtest" && !testFilter.empty()) {
        cmd += " --gtest_filter=" + testFilter;
    } else if (result.framework.framework == "catch2" && !testFilter.empty()) {
        cmd += " " + testFilter;
    }
    
    std::cout << "[TestExecutorV2] Command: " << cmd << "\n";
    
    result.exitCode = -1;
    result.timedOut = false;
    result.stdoutLog = executeCommand(cmd, result.exitCode, result.stdoutLog,
                                       result.stderrLog, timeoutMs, result.timedOut);
    
    auto endTime = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime);
    
    // Phase 4: Result Analysis
    result.executorSuccess = true;  // We got this far without crashing
    
    // Parse results
    result.testCases = parseResults(result.stdoutLog, result.framework.framework);
    
    // Calculate summary
    result.totalTests = static_cast<int>(result.testCases.size());
    result.passedTests = 0;
    result.failedTests = 0;
    result.skippedTests = 0;
    
    for (const auto& tc : result.testCases) {
        if (tc.passed) {
            result.passedTests++;
        } else {
            result.failedTests++;
        }
    }
    
    // If no tests found in output, try to infer from exit code
    if (result.totalTests == 0) {
        if (result.exitCode == 0) {
            // Assume at least one test passed if exit code is 0
            result.totalTests = 1;
            result.passedTests = 1;
        } else {
            result.failureReason = TestFailureReason::NoTestsFound;
            result.failureDetails = "No tests found in output";
        }
    }
    
    result.allTestsPassed = (result.failedTests == 0 && result.totalTests > 0);
    
    if (!result.allTestsPassed) {
        result.failureReason = categorizeFailure(result.exitCode, result.timedOut,
                                                    result.stderrLog, envStatus);
        result.failureDetails = "Tests failed: " + std::to_string(result.failedTests) + 
                                "/" + std::to_string(result.totalTests);
        if (result.timedOut) {
            result.failureDetails += " (timed out after " + std::to_string(timeoutMs) + "ms)";
        }
        std::cout << "[TestExecutorV2] Tests failed: " 
                  << testFailureReasonToString(result.failureReason) << "\n";
    } else {
        result.failureReason = TestFailureReason::None;
        result.failureDetails = "";
    }
    
    std::cout << "[TestExecutorV2] Tests: " << result.passedTests << "/" 
              << result.totalTests << " passed\n";
    std::cout << "[TestExecutorV2] Duration: " << result.duration.count() << "ms\n";
    
    return result;
}

bool TestExecutorV2::isEnvironmentReady(const std::string& testExecutable) {
    return checkEnvironment(testExecutable).ready;
}

TestExecutorV2::EnvironmentStatus TestExecutorV2::checkEnvironment(
    const std::string& testExecutable) {
    
    EnvironmentStatus status;
    status.executableExists = std::filesystem::exists(testExecutable);
    
    if (status.executableExists) {
        status.executableReadable = std::filesystem::is_regular_file(testExecutable);
        if (status.executableReadable) {
            status.executableSize = std::filesystem::file_size(testExecutable);
        }
    }
    
    status.detectedFramework = detectFramework(testExecutable);
    
    // Environment is ready if executable exists and is readable
    status.ready = status.executableExists && status.executableReadable;
    
    return status;
}

std::string TestExecutorV2::executeCommand(
    const std::string& cmd,
    int& exitCode,
    std::string& stdoutOut,
    std::string& stderrOut,
    int timeoutMs,
    bool& timedOut) {
    
    std::string fullOutput;
    timedOut = false;
    
    #ifdef _WIN32
    // Windows implementation with timeout
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    HANDLE hStdOutRead, hStdOutWrite;
    HANDLE hStdErrRead, hStdErrWrite;
    
    CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0);
    CreatePipe(&hStdErrRead, &hStdErrWrite, &sa, 0);
    
    SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStdErrRead, HANDLE_FLAG_INHERIT, 0);
    
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdErrWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;
    
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    
    if (CreateProcessA(NULL, const_cast<char*>(cmd.c_str()), NULL, NULL, TRUE,
                       0, NULL, NULL, &si, &pi)) {
        CloseHandle(hStdOutWrite);
        CloseHandle(hStdErrWrite);
        
        // Wait for process with timeout
        DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
        
        if (waitResult == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            timedOut = true;
            exitCode = -1;
        } else {
            DWORD exitCodeDw;
            GetExitCodeProcess(pi.hProcess, &exitCodeDw);
            exitCode = static_cast<int>(exitCodeDw);
        }
        
        // Read stdout
        char buffer[4096];
        DWORD bytesRead;
        while (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) 
               && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            stdoutOut += buffer;
        }
        
        // Read stderr
        while (ReadFile(hStdErrRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) 
               && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            stderrOut += buffer;
        }
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hStdOutRead);
        CloseHandle(hStdErrRead);
    } else {
        exitCode = -1;
        stdoutOut = "Failed to execute test";
    }
    
    #else
    // POSIX implementation
    FILE* pipe = popen((cmd + " 2>&1").c_str(), "r");
    if (!pipe) {
        exitCode = -1;
        return "Failed to execute test";
    }
    
    char buffer[4096];
    auto startTime = std::chrono::steady_clock::now();
    
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        stdoutOut += buffer;
        
        // Check timeout
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() > timeoutMs) {
            timedOut = true;
            break;
        }
    }
    
    exitCode = timedOut ? -1 : pclose(pipe);
    #endif
    
    return stdoutOut;
}

std::string TestExecutorV2::detectFramework(const std::string& testExecutable) {
    // Check executable for framework signatures
    std::ifstream file(testExecutable, std::ios::binary);
    if (!file) return "unknown";
    
    // Read first 8KB to look for signatures
    std::vector<char> buffer(8192);
    file.read(buffer.data(), buffer.size());
    auto bytesRead = file.gcount();
    std::string content(buffer.data(), bytesRead);
    
    // Check for Google Test signatures
    if (content.find("gtest") != std::string::npos ||
        content.find("Google Test") != std::string::npos ||
        content.find("::testing::") != std::string::npos) {
        return "gtest";
    }
    
    // Check for Catch2 signatures
    if (content.find("Catch2") != std::string::npos ||
        content.find("catch2") != std::string::npos ||
        content.find("CATCH") != std::string::npos) {
        return "catch2";
    }
    
    // Check for custom RawrXD test signatures
    if (content.find("VAL-012") != std::string::npos ||
        content.find("RawrXD") != std::string::npos) {
        return "custom";
    }
    
    return "generic";
}

TestFrameworkInfo TestExecutorV2::gatherFrameworkInfo(const std::string& testExecutable) {
    TestFrameworkInfo info;
    info.executable = testExecutable;
    info.framework = detectFramework(testExecutable);
    info.frameworkVersion = "unknown";
    
    return info;
}

std::vector<TestCaseResult> TestExecutorV2::parseResults(
    const std::string& output,
    const std::string& framework) {
    
    if (framework == "gtest") {
        return parseGTestOutput(output);
    } else if (framework == "catch2") {
        return parseCatch2Output(output);
    } else {
        return parseGenericOutput(output);
    }
}

std::vector<TestCaseResult> TestExecutorV2::parseGTestOutput(const std::string& output) {
    std::vector<TestCaseResult> results;
    
    // Parse Google Test output
    // Pattern: [  PASSED  ] TestSuite.TestName (X ms)
    // Pattern: [  FAILED  ] TestSuite.TestName (X ms)
    
    std::regex passedRegex(R"(\[\s+PASSED\s+\]\s+(\S+)\s*\((\d+)\s*ms\))");
    std::regex failedRegex(R"(\[\s+FAILED\s+\]\s+(\S+)\s*\((\d+)\s*ms\))");
    
    std::smatch match;
    std::string::const_iterator searchStart(output.cbegin());
    
    while (std::regex_search(searchStart, output.cend(), match, passedRegex)) {
        TestCaseResult tc;
        tc.name = match[1];
        tc.passed = true;
        tc.duration = std::chrono::milliseconds(std::stoi(match[2]));
        results.push_back(tc);
        searchStart = match.suffix().first;
    }
    
    searchStart = output.cbegin();
    while (std::regex_search(searchStart, output.cend(), match, failedRegex)) {
        TestCaseResult tc;
        tc.name = match[1];
        tc.passed = false;
        tc.duration = std::chrono::milliseconds(std::stoi(match[2]));
        results.push_back(tc);
        searchStart = match.suffix().first;
    }
    
    return results;
}

std::vector<TestCaseResult> TestExecutorV2::parseCatch2Output(const std::string& output) {
    std::vector<TestCaseResult> results;
    
    // Parse Catch2 output
    // Pattern: Passed: TestName (X ms)
    // Pattern: Failed: TestName (X ms)
    
    std::regex passedRegex(R"(Passed:\s+(\S+)\s*\((\d+)\s*ms\))");
    std::regex failedRegex(R"(Failed:\s+(\S+)\s*\((\d+)\s*ms\))");
    
    std::smatch match;
    std::string::const_iterator searchStart(output.cbegin());
    
    while (std::regex_search(searchStart, output.cend(), match, passedRegex)) {
        TestCaseResult tc;
        tc.name = match[1];
        tc.passed = true;
        tc.duration = std::chrono::milliseconds(std::stoi(match[2]));
        results.push_back(tc);
        searchStart = match.suffix().first;
    }
    
    searchStart = output.cbegin();
    while (std::regex_search(searchStart, output.cend(), match, failedRegex)) {
        TestCaseResult tc;
        tc.name = match[1];
        tc.passed = false;
        tc.duration = std::chrono::milliseconds(std::stoi(match[2]));
        results.push_back(tc);
        searchStart = match.suffix().first;
    }
    
    return results;
}

std::vector<TestCaseResult> TestExecutorV2::parseGenericOutput(const std::string& output) {
    std::vector<TestCaseResult> results;
    
    // Generic parsing - look for PASS/FAIL patterns
    std::regex passRegex(R"((PASS|OK|SUCCESS).*?[:\s]+(\S+))");
    std::regex failRegex(R"((FAIL|ERROR|FAILED).*?[:\s]+(\S+))");
    
    std::smatch match;
    std::string::const_iterator searchStart(output.cbegin());
    
    while (std::regex_search(searchStart, output.cend(), match, passRegex)) {
        TestCaseResult tc;
        tc.name = match[3];
        tc.passed = true;
        results.push_back(tc);
        searchStart = match.suffix().first;
    }
    
    searchStart = output.cbegin();
    while (std::regex_search(searchStart, output.cend(), match, failRegex)) {
        TestCaseResult tc;
        tc.name = match[3];
        tc.passed = false;
        results.push_back(tc);
        searchStart = match.suffix().first;
    }
    
    return results;
}

TestFailureReason TestExecutorV2::categorizeFailure(
    int exitCode,
    bool timedOut,
    const std::string& stderrOutput,
    const EnvironmentStatus& env) {
    
    if (timedOut) {
        return TestFailureReason::Timeout;
    }
    
    if (!env.ready) {
        return TestFailureReason::ExecutableMissing;
    }
    
    // Check for crash indicators
    if (stderrOutput.find("segmentation fault") != std::string::npos ||
        stderrOutput.find("access violation") != std::string::npos ||
        stderrOutput.find("SIGSEGV") != std::string::npos ||
        exitCode == -1073741819) {  // Windows access violation
        return TestFailureReason::Crash;
    }
    
    // Check for no tests found
    if (stderrOutput.find("no tests") != std::string::npos ||
        stderrOutput.find("no test cases") != std::string::npos) {
        return TestFailureReason::NoTestsFound;
    }
    
    // Default: tests failed
    return TestFailureReason::TestsFailed;
}

} // namespace VAL012
} // namespace RawrXD
