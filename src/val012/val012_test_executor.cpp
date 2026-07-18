/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#include "val012_test_executor.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#endif

namespace RawrXD {
namespace VAL012 {

TestExecutor::TestExecutor() {}

RealTestResult TestExecutor::execute(
    const std::string& testExecutable,
    const std::string& testFilter,
    int timeoutMs) {
    
    RealTestResult result;
    result.provenance = gatherProvenance(testExecutable);
    result.provenance.executedAt = std::chrono::system_clock::now();
    
    std::cout << "[TestExecutor] Starting real test execution...\n";
    std::cout << "[TestExecutor] Executable: " << testExecutable << "\n";
    std::cout << "[TestExecutor] Framework: " << result.provenance.framework << "\n";
    
    if (!testFilter.empty()) {
        std::cout << "[TestExecutor] Filter: " << testFilter << "\n";
    }
    
    auto startTime = std::chrono::steady_clock::now();
    
    // Construct test command
    std::string cmd = testExecutable;
    if (result.provenance.framework == "gtest" && !testFilter.empty()) {
        cmd += " --gtest_filter=" + testFilter;
    } else if (result.provenance.framework == "catch2" && !testFilter.empty()) {
        cmd += " " + testFilter;
    }
    
    // Execute tests
    result.provenance.mode = "real";
    int exitCode = -1;
    result.stdoutLog = executeCommand(cmd, exitCode, result.stdoutLog, 
                                       result.stderrLog, timeoutMs);
    
    auto endTime = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime);
    
    // Parse results
    result.testCases = parseResults(result.stdoutLog, result.provenance.framework);
    
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
    
    result.success = (result.failedTests == 0 && result.totalTests > 0);
    
    std::cout << "[TestExecutor] Tests: " << result.passedTests << "/" 
              << result.totalTests << " passed\n";
    std::cout << "[TestExecutor] Duration: " << result.duration.count() << "ms\n";
    
    return result;
}

std::string TestExecutor::detectFramework(const std::string& testExecutable) {
    // Check executable for framework signatures
    std::ifstream file(testExecutable, std::ios::binary);
    if (!file) return "unknown";
    
    // Read first 4KB to look for signatures
    std::vector<char> buffer(4096);
    file.read(buffer.data(), buffer.size());
    auto bytesRead = file.gcount();
    std::string content(buffer.data(), bytesRead);
    
    // Check for Google Test signatures
    if (content.find("gtest") != std::string::npos ||
        content.find("Google Test") != std::string::npos) {
        return "gtest";
    }
    
    // Check for Catch2 signatures
    if (content.find("Catch2") != std::string::npos ||
        content.find("catch2") != std::string::npos) {
        return "catch2";
    }
    
    // Check for custom RawrXD test signatures
    if (content.find("VAL-012") != std::string::npos ||
        content.find("RawrXD") != std::string::npos) {
        return "custom";
    }
    
    return "generic";
}

std::vector<TestCaseResult> TestExecutor::parseResults(
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

TestProvenance TestExecutor::gatherProvenance(const std::string& testExecutable) {
    TestProvenance prov;
    prov.mode = "real";
    prov.framework = detectFramework(testExecutable);
    prov.testExecutable = testExecutable;
    prov.executedAt = std::chrono::system_clock::now();
    
    // Framework version detection would go here
    prov.frameworkVersion = "unknown";
    
    return prov;
}

std::string TestExecutor::executeCommand(
    const std::string& cmd,
    int& exitCode,
    std::string& stdoutOut,
    std::string& stderrOut,
    int timeoutMs) {
    
    std::string fullOutput;
    
    #ifdef _WIN32
    // Windows implementation
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
    // POSIX implementation using popen
    FILE* pipe = popen((cmd + " 2>&1").c_str(), "r");
    if (!pipe) {
        exitCode = -1;
        return "Failed to execute test";
    }
    
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        stdoutOut += buffer;
    }
    
    exitCode = pclose(pipe);
    #endif
    
    return stdoutOut;
}

std::vector<TestCaseResult> TestExecutor::parseGTestOutput(const std::string& output) {
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

std::vector<TestCaseResult> TestExecutor::parseCatch2Output(const std::string& output) {
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
    
    return results;
}

std::vector<TestCaseResult> TestExecutor::parseGenericOutput(const std::string& output) {
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
    
    return results;
}

} // namespace VAL012
} // namespace RawrXD
