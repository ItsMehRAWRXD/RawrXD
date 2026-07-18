/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#include "val014_orchestrator.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <random>

#ifdef _WIN32
#include <windows.h>
#include <lmcons.h>
#else
#include <unistd.h>
#include <sys/utsname.h>
#endif

namespace RawrXD {
namespace VAL014 {

VAL014Orchestrator::VAL014Orchestrator() {}

ExecutionResult VAL014Orchestrator::execute(
    const std::string& buildDir,
    const std::string& testExecutable,
    const std::string& config) {
    
    std::cout << "[VAL-014] Starting real toolchain validation...\n";
    std::cout << "[VAL-014] Build dir: " << buildDir << "\n";
    std::cout << "[VAL-014] Test executable: " << testExecutable << "\n";
    
    ExecutionResult result;
    result.validationId = "VAL-014";
    result.executionId = generateExecutionId();
    result.startedAt = std::chrono::system_clock::now();
    result.hostname = getHostname();
    result.user = getUsername();
    
    // Phase 1: Build
    std::cout << "\n[VAL-014] Phase 1: Build execution...\n";
    VAL012::BuildExecutorV2 buildExecutor;
    auto buildRes = buildExecutor.execute(buildDir, "", config);
    result.buildResult = buildRes;
    
    // Phase 2: Test (only if build succeeded)
    if (buildRes.buildSuccess) {
        std::cout << "\n[VAL-014] Phase 2: Test execution...\n";
        VAL012::TestExecutorV2 testExecutor;
        auto testRes = testExecutor.execute(testExecutable, "", 300000);
        result.testResult = testRes;
    } else {
        std::cout << "\n[VAL-014] Phase 2: Skipped (build failed)\n";
    }
    
    // Determine environment readiness
    result.environmentReady = buildRes.environmentReady;
    if (!result.environmentReady) {
        result.environmentDetails = buildRes.failureDetails;
    } else {
        result.environmentDetails = "Environment ready";
    }
    
    // Set mode
    result.mode = buildRes.executionMode;
    
    result.completedAt = std::chrono::system_clock::now();
    
    // Print summary
    std::cout << "\n[VAL-014] Execution complete\n";
    std::cout << "[VAL-014] Overall success: " << (result.overallSuccess() ? "YES" : "NO") << "\n";
    std::cout << "[VAL-014] Primary failure: " << result.primaryFailureReason() << "\n";
    
    lastResult_ = result;
    return result;
}

ExecutionResult VAL014Orchestrator::executeBuild(
    const std::string& buildDir,
    const std::string& target,
    const std::string& config) {
    
    std::cout << "[VAL-014] Build-only execution...\n";
    
    ExecutionResult result;
    result.validationId = "VAL-014";
    result.executionId = generateExecutionId();
    result.startedAt = std::chrono::system_clock::now();
    result.hostname = getHostname();
    result.user = getUsername();
    
    VAL012::BuildExecutorV2 buildExecutor;
    auto buildRes = buildExecutor.execute(buildDir, target, config);
    result.buildResult = buildRes;
    
    result.environmentReady = buildRes.environmentReady;
    result.environmentDetails = buildRes.failureDetails;
    result.mode = buildRes.executionMode;
    
    result.completedAt = std::chrono::system_clock::now();
    
    lastResult_ = result;
    return result;
}

ExecutionResult VAL014Orchestrator::executeTests(
    const std::string& testExecutable,
    const std::string& testFilter) {
    
    std::cout << "[VAL-014] Test-only execution...\n";
    
    ExecutionResult result;
    result.validationId = "VAL-014";
    result.executionId = generateExecutionId();
    result.startedAt = std::chrono::system_clock::now();
    result.hostname = getHostname();
    result.user = getUsername();
    
    VAL012::TestExecutorV2 testExecutor;
    auto testRes = testExecutor.execute(testExecutable, testFilter, 300000);
    result.testResult = testRes;
    
    result.environmentReady = testRes.environmentReady;
    result.environmentDetails = testRes.failureDetails;
    result.mode = testRes.executionMode;
    
    result.completedAt = std::chrono::system_clock::now();
    
    lastResult_ = result;
    return result;
}

void VAL014Orchestrator::saveEvidence(const std::string& evidenceDir) {
    std::cout << "[VAL-014] Saving evidence to " << evidenceDir << "...\n";
    
    std::filesystem::create_directories(evidenceDir);
    
    // Save execution result
    std::ofstream resultOfs(evidenceDir + "/execution_result.json");
    if (resultOfs) {
        resultOfs << lastResult_.toJson().dump(2);
    }
    
    // Save build result if present
    if (lastResult_.buildResult.has_value()) {
        std::ofstream buildOfs(evidenceDir + "/build_result.json");
        if (buildOfs) {
            buildOfs << lastResult_.buildResult->toJson().dump(2);
        }
    }
    
    // Save test result if present
    if (lastResult_.testResult.has_value()) {
        std::ofstream testOfs(evidenceDir + "/test_result.json");
        if (testOfs) {
            testOfs << lastResult_.testResult->toJson().dump(2);
        }
    }
    
    // Save manifest
    val012::json manifest;
    manifest["validation_id"] = "VAL-014";
    manifest["execution_id"] = lastResult_.executionId;
    manifest["timestamp"] = static_cast<long long>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    manifest["files"] = val012::json::array();
    manifest["files"].push_back("execution_result.json");
    if (lastResult_.buildResult.has_value()) {
        manifest["files"].push_back("build_result.json");
    }
    if (lastResult_.testResult.has_value()) {
        manifest["files"].push_back("test_result.json");
    }
    
    std::ofstream manifestOfs(evidenceDir + "/manifest.json");
    if (manifestOfs) {
        manifestOfs << manifest.dump(2);
    }
    
    std::cout << "[VAL-014] Evidence saved\n";
}

std::string VAL014Orchestrator::generateExecutionId() {
    // Simple UUID generation
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    const char* hex = "0123456789abcdef";
    std::string uuid;
    for (int i = 0; i < 16; ++i) {
        uuid += hex[dis(gen)];
    }
    return "val014-" + uuid;
}

std::string VAL014Orchestrator::getHostname() {
#ifdef _WIN32
    char buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buffer);
    if (GetComputerNameA(buffer, &size)) {
        return std::string(buffer);
    }
    return "unknown";
#else
    struct utsname buf;
    if (uname(&buf) == 0) {
        return std::string(buf.nodename);
    }
    return "unknown";
#endif
}

std::string VAL014Orchestrator::getUsername() {
#ifdef _WIN32
    char buffer[UNLEN + 1];
    DWORD size = sizeof(buffer);
    if (GetUserNameA(buffer, &size)) {
        return std::string(buffer);
    }
    return "unknown";
#else
    const char* user = getenv("USER");
    return user ? std::string(user) : "unknown";
#endif
}

} // namespace VAL014
} // namespace RawrXD
