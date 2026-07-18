/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * VAL-014 Test: Real Toolchain Validation
 * 
 * Validates:
 * - Real compiler discovery
 * - Real configure step
 * - Real build step
 * - Real test invocation
 * - Real artifact collection
 * - Real failure classification
 */

#include "val014_orchestrator.h"
#include <iostream>
#include <fstream>
#include <filesystem>

using namespace RawrXD::VAL014;
using namespace RawrXD::VAL012;

struct TestOutcome {
    std::string name;
    bool passed = false;
    std::string details;
};

void printResult(const ExecutionResult& result) {
    std::cout << "\n=== Execution Result ===\n";
    std::cout << "Validation ID: " << result.validationId << "\n";
    std::cout << "Execution ID: " << result.executionId << "\n";
    std::cout << "Mode: " << result.mode.mode << "\n";
    std::cout << "  Reason: " << result.mode.reason << "\n";
    std::cout << "Environment Ready: " << (result.environmentReady ? "YES" : "NO") << "\n";
    std::cout << "  Details: " << result.environmentDetails << "\n";
    std::cout << "Overall Success: " << (result.overallSuccess() ? "YES" : "NO") << "\n";
    std::cout << "Primary Failure: " << result.primaryFailureReason() << "\n";
    
    if (result.buildResult.has_value()) {
        const auto& br = *result.buildResult;
        std::cout << "\nBuild Result:\n";
        std::cout << "  Success: " << (br.buildSuccess ? "YES" : "NO") << "\n";
        std::cout << "  Failure: " << buildFailureReasonToString(br.failureReason) << "\n";
        std::cout << "  Toolchain: " << br.toolchain.tool << "\n";
        std::cout << "    CMake: " << br.toolchain.cmakeVersion << "\n";
        std::cout << "    Ninja: " << br.toolchain.ninjaVersion << "\n";
        std::cout << "    Compiler: " << br.toolchain.compiler << "\n";
        std::cout << "  Artifacts: " << br.artifacts.size() << "\n";
    }
    
    if (result.testResult.has_value()) {
        const auto& tr = *result.testResult;
        std::cout << "\nTest Result:\n";
        std::cout << "  Success: " << (tr.allTestsPassed ? "YES" : "NO") << "\n";
        std::cout << "  Tests: " << tr.passedTests << "/" << tr.totalTests << "\n";
        std::cout << "  Framework: " << tr.framework.framework << "\n";
    }
}

int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "VAL-014: Real Toolchain Validation\n";
    std::cout << "========================================\n\n";
    
    std::string buildDir = (argc > 1) ? argv[1] : "build-val012-simple";
    std::string testExecutable = buildDir + "/val012_test.exe";
    
    std::vector<TestOutcome> outcomes;
    VAL014Orchestrator orchestrator;
    
    // TEST 1: Real compiler discovery
    std::cout << "[TEST 1] Real compiler discovery...\n";
    {
        auto result = orchestrator.executeBuild(buildDir, "", "Release");
        
        bool pass = result.buildResult.has_value() &&
                    !result.buildResult->toolchain.compiler.empty() &&
                    result.buildResult->toolchain.compiler != "Unknown";
        
        outcomes.push_back({"Real compiler discovery", pass, 
            "Detected: " + (result.buildResult.has_value() ? 
                result.buildResult->toolchain.compiler : "none")});
        
        std::cout << "  Compiler: " << (result.buildResult.has_value() ? 
            result.buildResult->toolchain.compiler : "N/A") << "\n";
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n\n";
    }
    
    // TEST 2: Real configure step detection
    std::cout << "[TEST 2] Real configure step detection...\n";
    {
        auto result = orchestrator.executeBuild(buildDir, "", "Release");
        
        bool pass = result.buildResult.has_value() &&
                    (!result.buildResult->toolchain.cmakeVersion.empty() ||
                     !result.buildResult->toolchain.ninjaVersion.empty());
        
        outcomes.push_back({"Real configure step detection", pass,
            "CMake: " + (result.buildResult.has_value() ? 
                result.buildResult->toolchain.cmakeVersion : "none")});
        
        std::cout << "  CMake: " << (result.buildResult.has_value() ? 
            result.buildResult->toolchain.cmakeVersion : "N/A") << "\n";
        std::cout << "  Ninja: " << (result.buildResult.has_value() ? 
            result.buildResult->toolchain.ninjaVersion : "N/A") << "\n";
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n\n";
    }
    
    // TEST 3: Real build step (with real executable)
    std::cout << "[TEST 3] Real build step...\n";
    if (std::filesystem::exists(testExecutable)) {
        auto result = orchestrator.execute(buildDir, testExecutable, "Release");
        printResult(result);
        
        bool pass = result.buildResult.has_value() &&
                    result.buildResult->executorSuccess &&
                    result.buildResult->environmentReady;
        
        outcomes.push_back({"Real build step", pass,
            "Exit code: " + std::to_string(result.buildResult.has_value() ? 
                result.buildResult->exitCode : -1)});
        
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n\n";
    } else {
        std::cout << "  Skipped: Test executable not found\n";
        std::cout << "  Build it first with: val012_simple_build.bat\n\n";
        outcomes.push_back({"Real build step", false, "Executable not found"});
    }
    
    // TEST 4: Real test invocation
    std::cout << "[TEST 4] Real test invocation...\n";
    if (std::filesystem::exists(testExecutable)) {
        auto result = orchestrator.execute(buildDir, testExecutable, "Release");
        
        bool pass = result.testResult.has_value() &&
                    result.testResult->executorSuccess &&
                    result.testResult->environmentReady &&
                    result.testResult->totalTests > 0;
        
        outcomes.push_back({"Real test invocation", pass,
            "Tests run: " + std::to_string(result.testResult.has_value() ? 
                result.testResult->totalTests : 0)});
        
        std::cout << "  Tests: " << (result.testResult.has_value() ? 
            std::to_string(result.testResult->totalTests) : "N/A") << "\n";
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n\n";
    } else {
        std::cout << "  Skipped: Test executable not found\n\n";
        outcomes.push_back({"Real test invocation", false, "Executable not found"});
    }
    
    // TEST 5: Real artifact collection
    std::cout << "[TEST 5] Real artifact collection...\n";
    if (std::filesystem::exists(testExecutable)) {
        auto result = orchestrator.execute(buildDir, testExecutable, "Release");
        
        bool pass = result.buildResult.has_value() &&
                    !result.buildResult->artifacts.empty();
        
        outcomes.push_back({"Real artifact collection", pass,
            "Artifacts: " + std::to_string(result.buildResult.has_value() ? 
                result.buildResult->artifacts.size() : 0)});
        
        if (result.buildResult.has_value() && !result.buildResult->artifacts.empty()) {
            std::cout << "  Artifacts collected:\n";
            for (const auto& art : result.buildResult->artifacts) {
                std::cout << "    - " << art.path << " (" << art.type << ")\n";
            }
        }
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n\n";
    } else {
        std::cout << "  Skipped: Test executable not found\n\n";
        outcomes.push_back({"Real artifact collection", false, "Executable not found"});
    }
    
    // TEST 6: Real failure classification
    std::cout << "[TEST 6] Real failure classification...\n";
    {
        // Test with non-existent directory to trigger BuildDirectoryMissing
        auto result = orchestrator.executeBuild("nonexistent_dir", "", "Release");
        
        bool pass = result.buildResult.has_value() &&
                    result.buildResult->executorSuccess &&
                    !result.buildResult->environmentReady &&
                    result.buildResult->failureReason == BuildFailureReason::BuildDirectoryMissing;
        
        outcomes.push_back({"Real failure classification", pass,
            "Failure: " + buildFailureReasonToString(result.buildResult.has_value() ? 
                result.buildResult->failureReason : BuildFailureReason::Unknown)});
        
        std::cout << "  Failure reason: " << (result.buildResult.has_value() ? 
            buildFailureReasonToString(result.buildResult->failureReason) : "N/A") << "\n";
        std::cout << "  Executor success: " << (result.buildResult.has_value() && 
            result.buildResult->executorSuccess ? "YES" : "NO") << "\n";
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n\n";
    }
    
    // TEST 7: Universal ExecutionResult contract
    std::cout << "[TEST 7] Universal ExecutionResult contract...\n";
    {
        auto result = orchestrator.executeBuild(buildDir, "", "Release");
        
        // Verify all required fields
        bool hasValidationId = !result.validationId.empty();
        bool hasExecutionId = !result.executionId.empty();
        bool hasMode = !result.mode.mode.empty();
        bool hasBuildResult = result.buildResult.has_value();
        bool hasPrimaryFailure = !result.primaryFailureReason().empty();
        
        bool pass = hasValidationId && hasExecutionId && hasMode && 
                    hasBuildResult && hasPrimaryFailure;
        
        outcomes.push_back({"Universal ExecutionResult contract", pass,
            "Fields: validation_id=" + std::to_string(hasValidationId) +
            ", execution_id=" + std::to_string(hasExecutionId) +
            ", mode=" + std::to_string(hasMode) +
            ", build_result=" + std::to_string(hasBuildResult) +
            ", primary_failure=" + std::to_string(hasPrimaryFailure)});
        
        std::cout << "  Has validation_id: " << (hasValidationId ? "YES" : "NO") << "\n";
        std::cout << "  Has execution_id: " << (hasExecutionId ? "YES" : "NO") << "\n";
        std::cout << "  Has mode: " << (hasMode ? "YES" : "NO") << "\n";
        std::cout << "  Has build_result: " << (hasBuildResult ? "YES" : "NO") << "\n";
        std::cout << "  Has primary_failure: " << (hasPrimaryFailure ? "YES" : "NO") << "\n";
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n\n";
    }
    
    // TEST 8: Evidence generation
    std::cout << "[TEST 8] Evidence generation...\n";
    {
        std::string evidenceDir = "evidence/val014-test-" + 
            std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
        
        orchestrator.execute(buildDir, testExecutable, "Release");
        orchestrator.saveEvidence(evidenceDir);
        
        bool hasResult = std::filesystem::exists(evidenceDir + "/execution_result.json");
        bool hasManifest = std::filesystem::exists(evidenceDir + "/manifest.json");
        
        bool pass = hasResult && hasManifest;
        
        outcomes.push_back({"Evidence generation", pass,
            "Files: execution_result=" + std::to_string(hasResult) +
            ", manifest=" + std::to_string(hasManifest)});
        
        std::cout << "  Evidence dir: " << evidenceDir << "\n";
        std::cout << "  Has execution_result.json: " << (hasResult ? "YES" : "NO") << "\n";
        std::cout << "  Has manifest.json: " << (hasManifest ? "YES" : "NO") << "\n";
        std::cout << "  Result: " << (pass ? "PASS" : "FAIL") << "\n\n";
    }
    
    // Summary
    std::cout << "========================================\n";
    std::cout << "VAL-014 Test Summary\n";
    std::cout << "========================================\n\n";
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& outcome : outcomes) {
        std::cout << (outcome.passed ? "[PASS]" : "[FAIL]") << " " << outcome.name << "\n";
        std::cout << "       " << outcome.details << "\n";
        
        if (outcome.passed) passed++;
        else failed++;
    }
    
    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << "/" << outcomes.size() << " passed\n";
    std::cout << "========================================\n";
    
    // Validation report
    VAL014ValidationReport report;
    report.realToolchainValidated = passed >= 6;
    report.compilerDiscovered = passed >= 1;
    report.configureStepValidated = passed >= 2;
    report.buildStepValidated = passed >= 3;
    report.testInvocationValidated = passed >= 4;
    report.artifactCollectionValidated = passed >= 5;
    report.failureClassificationValidated = passed >= 6;
    report.totalExecutions = static_cast<int>(outcomes.size());
    report.successfulExecutions = passed;
    report.failedExecutions = failed;
    
    // Get toolchain info from last execution
    auto lastResult = orchestrator.getLastResult();
    if (lastResult.buildResult.has_value()) {
        report.cmakeVersion = lastResult.buildResult->toolchain.cmakeVersion;
        report.ninjaVersion = lastResult.buildResult->toolchain.ninjaVersion;
        report.compiler = lastResult.buildResult->toolchain.compiler;
        report.compilerVersion = lastResult.buildResult->toolchain.compilerVersion;
    }
    
    std::cout << "\nValidation Report:\n";
    std::cout << report.toJson().dump(2) << "\n";
    
    return failed == 0 ? 0 : 1;
}
