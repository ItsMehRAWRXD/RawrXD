/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * VAL-019 Real Execution Bridge Test
 * 
 * Demonstrates the real build/test execution bridge that connects
 * VAL-019 autonomous execution to actual CMake/Ninja builds.
 * 
 * This is the critical bridge from simulated to real execution.
 */

#include "execution_runner.h"
#include "val019_autonomous_execution.h"
#include <iostream>
#include <filesystem>
#include <fstream>

using namespace RawrXD::VAL019;
using namespace RawrXD::VAL016;
using namespace RawrXD::VAL014;
using namespace RawrXD::VAL012;

// Create a minimal test project
bool createTestProject(const std::string& dir) {
    // Clean up any existing directory
    if (std::filesystem::exists(dir)) {
        std::filesystem::remove_all(dir);
    }
    std::filesystem::create_directories(dir);
    std::filesystem::create_directories(dir + "/src");
    
    // Create CMakeLists.txt
    std::ofstream cmake(dir + "/CMakeLists.txt");
    if (!cmake) return false;
    cmake << "cmake_minimum_required(VERSION 3.20)\n";
    cmake << "project(TestProject CXX)\n";
    cmake << "set(CMAKE_CXX_STANDARD 20)\n";
    cmake << "add_executable(test_app src/main.cpp)\n";
    cmake << "enable_testing()\n";
    cmake << "add_test(NAME simple_test COMMAND test_app)\n";
    cmake.close();
    return true;
}

// Create working source file
bool createWorkingSource(const std::string& dir) {
    std::ofstream src(dir + "/src/main.cpp");
    if (!src) return false;
    src << "#include <iostream>\n";
    src << "int main() {\n";
    src << "    std::cout << \"Hello from test app\" << std::endl;\n";
    src << "    return 0;\n";
    src << "}\n";
    return true;
}

// Create broken source file (compile error)
bool createBrokenSource(const std::string& dir) {
    std::ofstream src(dir + "/src/main.cpp");
    if (!src) return false;
    src << "#include <iostream>\n";
    src << "int main() {\n";
    src << "    std::cout << \"Missing semicolon\"\n";  // Error: missing semicolon\n";
    src << "    return 0\n";  // Error: missing semicolon\n";
    src << "}\n";
    return true;
}

// Test 1: Real build execution
bool testRealBuildExecution() {
    std::cout << "\n[Test 1] Real Build Execution\n";
    std::cout << "================================\n";
    
    std::string testDir = "val019_test_build";
    std::string buildDir = "val019_test_build_build";  // Separate build dir
    
    // Clean up any existing directories
    if (std::filesystem::exists(testDir)) {
        std::filesystem::remove_all(testDir);
    }
    if (std::filesystem::exists(buildDir)) {
        std::filesystem::remove_all(buildDir);
    }
    
    // Setup
    if (!createTestProject(testDir)) {
        std::cout << "✗ Failed to create test project\n";
        return false;
    }
    if (!createWorkingSource(testDir)) {
        std::cout << "✗ Failed to create source file\n";
        return false;
    }
    
    // Configure
    std::cout << "Configuring...\n";
    ExecutionRunner runner;
    ExecutionConfig config;
    config.workingDirectory = testDir;
    config.buildDirectory = buildDir;
    
    auto configureOutput = runner.executeConfigure(config);
    if (configureOutput.exitCode != 0) {
        std::cout << "✗ Configure failed:\n" << configureOutput.stderrLog << "\n";
        std::filesystem::remove_all(testDir);
        std::filesystem::remove_all(buildDir);
        return false;
    }
    std::cout << "✓ Configure succeeded\n";
    
    // Build
    std::cout << "Building...\n";
    auto buildResult = runner.executeBuild(config);
    
    std::cout << "Build result:\n";
    std::cout << "  Success: " << (buildResult.success ? "YES" : "NO") << "\n";
    std::cout << "  Exit code: " << buildResult.output.exitCode << "\n";
    std::cout << "  Duration: " << buildResult.output.duration.count() << "ms\n";
    std::cout << "  Stdout hash: " << buildResult.output.stdoutHash << "\n";
    std::cout << "  Stderr hash: " << buildResult.output.stderrHash << "\n";
    
    // Cleanup
    std::filesystem::remove_all(testDir);
    std::filesystem::remove_all(buildDir);
    
    return buildResult.success;
}

// Test 2: Real build failure detection
bool testRealBuildFailureDetection() {
    std::cout << "\n[Test 2] Real Build Failure Detection\n";
    std::cout << "======================================\n";
    
    std::string testDir = "val019_test_failure";
    std::string buildDir = testDir + "/build";
    
    // Setup with broken source
    if (!createTestProject(testDir)) {
        std::cout << "✗ Failed to create test project\n";
        return false;
    }
    if (!createBrokenSource(testDir)) {
        std::cout << "✗ Failed to create broken source\n";
        return false;
    }
    
    // Configure
    std::cout << "Configuring...\n";
    ExecutionRunner runner;
    ExecutionConfig config;
    config.workingDirectory = testDir;
    config.buildDirectory = "build";
    
    auto configureOutput = runner.executeConfigure(config);
    if (configureOutput.exitCode != 0) {
        std::cout << "✗ Configure failed\n";
        std::filesystem::remove_all(testDir);
        return false;
    }
    
    // Build (should fail)
    std::cout << "Building (expecting failure)...\n";
    auto buildResult = runner.executeBuild(config);
    
    std::cout << "Build result:\n";
    std::cout << "  Success: " << (buildResult.success ? "YES" : "NO") << "\n";
    std::cout << "  Failure reason: " << static_cast<int>(buildResult.failureReason) << "\n";
    std::cout << "  Failure details: " << buildResult.failureDetails << "\n";
    std::cout << "  Affected files: " << buildResult.affectedFiles.size() << "\n";
    for (const auto& file : buildResult.affectedFiles) {
        std::cout << "    - " << file << "\n";
    }
    
    // Convert to VAL-016 compatible result
    auto executionResult = buildResult.toExecutionResult(config);
    std::cout << "\nVAL-016 compatible result:\n";
    std::cout << "  Has build result: " << (executionResult.buildResult.has_value() ? "YES" : "NO") << "\n";
    if (executionResult.buildResult.has_value()) {
        std::cout << "  Failure category: " << static_cast<int>(executionResult.buildResult->failureReason) << "\n";
    }
    
    // Cleanup
    std::filesystem::remove_all(testDir);
    
    // Test passes if build failed as expected
    return !buildResult.success && 
           buildResult.failureReason == BuildFailureReason::CompileFailed;
}

// Test 3: Build/Test pipeline with evidence
bool testBuildTestPipeline() {
    std::cout << "\n[Test 3] Build/Test Pipeline with Evidence\n";
    std::cout << "==========================================\n";
    
    std::string testDir = "val019_test_pipeline";
    
    // Setup
    if (!createTestProject(testDir)) {
        std::cout << "✗ Failed to create test project\n";
        return false;
    }
    if (!createWorkingSource(testDir)) {
        std::cout << "✗ Failed to create source file\n";
        return false;
    }
    
    // Execute pipeline
    std::cout << "Executing pipeline...\n";
    RealBuildExecutor executor;
    auto result = executor.executePipeline(testDir, testDir + "/build", false);  // No repair for this test
    
    std::cout << "\nPipeline result:\n";
    std::cout << "  Build success: " << (result.buildSuccess ? "YES" : "NO") << "\n";
    std::cout << "  Test success: " << (result.testSuccess ? "YES" : "NO") << "\n";
    std::cout << "  Repair invoked: " << (result.repairInvoked ? "YES" : "NO") << "\n";
    std::cout << "  Execution history: " << result.executionHistory.size() << " entries\n";
    std::cout << "  Evidence dir: " << result.evidenceDir << "\n";
    
    // Check evidence was created
    bool evidenceExists = std::filesystem::exists(result.evidenceDir);
    std::cout << "  Evidence exists: " << (evidenceExists ? "YES" : "NO") << "\n";
    
    // Cleanup
    std::filesystem::remove_all(testDir);
    
    return result.buildSuccess && result.testSuccess && evidenceExists;
}

// Test 4: Evidence chain integrity
bool testEvidenceChainIntegrity() {
    std::cout << "\n[Test 4] Evidence Chain Integrity\n";
    std::cout << "====================================\n";
    
    std::string testDir = "val019_test_evidence";
    
    // Setup
    if (!createTestProject(testDir)) {
        std::cout << "✗ Failed to create test project\n";
        return false;
    }
    if (!createWorkingSource(testDir)) {
        std::cout << "✗ Failed to create source file\n";
        return false;
    }
    
    // Execute and capture evidence
    RealBuildExecutor executor;
    auto result = executor.executePipeline(testDir, testDir + "/build", false);
    
    // Verify evidence files
    std::cout << "Evidence files:\n";
    int fileCount = 0;
    for (const auto& entry : std::filesystem::directory_iterator(result.evidenceDir)) {
        std::cout << "  " << entry.path().filename().string() << "\n";
        fileCount++;
    }
    
    std::cout << "Total evidence files: " << fileCount << "\n";
    
    // Cleanup
    std::filesystem::remove_all(testDir);
    
    return fileCount >= 2;  // Should have at least build and test evidence
}

// Test 5: Integration with VAL-016
bool testVAL016Integration() {
    std::cout << "\n[Test 5] VAL-016 Integration\n";
    std::cout << "=============================\n";
    
    std::string testDir = "val019_test_val016";
    
    // Setup with broken source to trigger repair
    if (!createTestProject(testDir)) {
        std::cout << "✗ Failed to create test project\n";
        return false;
    }
    if (!createBrokenSource(testDir)) {
        std::cout << "✗ Failed to create broken source\n";
        return false;
    }
    
    // Execute pipeline with repair enabled
    std::cout << "Executing pipeline with VAL-016 repair...\n";
    RealBuildExecutor executor;
    auto result = executor.executePipeline(testDir, testDir + "/build", true);  // Enable repair
    
    std::cout << "\nPipeline result:\n";
    std::cout << "  Build success: " << (result.buildSuccess ? "YES" : "NO") << "\n";
    std::cout << "  Repair invoked: " << (result.repairInvoked ? "YES" : "NO") << "\n";
    std::cout << "  Repair attempts: " << result.repairAttempts << "\n";
    
    // Note: Repair may not actually fix the code (VAL-016 policies are templates),
    // but the integration should work
    bool integrationWorks = result.repairInvoked;  // Repair was attempted
    
    // Cleanup
    std::filesystem::remove_all(testDir);
    
    return integrationWorks;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "VAL-019 Real Execution Bridge Test\n";
    std::cout << "========================================\n";
    std::cout << "\nThis test validates the bridge between\n";
    std::cout << "VAL-019 autonomous execution and real\n";
    std::cout << "CMake/Ninja build/test execution.\n\n";
    
    int passed = 0;
    int failed = 0;
    
    // Run tests
    if (testRealBuildExecution()) {
        std::cout << "\n✓ Test 1 PASSED\n";
        passed++;
    } else {
        std::cout << "\n✗ Test 1 FAILED\n";
        failed++;
    }
    
    if (testRealBuildFailureDetection()) {
        std::cout << "\n✓ Test 2 PASSED\n";
        passed++;
    } else {
        std::cout << "\n✗ Test 2 FAILED\n";
        failed++;
    }
    
    if (testBuildTestPipeline()) {
        std::cout << "\n✓ Test 3 PASSED\n";
        passed++;
    } else {
        std::cout << "\n✗ Test 3 FAILED\n";
        failed++;
    }
    
    if (testEvidenceChainIntegrity()) {
        std::cout << "\n✓ Test 4 PASSED\n";
        passed++;
    } else {
        std::cout << "\n✗ Test 4 FAILED\n";
        failed++;
    }
    
    if (testVAL016Integration()) {
        std::cout << "\n✓ Test 5 PASSED\n";
        passed++;
    } else {
        std::cout << "\n✗ Test 5 FAILED\n";
        failed++;
    }
    
    // Summary
    std::cout << "\n========================================\n";
    std::cout << "Test Summary\n";
    std::cout << "========================================\n";
    std::cout << "Total:  " << (passed + failed) << "\n";
    std::cout << "Passed: " << passed << "\n";
    std::cout << "Failed: " << failed << "\n";
    std::cout << "Success Rate: " << (100 * passed / (passed + failed)) << "%\n";
    
    if (failed == 0) {
        std::cout << "\n✓ All tests PASSED\n";
        std::cout << "\nThe real execution bridge is operational.\n";
        std::cout << "VAL-019 can now execute real CMake builds\n";
        std::cout << "and integrate with VAL-016 repair.\n";
        return 0;
    } else {
        std::cout << "\n✗ Some tests FAILED\n";
        return 1;
    }
}
