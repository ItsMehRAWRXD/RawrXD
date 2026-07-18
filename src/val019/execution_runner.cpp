/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#include "execution_runner.h"
#include "val016_repair_orchestrator.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <regex>
#include <array>
#include <chrono>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#endif

namespace RawrXD {
namespace VAL019 {

// Helper to calculate SHA256 hash (simplified - use proper crypto in production)
std::string ExecutionRunner::calculateHash(const std::string& input) {
    std::hash<std::string> hasher;
    auto hash = hasher(input);
    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << hash;
    return ss.str();
}

// Classify build failure from stderr
std::string ExecutionRunner::classifyBuildFailure(const std::string& stderrLog) {
    if (stderrLog.find("error:") != std::string::npos || 
        stderrLog.find("error C") != std::string::npos) {
        return "COMPILE_ERROR";
    }
    if (stderrLog.find("undefined reference") != std::string::npos ||
        stderrLog.find("LNK") != std::string::npos) {
        return "LINK_ERROR";
    }
    if (stderrLog.find("cannot find") != std::string::npos ||
        stderrLog.find("No such file") != std::string::npos) {
        return "MISSING_DEPENDENCY";
    }
    if (stderrLog.find("CMake Error") != std::string::npos) {
        return "CONFIGURE_ERROR";
    }
    return "UNKNOWN_ERROR";
}

// Classify test failure from stderr
std::string ExecutionRunner::classifyTestFailure(const std::string& stderrLog) {
    if (stderrLog.find("Assertion failed") != std::string::npos ||
        stderrLog.find("assert") != std::string::npos) {
        return "ASSERTION_FAILURE";
    }
    if (stderrLog.find("Expected:") != std::string::npos ||
        stderrLog.find("Actual:") != std::string::npos) {
        return "EXPECTATION_FAILURE";
    }
    if (stderrLog.find("timeout") != std::string::npos ||
        stderrLog.find("timed out") != std::string::npos) {
        return "TIMEOUT";
    }
    if (stderrLog.find("segmentation") != std::string::npos ||
        stderrLog.find("access violation") != std::string::npos) {
        return "CRASH";
    }
    return "TEST_FAILURE";
}

// Extract affected files from error output
std::vector<std::string> ExecutionRunner::extractErrorFiles(const std::string& stderrLog) {
    std::vector<std::string> files;
    std::regex fileRegex(R"(([^\s:]+)\.(cpp|c|h|hpp|cc|cxx):(\d+):)");
    std::smatch match;
    std::string::const_iterator searchStart(stderrLog.cbegin());
    
    while (std::regex_search(searchStart, stderrLog.cend(), match, fileRegex)) {
        std::string file = match[1].str() + "." + match[2].str();
        if (std::find(files.begin(), files.end(), file) == files.end()) {
            files.push_back(file);
        }
        searchStart = match.suffix().first;
    }
    
    return files;
}

// Implementation class
class ExecutionRunner::Impl {
public:
    std::string cmakePath_ = "cmake";
    std::string ninjaPath_ = "ninja";
    std::string ctestPath_ = "ctest";
    std::chrono::milliseconds defaultTimeout_{300000};
    
#ifdef _WIN32
    // Windows process execution with output capture
    ExecutionOutput executeCommand(const std::string& command, 
                                   const std::string& workingDir,
                                   std::chrono::milliseconds timeout) {
        ExecutionOutput output;
        output.startedAt = std::chrono::system_clock::now();
        
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;
        
        HANDLE hStdOutRead, hStdOutWrite;
        HANDLE hStdErrRead, hStdErrWrite;
        
        // Create pipes for stdout and stderr
        if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0) ||
            !CreatePipe(&hStdErrRead, &hStdErrWrite, &sa, 0)) {
            output.exitCode = -1;
            output.stderrLog = "Failed to create pipes";
            return output;
        }
        
        // Prevent inheritance of read handles
        SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(hStdErrRead, HANDLE_FLAG_INHERIT, 0);
        
        STARTUPINFOA si = {};
        si.cb = sizeof(STARTUPINFOA);
        si.hStdOutput = hStdOutWrite;
        si.hStdError = hStdErrWrite;
        si.dwFlags = STARTF_USESTDHANDLES;
        
        PROCESS_INFORMATION pi = {};
        
        std::string cmd = "cmd.exe /c " + command;
        
        BOOL success = CreateProcessA(
            NULL,
            const_cast<char*>(cmd.c_str()),
            NULL, NULL, TRUE, 0, NULL,
            workingDir.empty() ? NULL : workingDir.c_str(),
            &si, &pi
        );
        
        if (!success) {
            output.exitCode = -1;
            output.stderrLog = "Failed to create process";
            CloseHandle(hStdOutWrite);
            CloseHandle(hStdErrWrite);
            CloseHandle(hStdOutRead);
            CloseHandle(hStdErrRead);
            return output;
        }
        
        CloseHandle(hStdOutWrite);
        CloseHandle(hStdErrWrite);
        
        // Read output with timeout
        auto startTime = std::chrono::steady_clock::now();
        char buffer[4096];
        DWORD bytesRead;
        BOOL stdoutDone = FALSE, stderrDone = FALSE;
        
        while (!stdoutDone || !stderrDone) {
            // Check timeout
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed > timeout) {
                output.timedOut = true;
                TerminateProcess(pi.hProcess, 1);
                break;
            }
            
            // Read stdout
            if (!stdoutDone) {
                if (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
                    if (bytesRead > 0) {
                        buffer[bytesRead] = '\0';
                        output.stdoutLog += buffer;
                    }
                } else {
                    stdoutDone = TRUE;
                }
            }
            
            // Read stderr
            if (!stderrDone) {
                if (ReadFile(hStdErrRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
                    if (bytesRead > 0) {
                        buffer[bytesRead] = '\0';
                        output.stderrLog += buffer;
                    }
                } else {
                    stderrDone = TRUE;
                }
            }
            
            // Small sleep to prevent busy waiting
            Sleep(10);
        }
        
        // Get exit code
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        output.exitCode = static_cast<int>(exitCode);
        
        // Cleanup
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hStdOutRead);
        CloseHandle(hStdErrRead);
        
        output.completedAt = std::chrono::system_clock::now();
        output.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            output.completedAt - output.startedAt);
        
        // Calculate hashes
        output.stdoutHash = ExecutionRunner::calculateHash(output.stdoutLog);
        output.stderrHash = ExecutionRunner::calculateHash(output.stderrLog);
        
        return output;
    }
#else
    // POSIX implementation
    ExecutionOutput executeCommand(const std::string& command,
                                   const std::string& workingDir,
                                   std::chrono::milliseconds timeout) {
        ExecutionOutput output;
        output.startedAt = std::chrono::system_clock::now();
        
        int stdoutPipe[2], stderrPipe[2];
        if (pipe(stdoutPipe) == -1 || pipe(stderrPipe) == -1) {
            output.exitCode = -1;
            output.stderrLog = "Failed to create pipes";
            return output;
        }
        
        pid_t pid = fork();
        if (pid == -1) {
            output.exitCode = -1;
            output.stderrLog = "Failed to fork";
            return output;
        }
        
        if (pid == 0) {
            // Child process
            close(stdoutPipe[0]);
            close(stderrPipe[0]);
            
            dup2(stdoutPipe[1], STDOUT_FILENO);
            dup2(stderrPipe[1], STDERR_FILENO);
            
            close(stdoutPipe[1]);
            close(stderrPipe[1]);
            
            if (!workingDir.empty()) {
                chdir(workingDir.c_str());
            }
            
            execl("/bin/sh", "sh", "-c", command.c_str(), NULL);
            _exit(127);
        }
        
        // Parent process
        close(stdoutPipe[1]);
        close(stderrPipe[1]);
        
        // Read output with timeout
        auto startTime = std::chrono::steady_clock::now();
        char buffer[4096];
        
        // Set pipes to non-blocking
        fcntl(stdoutPipe[0], F_SETFL, O_NONBLOCK);
        fcntl(stderrPipe[0], F_SETFL, O_NONBLOCK);
        
        bool childExited = false;
        int status;
        
        while (!childExited) {
            // Check timeout
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed > timeout) {
                output.timedOut = true;
                kill(pid, SIGTERM);
                break;
            }
            
            // Try to read stdout
            ssize_t bytesRead = read(stdoutPipe[0], buffer, sizeof(buffer) - 1);
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                output.stdoutLog += buffer;
            }
            
            // Try to read stderr
            bytesRead = read(stderrPipe[0], buffer, sizeof(buffer) - 1);
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                output.stderrLog += buffer;
            }
            
            // Check if child exited
            pid_t result = waitpid(pid, &status, WNOHANG);
            if (result == pid) {
                childExited = true;
                if (WIFEXITED(status)) {
                    output.exitCode = WEXITSTATUS(status);
                } else {
                    output.exitCode = -1;
                }
            }
            
            usleep(10000);  // 10ms
        }
        
        close(stdoutPipe[0]);
        close(stderrPipe[0]);
        
        output.completedAt = std::chrono::system_clock::now();
        output.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            output.completedAt - output.startedAt);
        
        // Calculate hashes
        output.stdoutHash = ExecutionRunner::calculateHash(output.stdoutLog);
        output.stderrHash = ExecutionRunner::calculateHash(output.stderrLog);
        
        return output;
    }
#endif
};

// Constructor/Destructor
ExecutionRunner::ExecutionRunner() : impl_(std::make_unique<Impl>()) {}
ExecutionRunner::~ExecutionRunner() = default;

// Execute build
BuildExecutorResult ExecutionRunner::executeBuild(const ExecutionConfig& config) {
    BuildExecutorResult result;
    
    // Build command
    std::string cmd = impl_->cmakePath_ + " --build " + config.buildDirectory;
    if (!config.target.empty()) {
        cmd += " --target " + config.target;
    }
    for (const auto& arg : config.extraArgs) {
        cmd += " " + arg;
    }
    
    std::cout << "[VAL-019] Executing: " << cmd << std::endl;
    
    // Execute
    result.output = impl_->executeCommand(cmd, config.workingDirectory, config.timeout);
    
    // Analyze result
    result.success = (result.output.exitCode == 0);
    
    if (!result.success) {
        std::string failureClass = classifyBuildFailure(result.output.stderrLog);
        result.failureDetails = failureClass;
        result.affectedFiles = extractErrorFiles(result.output.stderrLog);
        
        // Map to VAL-016 failure reason
        if (failureClass == "COMPILE_ERROR") {
            result.failureReason = VAL012::BuildFailureReason::CompileFailed;
        } else if (failureClass == "LINK_ERROR") {
            result.failureReason = VAL012::BuildFailureReason::LinkFailed;
        } else if (failureClass == "MISSING_DEPENDENCY") {
            result.failureReason = VAL012::BuildFailureReason::BuildDirectoryMissing;
        } else {
            result.failureReason = VAL012::BuildFailureReason::Unknown;
        }
    }
    
    return result;
}

// Execute tests
TestExecutorResult ExecutionRunner::executeTests(const ExecutionConfig& config) {
    TestExecutorResult result;
    
    // Build command
    std::string cmd = impl_->ctestPath_ + " --test-dir " + config.buildDirectory;
    if (!config.target.empty()) {
        cmd += " -R " + config.target;
    }
    cmd += " --output-on-failure";
    for (const auto& arg : config.extraArgs) {
        cmd += " " + arg;
    }
    
    std::cout << "[VAL-019] Executing: " << cmd << std::endl;
    
    // Execute
    result.output = impl_->executeCommand(cmd, config.workingDirectory, config.timeout);
    
    // Analyze result
    result.success = (result.output.exitCode == 0);
    
    if (!result.success) {
        std::string failureClass = classifyTestFailure(result.output.stderrLog);
        result.failureDetails = failureClass;
        result.failureReason = VAL012::TestFailureReason::TestsFailed;
    }
    
    // Parse test counts from output (simplified)
    // In real implementation, parse CTest output or use test framework specific parsing
    result.totalTests = 1;  // Placeholder
    result.passedTests = result.success ? 1 : 0;
    result.failedTests = result.success ? 0 : 1;
    
    return result;
}

// Execute configure
ExecutionOutput ExecutionRunner::executeConfigure(const ExecutionConfig& config) {
    std::string cmd = impl_->cmakePath_ + " -B " + config.buildDirectory;
    if (!config.workingDirectory.empty()) {
        cmd += " -S " + config.workingDirectory;
    }
    for (const auto& arg : config.extraArgs) {
        cmd += " " + arg;
    }
    
    std::cout << "[VAL-019] Executing: " << cmd << std::endl;
    
    return impl_->executeCommand(cmd, "", config.timeout);
}

// Execute custom command
ExecutionOutput ExecutionRunner::executeCustom(const std::string& command, 
                                                  const ExecutionConfig& config) {
    std::cout << "[VAL-019] Executing custom: " << command << std::endl;
    return impl_->executeCommand(command, config.workingDirectory, config.timeout);
}

// Generate evidence artifact
std::string ExecutionRunner::generateEvidenceArtifact(const std::string& evidenceDir,
                                                       const std::string& name,
                                                       const val012::json& data) {
    std::filesystem::create_directories(evidenceDir);
    std::string path = evidenceDir + "/" + name + ".json";
    std::ofstream ofs(path);
    if (ofs) {
        ofs << data.dump(2);
    }
    return path;
}

// Configuration
void ExecutionRunner::setCMakePath(const std::string& path) { impl_->cmakePath_ = path; }
void ExecutionRunner::setNinjaPath(const std::string& path) { impl_->ninjaPath_ = path; }
void ExecutionRunner::setCTestPath(const std::string& path) { impl_->ctestPath_ = path; }
void ExecutionRunner::setDefaultTimeout(std::chrono::milliseconds timeout) { 
    impl_->defaultTimeout_ = timeout; 
}

// Convert BuildExecutorResult to VAL014 ExecutionResult
VAL014::ExecutionResult BuildExecutorResult::toExecutionResult(const ExecutionConfig& config) const {
    VAL014::ExecutionResult result;
    result.validationId = "VAL-019-BUILD";
    result.executionId = "build-" + std::to_string(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    result.mode.mode = "real";
    result.mode.reason = "VAL-019 real build execution";
    result.environmentReady = true;
    result.startedAt = output.startedAt;
    result.completedAt = output.completedAt;
    
    VAL012::DetailedBuildResult buildResult;
    buildResult.executionMode = result.mode;
    buildResult.executorSuccess = true;
    buildResult.environmentReady = true;
    buildResult.buildSuccess = success;
    buildResult.failureReason = failureReason;
    buildResult.failureDetails = failureDetails;
    buildResult.exitCode = output.exitCode;
    buildResult.stdoutLog = output.stdoutLog;
    buildResult.stderrLog = output.stderrLog;
    buildResult.workingDirectory = config.workingDirectory;
    buildResult.executedAt = output.startedAt;
    
    result.buildResult = buildResult;
    
    return result;
}

// Convert TestExecutorResult to VAL014 ExecutionResult
VAL014::ExecutionResult TestExecutorResult::toExecutionResult(const ExecutionConfig& config) const {
    VAL014::ExecutionResult result;
    result.validationId = "VAL-019-TEST";
    result.executionId = "test-" + std::to_string(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    result.mode.mode = "real";
    result.mode.reason = "VAL-019 real test execution";
    result.environmentReady = true;
    result.startedAt = output.startedAt;
    result.completedAt = output.completedAt;
    
    // Build succeeded (we got to test)
    VAL012::DetailedBuildResult buildResult;
    buildResult.executionMode = result.mode;
    buildResult.executorSuccess = true;
    buildResult.environmentReady = true;
    buildResult.buildSuccess = true;
    buildResult.workingDirectory = config.workingDirectory;
    buildResult.executedAt = output.startedAt;
    result.buildResult = buildResult;
    
    // Test result
    VAL012::DetailedTestResult testResult;
    testResult.executionMode = result.mode;
    testResult.executorSuccess = true;
    testResult.allTestsPassed = success;
    testResult.failureReason = failureReason;
    testResult.failureDetails = failureDetails;
    testResult.totalTests = totalTests;
    testResult.passedTests = passedTests;
    testResult.failedTests = failedTests;
    testResult.exitCode = output.exitCode;
    testResult.stdoutLog = output.stdoutLog;
    testResult.stderrLog = output.stderrLog;
    testResult.executedAt = output.startedAt;
    
    result.testResult = testResult;
    
    return result;
}

// RealBuildExecutor implementation
RealBuildExecutor::RealBuildExecutor() = default;
RealBuildExecutor::~RealBuildExecutor() = default;

VAL014::ExecutionResult RealBuildExecutor::build(const std::string& sourceDir,
                                                    const std::string& buildDir,
                                                    const std::string& target) {
    ExecutionConfig config;
    config.workingDirectory = sourceDir;
    config.buildDirectory = buildDir;
    config.target = target;
    config.type = ExecutionType::Build;
    
    auto result = runner_.executeBuild(config);
    return result.toExecutionResult(config);
}

VAL014::ExecutionResult RealBuildExecutor::test(const std::string& buildDir,
                                                 const std::string& testName) {
    ExecutionConfig config;
    config.buildDirectory = buildDir;
    config.target = testName;
    config.type = ExecutionType::Test;
    
    auto result = runner_.executeTests(config);
    return result.toExecutionResult(config);
}

RealBuildExecutor::PipelineResult RealBuildExecutor::executePipeline(
    const std::string& sourceDir,
    const std::string& buildDir,
    bool enableRepair) {
    
    PipelineResult pipeline;
    std::string evidenceDir = "evidence/val019-pipeline-" + 
        std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    pipeline.evidenceDir = evidenceDir;
    
    std::cout << "\n[VAL-019] Starting build/test pipeline" << std::endl;
    std::cout << "  Source: " << sourceDir << std::endl;
    std::cout << "  Build: " << buildDir << std::endl;
    std::cout << "  Repair: " << (enableRepair ? "enabled" : "disabled") << std::endl;
    
    // Step 1: Build
    std::cout << "\n[VAL-019] Step 1: Building..." << std::endl;
    auto buildResult = this->build(sourceDir, buildDir);
    pipeline.executionHistory.push_back(buildResult);
    pipeline.buildSuccess = buildResult.buildResult.has_value() && 
                           buildResult.buildResult->buildSuccess;
    
    // Save build evidence
    if (buildResult.buildResult.has_value()) {
        runner_.generateEvidenceArtifact(evidenceDir, "build_attempt_001", 
                                         buildResult.buildResult->toJson());
    }
    
    // Step 2: If build failed and repair enabled, attempt repair
    if (!pipeline.buildSuccess && enableRepair) {
        std::cout << "\n[VAL-019] Build failed, attempting repair..." << std::endl;
        pipeline.repairInvoked = true;
        
        VAL016::VAL016RepairOrchestrator repairOrchestrator;
        auto repairSession = repairOrchestrator.repair(buildResult, 3);
        pipeline.repairAttempts = static_cast<int>(repairSession.attempts.size());
        
        // Save repair evidence
        val012::json repairJson;
        repairJson["session_id"] = repairSession.sessionId;
        repairJson["success"] = repairSession.success;
        repairJson["error"] = repairSession.errorMessage;
        runner_.generateEvidenceArtifact(evidenceDir, "repair_session", repairJson);
        
        if (repairSession.success) {
            std::cout << "[VAL-019] Repair succeeded, rebuilding..." << std::endl;
            
            // Rebuild after repair
            auto rebuildResult = this->build(sourceDir, buildDir);
            pipeline.executionHistory.push_back(rebuildResult);
            pipeline.buildSuccess = rebuildResult.buildResult.has_value() && 
                                   rebuildResult.buildResult->buildSuccess;
            
            if (rebuildResult.buildResult.has_value()) {
                runner_.generateEvidenceArtifact(evidenceDir, "build_attempt_002", 
                                                 rebuildResult.buildResult->toJson());
            }
        } else {
            std::cout << "[VAL-019] Repair failed" << std::endl;
        }
    }
    
    // Step 3: Test (only if build succeeded)
    if (pipeline.buildSuccess) {
        std::cout << "\n[VAL-019] Step 3: Testing..." << std::endl;
        auto testResult = this->test(buildDir);
        pipeline.executionHistory.push_back(testResult);
        pipeline.testSuccess = testResult.testResult.has_value() && 
                              testResult.testResult->allTestsPassed;
        
        if (testResult.testResult.has_value()) {
            runner_.generateEvidenceArtifact(evidenceDir, "test_execution", 
                                             testResult.testResult->toJson());
        }
        
        // Step 4: If test failed and repair enabled, attempt repair
        if (!pipeline.testSuccess && enableRepair) {
            std::cout << "\n[VAL-019] Tests failed, attempting repair..." << std::endl;
            pipeline.repairInvoked = true;
            
            VAL016::VAL016RepairOrchestrator repairOrchestrator;
            auto repairSession = repairOrchestrator.repair(testResult, 3);
            pipeline.repairAttempts += static_cast<int>(repairSession.attempts.size());
            
            val012::json repairJson2;
            repairJson2["session_id"] = repairSession.sessionId;
            repairJson2["success"] = repairSession.success;
            repairJson2["error"] = repairSession.errorMessage;
            runner_.generateEvidenceArtifact(evidenceDir, "repair_session_test", repairJson2);
            
            if (repairSession.success) {
                std::cout << "[VAL-019] Repair succeeded, retesting..." << std::endl;
                
                auto retestResult = this->test(buildDir);
                pipeline.executionHistory.push_back(retestResult);
                pipeline.testSuccess = retestResult.testResult.has_value() && 
                                      retestResult.testResult->allTestsPassed;
                
                if (retestResult.testResult.has_value()) {
                    runner_.generateEvidenceArtifact(evidenceDir, "test_execution_002", 
                                                     retestResult.testResult->toJson());
                }
            }
        }
    }
    
    // Save pipeline summary
    runner_.generateEvidenceArtifact(evidenceDir, "pipeline_summary", pipeline.toJson());
    
    std::cout << "\n[VAL-019] Pipeline complete" << std::endl;
    std::cout << "  Build: " << (pipeline.buildSuccess ? "SUCCESS" : "FAILED") << std::endl;
    std::cout << "  Test: " << (pipeline.testSuccess ? "SUCCESS" : 
                               (pipeline.buildSuccess ? "FAILED" : "SKIPPED")) << std::endl;
    std::cout << "  Repair attempts: " << pipeline.repairAttempts << std::endl;
    std::cout << "  Evidence: " << evidenceDir << std::endl;
    
    return pipeline;
}

} // namespace VAL019
} // namespace RawrXD
