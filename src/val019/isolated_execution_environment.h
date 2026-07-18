/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * VAL-019.2 Isolated Execution Environment
 * 
 * Provides reproducible, isolated workspaces for autonomous execution.
 * Each execution receives its own directory structure to prevent
 * CMake cache conflicts and ensure reproducibility.
 */

#ifndef VAL019_ISOLATED_EXECUTION_ENVIRONMENT_H
#define VAL019_ISOLATED_EXECUTION_ENVIRONMENT_H

#include "execution_runner.h"
#include <string>
#include <vector>
#include <memory>

namespace RawrXD {
namespace VAL019 {

/**
 * @struct ExecutionWorkspace
 * Isolated workspace for a single execution
 */
struct ExecutionWorkspace {
    std::string workspaceId;
    std::string basePath;
    std::string sourcePath;
    std::string buildPath;
    std::string artifactsPath;
    std::string evidencePath;
    std::string tempPath;
    
    std::chrono::system_clock::time_point createdAt;
    
    val012::json toJson() const {
        val012::json j;
        j["workspace_id"] = workspaceId;
        j["base_path"] = basePath;
        j["source_path"] = sourcePath;
        j["build_path"] = buildPath;
        j["artifacts_path"] = artifactsPath;
        j["evidence_path"] = evidencePath;
        j["temp_path"] = tempPath;
        return j;
    }
};

/**
 * @struct ExecutionMetadata
 * Deterministic execution metadata for evidence
 */
struct ExecutionMetadata {
    std::string executionId;
    std::string sourceCommit;
    std::string generator;
    std::string compiler;
    std::string compilerVersion;
    std::string cmakeVersion;
    std::string cmakeGenerator;
    std::string command;
    int exitCode = -1;
    std::chrono::milliseconds duration{0};
    std::string stdoutSha256;
    std::string stderrSha256;
    std::vector<std::pair<std::string, std::string>> artifacts;  // path -> sha256
    std::chrono::system_clock::time_point executedAt;
    
    val012::json toJson() const {
        val012::json j;
        j["execution_id"] = executionId;
        j["source_commit"] = sourceCommit;
        j["generator"] = generator;
        j["compiler"] = compiler;
        j["compiler_version"] = compilerVersion;
        j["cmake_version"] = cmakeVersion;
        j["cmake_generator"] = cmakeGenerator;
        j["command"] = command;
        j["exit_code"] = exitCode;
        j["duration_ms"] = static_cast<int>(duration.count());
        j["stdout_sha256"] = stdoutSha256;
        j["stderr_sha256"] = stderrSha256;
        val012::json artifactsArray = val012::json::array();
        for (const auto& [path, hash] : artifacts) {
            val012::json artifact;
            artifact["path"] = path;
            artifact["sha256"] = hash;
            artifactsArray.push_back(artifact);
        }
        j["artifacts"] = artifactsArray;
        return j;
    }
};

/**
 * @class IsolatedExecutionEnvironment
 * Manages isolated workspaces for reproducible execution
 */
class IsolatedExecutionEnvironment {
public:
    IsolatedExecutionEnvironment(const std::string& baseDir = "validation/runs");
    ~IsolatedExecutionEnvironment();
    
    // Workspace management
    ExecutionWorkspace createWorkspace(const std::string& prefix = "exec");
    void destroyWorkspace(const ExecutionWorkspace& workspace);
    void cleanupOldWorkspaces(int maxAgeHours = 24);
    
    // Source management
    bool populateSource(const ExecutionWorkspace& workspace, 
                        const std::string& sourceDir);
    bool createMinimalProject(const ExecutionWorkspace& workspace,
                               const std::string& projectType = "cpp");
    bool injectFault(const ExecutionWorkspace& workspace,
                     const std::string& faultType);
    
    // Execution with full metadata
    struct IsolatedExecutionResult {
        bool success = false;
        ExecutionWorkspace workspace;
        ExecutionMetadata metadata;
        BuildExecutorResult buildResult;
        std::string evidencePath;
        
        val012::json toJson() const {
            val012::json j;
            j["success"] = success;
            j["workspace"] = workspace.toJson();
            j["metadata"] = metadata.toJson();
            j["evidence_path"] = evidencePath;
            return j;
        }
    };
    
    IsolatedExecutionResult executeBuild(const ExecutionWorkspace& workspace,
                                          const std::string& target = "");
    IsolatedExecutionResult executeTest(const ExecutionWorkspace& workspace,
                                         const std::string& testName = "");
    
    // Evidence generation
    std::string saveEvidence(const ExecutionWorkspace& workspace,
                            const std::string& name,
                            const val012::json& data);
    
    // Utilities
    static std::string calculateFileHash(const std::string& filePath);
    static std::string getCurrentGitCommit();
    static std::string detectCompiler();
    static std::string detectCMakeVersion();
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @class FailureRecoveryDemonstrator
 * Controlled failure/recovery loop demonstration
 */
class FailureRecoveryDemonstrator {
public:
    FailureRecoveryDemonstrator();
    ~FailureRecoveryDemonstrator();
    
    struct RecoveryResult {
        bool success = false;
        std::string failureType;
        std::string diagnosis;
        std::string repairStrategy;
        int repairAttempts = 0;
        std::chrono::milliseconds totalDuration{0};
        std::string evidenceDir;
        std::vector<std::string> lifecycleStates;  // FAILED -> DIAGNOSED -> REPAIRED -> REBUILT -> PASSED
        
        val012::json toJson() const {
            val012::json j;
            j["success"] = success;
            j["failure_type"] = failureType;
            j["diagnosis"] = diagnosis;
            j["repair_strategy"] = repairStrategy;
            j["repair_attempts"] = repairAttempts;
            j["total_duration_ms"] = static_cast<int>(totalDuration.count());
            j["evidence_dir"] = evidenceDir;
            j["lifecycle_states"] = lifecycleStates;
            return j;
        }
    };
    
    // Demonstrate complete failure/recovery loop
    RecoveryResult demonstrateCompileErrorRecovery();
    RecoveryResult demonstrateLinkErrorRecovery();
    RecoveryResult demonstrateTestFailureRecovery();
    
    // Generate demonstration report
    std::string generateReport(const RecoveryResult& result);
    
private:
    IsolatedExecutionEnvironment env_;
};

} // namespace VAL019
} // namespace RawrXD

#endif // VAL019_ISOLATED_EXECUTION_ENVIRONMENT_H
