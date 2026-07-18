/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

/**
 * VAL-012 Build Executor V2
 * 
 * Executes real CMake/Ninja builds with structured results.
 * Returns DetailedBuildResult with explicit failure categorization.
 */

#include "val012_result_types.h"

namespace RawrXD {
namespace VAL012 {

/**
 * @class BuildExecutorV2
 * Enhanced build executor with structured results
 */
class BuildExecutorV2 {
public:
    BuildExecutorV2();
    
    /**
     * Execute a build with full result structure
     * 
     * @param buildDir Directory containing build files
     * @param target Specific target (empty for all)
     * @param config Release/Debug
     * @param timeoutMs Maximum time allowed (0 for no timeout)
     * @return DetailedBuildResult with full categorization
     */
    DetailedBuildResult execute(
        const std::string& buildDir,
        const std::string& target = "",
        const std::string& config = "Release",
        int timeoutMs = 0);
    
    /**
     * Check if build environment is ready
     */
    bool isEnvironmentReady(const std::string& buildDir);
    
    /**
     * Get detailed environment status
     */
    struct EnvironmentStatus {
        bool ready = false;
        bool hasCMake = false;
        bool hasNinja = false;
        bool hasBuildDir = false;
        bool hasCMakeCache = false;
        bool hasBuildNinja = false;
        std::string detectedTool;
    };
    EnvironmentStatus checkEnvironment(const std::string& buildDir);

private:
    // Execution
    std::string executeCommand(
        const std::string& cmd,
        const std::string& cwd,
        int& exitCode,
        std::string& stdoutOut,
        std::string& stderrOut,
        int timeoutMs);
    
    // Detection
    std::string detectBuildSystem(const std::string& buildDir);
    ToolchainInfo gatherToolchainInfo(const std::string& buildDir);
    
    // Artifact collection
    std::vector<BuildArtifact> collectArtifacts(const std::string& buildDir);
    std::string computeSha256(const std::string& filePath);
    
    // Tool queries
    std::string getCMakeVersion();
    std::string getNinjaVersion();
    std::string getCompilerInfo();
    std::string getCompilerVersion();
    
    // Failure analysis
    BuildFailureReason categorizeFailure(
        int exitCode,
        const std::string& stderrOutput,
        const EnvironmentStatus& envStatus);
};

} // namespace VAL012
} // namespace RawrXD
