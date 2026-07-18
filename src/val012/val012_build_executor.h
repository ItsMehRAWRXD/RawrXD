/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

/**
 * VAL-012 Build Executor
 * 
 * Executes real CMake/Ninja builds and captures:
 * - Exit code
 * - Elapsed time
 * - stdout/stderr
 * - Artifacts produced
 * - Toolchain information
 */

#include <string>
#include <vector>
#include <chrono>
#include "json_minimal.hpp"

namespace RawrXD {
namespace VAL012 {

/**
 * @struct BuildArtifact
 * Represents a file produced by the build
 */
struct BuildArtifact {
    std::string path;
    std::string type;      // "executable", "library", "object", "other"
    size_t sizeBytes = 0;
    std::string sha256;    // Hash of the file
    
    val012::json toJson() const {
        val012::json j;
        j["path"] = path;
        j["type"] = type;
        j["size_bytes"] = static_cast<long long>(sizeBytes);
        j["sha256"] = sha256;
        return j;
    }
};

/**
 * @struct BuildProvenance
 * Toolchain and environment information
 */
struct BuildProvenance {
    std::string mode = "real";           // "real" or "simulated"
    std::string tool = "cmake+ninja";    // Build tool used
    std::string cmakeVersion;
    std::string ninjaVersion;
    std::string compiler;
    std::string compilerVersion;
    std::string targetArchitecture;
    std::string buildType;               // Release, Debug, etc.
    
    val012::json toJson() const {
        val012::json j;
        j["mode"] = mode;
        j["tool"] = tool;
        j["cmake_version"] = cmakeVersion;
        j["ninja_version"] = ninjaVersion;
        j["compiler"] = compiler;
        j["compiler_version"] = compilerVersion;
        j["target_architecture"] = targetArchitecture;
        j["build_type"] = buildType;
        return j;
    }
};

/**
 * @struct RealBuildResult
 * Complete build execution result with provenance
 */
struct RealBuildResult {
    bool success = false;
    int exitCode = -1;
    std::chrono::milliseconds duration{0};
    std::string stdoutLog;
    std::string stderrLog;
    std::vector<BuildArtifact> artifacts;
    BuildProvenance provenance;
    
    val012::json toJson() const {
        val012::json j;
        j["success"] = success;
        j["exit_code"] = exitCode;
        j["duration_ms"] = static_cast<long long>(duration.count());
        j["stdout"] = stdoutLog;
        j["stderr"] = stderrLog;
        
        val012::json artifactsJson = val012::json::array();
        for (const auto& art : artifacts) {
            artifactsJson.push_back(art.toJson());
        }
        j["artifacts"] = artifactsJson;
        j["provenance"] = provenance.toJson();
        return j;
    }
};

/**
 * @class BuildExecutor
 * Executes real builds and captures all relevant data
 */
class BuildExecutor {
public:
    BuildExecutor();
    
    /**
     * Execute a real CMake/Ninja build
     * 
     * @param buildDir Directory containing build.ninja or CMakeCache.txt
     * @param target Specific target to build (empty for all)
     * @param config Release/Debug configuration
     * @return Complete build result with provenance
     */
    RealBuildResult execute(
        const std::string& buildDir,
        const std::string& target = "",
        const std::string& config = "Release");
    
    /**
     * Detect available build system (Ninja vs Make vs MSBuild)
     */
    std::string detectBuildSystem(const std::string& buildDir);
    
    /**
     * Collect build artifacts from output directory
     */
    std::vector<BuildArtifact> collectArtifacts(const std::string& buildDir);
    
    /**
     * Gather toolchain provenance information
     */
    BuildProvenance gatherProvenance(const std::string& buildDir);

private:
    std::string executeCommand(
        const std::string& cmd,
        const std::string& cwd,
        int& exitCode,
        std::string& stdoutOutput,
        std::string& stderrOutput);
    
    std::string computeSha256(const std::string& filePath);
    std::string getCMakeVersion();
    std::string getNinjaVersion();
    std::string getCompilerInfo();
};

} // namespace VAL012
} // namespace RawrXD
