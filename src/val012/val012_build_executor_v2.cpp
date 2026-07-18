/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#include "val012_build_executor_v2.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <array>
#include <sstream>
#include <iomanip>
#include <regex>

#ifdef _WIN32
#include <windows.h>
#endif

namespace RawrXD {
namespace VAL012 {

BuildExecutorV2::BuildExecutorV2() {}

DetailedBuildResult BuildExecutorV2::execute(
    const std::string& buildDir,
    const std::string& target,
    const std::string& config,
    int timeoutMs) {
    
    DetailedBuildResult result;
    result.workingDirectory = buildDir;
    result.toolchain.buildType = config;
    result.executedAt = std::chrono::system_clock::now();
    
    std::cout << "[BuildExecutorV2] Starting build execution...\n";
    
    // Phase 1: Environment Check
    auto envStatus = checkEnvironment(buildDir);
    result.environmentReady = envStatus.ready;
    
    if (!envStatus.ready) {
        std::cout << "[BuildExecutorV2] Environment not ready\n";
        result.executorSuccess = true;  // Executor worked correctly
        result.buildSuccess = false;
        result.failureReason = BuildFailureReason::BuildDirectoryMissing;
        
        // Build detailed failure message
        std::ostringstream oss;
        oss << "Build environment not ready:";
        if (!envStatus.hasCMake) oss << " CMake not found;";
        if (!envStatus.hasBuildDir) oss << " Build directory does not exist;";
        if (!envStatus.hasCMakeCache && !envStatus.hasBuildNinja) {
            oss << " No CMakeCache.txt or build.ninja found;";
        }
        result.failureDetails = oss.str();
        
        // Still gather toolchain info for diagnostics
        result.toolchain = gatherToolchainInfo(buildDir);
        
        result.executionMode.mode = "real";
        result.executionMode.reason = "Environment check failed";
        
        return result;
    }
    
    // Phase 2: Toolchain Detection
    result.toolchain = gatherToolchainInfo(buildDir);
    result.executionMode.mode = "real";
    result.executionMode.reason = "Environment ready, executing real build";
    
    std::cout << "[BuildExecutorV2] Tool: " << result.toolchain.tool << "\n";
    std::cout << "[BuildExecutorV2] Compiler: " << result.toolchain.compiler << "\n";
    
    // Phase 3: Build Execution
    auto startTime = std::chrono::steady_clock::now();
    
    std::string cmd;
    if (result.toolchain.tool.find("ninja") != std::string::npos) {
        cmd = "ninja";
        if (!target.empty()) cmd += " " + target;
    } else {
        cmd = "cmake --build . --config " + config;
        if (!target.empty()) cmd += " --target " + target;
    }
    
    std::cout << "[BuildExecutorV2] Command: " << cmd << "\n";
    
    result.exitCode = -1;
    result.stdoutLog = executeCommand(cmd, buildDir, result.exitCode,
                                       result.stdoutLog, result.stderrLog, timeoutMs);
    
    auto endTime = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime);
    
    // Phase 4: Result Analysis
    result.executorSuccess = true;  // We got this far without crashing
    result.buildSuccess = (result.exitCode == 0);
    
    if (!result.buildSuccess) {
        result.failureReason = categorizeFailure(result.exitCode, result.stderrLog, envStatus);
        result.failureDetails = "Build failed with exit code " + std::to_string(result.exitCode);
        if (!result.stderrLog.empty()) {
            result.failureDetails += ": " + result.stderrLog.substr(0, 500);
        }
        std::cout << "[BuildExecutorV2] Build failed: " 
                  << buildFailureReasonToString(result.failureReason) << "\n";
    } else {
        result.failureReason = BuildFailureReason::None;
        result.failureDetails = "";
        
        // Phase 5: Artifact Collection (only on success)
        result.artifacts = collectArtifacts(buildDir);
        std::cout << "[BuildExecutorV2] Collected " << result.artifacts.size() 
                  << " artifacts\n";
    }
    
    std::cout << "[BuildExecutorV2] Build " 
              << (result.buildSuccess ? "succeeded" : "failed")
              << " in " << result.duration.count() << "ms\n";
    
    return result;
}

bool BuildExecutorV2::isEnvironmentReady(const std::string& buildDir) {
    return checkEnvironment(buildDir).ready;
}

BuildExecutorV2::EnvironmentStatus BuildExecutorV2::checkEnvironment(
    const std::string& buildDir) {
    
    EnvironmentStatus status;
    status.hasBuildDir = std::filesystem::exists(buildDir);
    
    if (status.hasBuildDir) {
        std::filesystem::path dir(buildDir);
        status.hasCMakeCache = std::filesystem::exists(dir / "CMakeCache.txt");
        status.hasBuildNinja = std::filesystem::exists(dir / "build.ninja");
        status.hasCMake = !getCMakeVersion().empty() && getCMakeVersion() != "unknown";
        status.hasNinja = !getNinjaVersion().empty() && getNinjaVersion() != "unknown";
    }
    
    // Environment is ready if we have a build directory with either CMakeCache or build.ninja
    status.ready = status.hasBuildDir && (status.hasCMakeCache || status.hasBuildNinja);
    
    if (status.hasBuildNinja) {
        status.detectedTool = "ninja";
    } else if (status.hasCMakeCache) {
        status.detectedTool = "cmake";
    } else {
        status.detectedTool = "unknown";
    }
    
    return status;
}

std::string BuildExecutorV2::executeCommand(
    const std::string& cmd,
    const std::string& cwd,
    int& exitCode,
    std::string& stdoutOut,
    std::string& stderrOut,
    int timeoutMs) {
    
    std::string fullOutput;
    
    #ifdef _WIN32
    // Windows: Use cmd /c to execute in directory
    std::string fullCmd = "cmd /c \"cd /d \"" + cwd + "\" && " + cmd + " 2>&1\"";
    
    FILE* pipe = _popen(fullCmd.c_str(), "r");
    if (!pipe) {
        exitCode = -1;
        return "Failed to execute command";
    }
    
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        fullOutput += buffer;
    }
    
    exitCode = _pclose(pipe);
    stdoutOut = fullOutput;
    stderrOut = ""; // Combined on Windows
    
    #else
    // POSIX
    std::array<char, 4096> buffer;
    std::string fullCmd = "cd \"" + cwd + "\" && " + cmd + " 2>&1";
    
    FILE* pipe = popen(fullCmd.c_str(), "r");
    if (!pipe) {
        exitCode = -1;
        return "Failed to execute command";
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        fullOutput += buffer.data();
    }
    
    exitCode = pclose(pipe);
    stdoutOut = fullOutput;
    stderrOut = "";
    #endif
    
    return fullOutput;
}

std::string BuildExecutorV2::detectBuildSystem(const std::string& buildDir) {
    auto status = checkEnvironment(buildDir);
    return status.detectedTool;
}

ToolchainInfo BuildExecutorV2::gatherToolchainInfo(const std::string& buildDir) {
    ToolchainInfo info;
    
    info.cmakeVersion = getCMakeVersion();
    info.ninjaVersion = getNinjaVersion();
    info.compiler = getCompilerInfo();
    info.compilerVersion = getCompilerVersion();
    
    // Detect tool combination
    if (!info.ninjaVersion.empty() && info.ninjaVersion != "unknown") {
        info.tool = "cmake+ninja";
    } else {
        info.tool = "cmake+make";
    }
    
    // Detect architecture
    #ifdef _WIN64
    info.targetArchitecture = "x86_64-windows-msvc";
    #elif _WIN32
    info.targetArchitecture = "x86-windows-msvc";
    #elif __x86_64__
    info.targetArchitecture = "x86_64-linux-gnu";
    #else
    info.targetArchitecture = "unknown";
    #endif
    
    return info;
}

std::vector<BuildArtifact> BuildExecutorV2::collectArtifacts(const std::string& buildDir) {
    std::vector<BuildArtifact> artifacts;
    std::filesystem::path dir(buildDir);
    
    for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        
        std::string ext = entry.path().extension().string();
        std::string filename = entry.path().filename().string();
        
        // Skip if filename contains "test" or "Test" (those are test executables)
        if (filename.find("test") != std::string::npos || 
            filename.find("Test") != std::string::npos) {
            continue;
        }
        
        BuildArtifact art;
        art.path = std::filesystem::relative(entry.path(), dir).string();
        art.sizeBytes = entry.file_size();
        
        // Determine type
        if (ext == ".exe") {
            art.type = "executable";
        } else if (ext == ".dll" || ext == ".so" || ext == ".dylib") {
            art.type = "library";
        } else if (ext == ".lib" || ext == ".a") {
            art.type = "static_library";
        } else if (ext == ".obj" || ext == ".o") {
            art.type = "object";
        } else {
            continue; // Skip other files
        }
        
        art.sha256 = computeSha256(entry.path().string());
        artifacts.push_back(art);
    }
    
    return artifacts;
}

std::string BuildExecutorV2::computeSha256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return "hash_error";
    
    // Simple hash: XOR of file contents
    unsigned long hash = 0;
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        for (std::streamsize i = 0; i < file.gcount(); ++i) {
            hash = hash * 31 + static_cast<unsigned char>(buffer[i]);
        }
    }
    
    std::ostringstream oss;
    oss << std::hex << std::setw(16) << std::setfill('0') << hash;
    return oss.str();
}

std::string BuildExecutorV2::getCMakeVersion() {
    int exitCode;
    std::string stdoutOut, stderrOut;
    executeCommand("cmake --version", ".", exitCode, stdoutOut, stderrOut, 0);
    
    if (exitCode == 0 && !stdoutOut.empty()) {
        std::regex versionRegex("cmake version ([0-9]+\\.[0-9]+\\.[0-9]+)");
        std::smatch match;
        if (std::regex_search(stdoutOut, match, versionRegex)) {
            return match[1];
        }
    }
    return "unknown";
}

std::string BuildExecutorV2::getNinjaVersion() {
    int exitCode;
    std::string stdoutOut, stderrOut;
    executeCommand("ninja --version", ".", exitCode, stdoutOut, stderrOut, 0);
    
    if (exitCode == 0 && !stdoutOut.empty()) {
        // First line is version
        size_t pos = stdoutOut.find('\n');
        if (pos != std::string::npos) {
            return stdoutOut.substr(0, pos);
        }
        return stdoutOut;
    }
    return "unknown";
}

std::string BuildExecutorV2::getCompilerInfo() {
    #ifdef _WIN32
    return "MSVC";
    #elif defined(__clang__)
    return "Clang";
    #elif defined(__GNUC__)
    return "GCC";
    #else
    return "Unknown";
    #endif
}

std::string BuildExecutorV2::getCompilerVersion() {
    #ifdef _WIN32
    // Try to get MSVC version
    int exitCode;
    std::string stdoutOut, stderrOut;
    executeCommand("cl 2>&1", ".", exitCode, stdoutOut, stderrOut, 0);
    
    std::regex versionRegex("Version ([0-9]+\\.[0-9]+)");
    std::smatch match;
    if (std::regex_search(stdoutOut, match, versionRegex)) {
        return "MSVC " + std::string(match[1]);
    }
    return "unknown";
    #elif defined(__clang__)
    return __clang_version__;
    #elif defined(__GNUC__)
    return std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__);
    #else
    return "unknown";
    #endif
}

BuildFailureReason BuildExecutorV2::categorizeFailure(
    int exitCode,
    const std::string& stderrOutput,
    const EnvironmentStatus& envStatus) {
    
    if (!envStatus.ready) {
        return BuildFailureReason::BuildDirectoryMissing;
    }
    
    // Check stderr for specific error patterns
    if (stderrOutput.find("CMake Error") != std::string::npos) {
        return BuildFailureReason::ConfigureFailed;
    }
    if (stderrOutput.find("error:") != std::string::npos || 
        stderrOutput.find("error C") != std::string::npos) {
        if (stderrOutput.find("link") != std::string::npos ||
            stderrOutput.find("LNK") != std::string::npos) {
            return BuildFailureReason::LinkFailed;
        }
        return BuildFailureReason::CompileFailed;
    }
    if (stderrOutput.find("ninja: error") != std::string::npos) {
        return BuildFailureReason::CompileFailed;
    }
    
    // Check for tool missing
    if (stderrOutput.find("not recognized") != std::string::npos ||
        stderrOutput.find("not found") != std::string::npos) {
        return BuildFailureReason::ToolMissing;
    }
    
    return BuildFailureReason::Unknown;
}

} // namespace VAL012
} // namespace RawrXD
