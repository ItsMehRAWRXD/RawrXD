/*===========================================================================
 * runtime_paths.hpp
 *
 * Runtime Path Resolution - No Hardcoded Paths
 *
 * All paths resolved relative to executable location via GetModuleFileName()
 * Eliminates dependency on D:\RawrXD\ or any source tree assumptions
 *
 * Usage:
 *   RuntimePaths paths;
 *   paths.Initialize();
 *   std::string kernelPath = paths.GetKernelsPath();
 *===========================================================================*/

#pragma once

#include <string>
#include <filesystem>

namespace RawrXD {
namespace Runtime {

class RuntimePaths {
public:
    RuntimePaths();
    ~RuntimePaths();

    // Initialize paths from executable location
    // Must be called before any other methods
    bool Initialize();

    // Path getters - all return absolute paths
    std::filesystem::path GetExecutablePath() const;
    std::filesystem::path GetRuntimeRoot() const;
    std::filesystem::path GetBinPath() const;
    std::filesystem::path GetKernelsPath() const;
    std::filesystem::path GetModelsPath() const;
    std::filesystem::path GetConfigPath() const;
    std::filesystem::path GetLogsPath() const;
    std::filesystem::path GetTelemetryPath() const;

    // Specific file paths
    std::filesystem::path GetKernelBinary(const std::string& name) const;
    std::filesystem::path GetConfigFile(const std::string& name) const;
    std::filesystem::path GetModelPath(const std::string& name) const;

    // Validate directory structure exists
    bool ValidateStructure() const;

    // Create missing directories
    bool EnsureDirectories() const;

    // Get path summary for logging
    std::string GetPathSummary() const;

private:
    std::filesystem::path m_exePath;
    std::filesystem::path m_runtimeRoot;
    bool m_initialized = false;

    // Platform-specific implementation
    bool ResolveExecutablePath();
};

// C API exports
extern "C" {
    __declspec(dllexport) const char* RawrXD_GetRuntimeRoot();
    __declspec(dllexport) const char* RawrXD_GetKernelsPath();
    __declspec(dllexport) const char* RawrXD_GetModelsPath();
    __declspec(dllexport) int RawrXD_ValidateRuntimeStructure();
}

} // namespace Runtime
} // namespace RawrXD
