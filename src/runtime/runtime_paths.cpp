/*===========================================================================
 * runtime_paths.cpp
 *
 * Runtime Path Resolution Implementation
 *
 * All paths resolved relative to executable location
 * No dependency on build environment or source tree
 *===========================================================================*/

#include "runtime_paths.hpp"
#include <iostream>
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#endif

namespace RawrXD {
namespace Runtime {

RuntimePaths::RuntimePaths() = default;
RuntimePaths::~RuntimePaths() = default;

bool RuntimePaths::Initialize() {
    if (m_initialized) return true;

    if (!ResolveExecutablePath()) {
        return false;
    }

    // Runtime root is parent of bin directory
    // Expected: bin/RawrXD_Engine.exe -> runtime root is parent
    m_runtimeRoot = m_exePath.parent_path().parent_path();

    // If running from bin directory, use parent
    // If running standalone, use current directory
    if (m_exePath.parent_path().filename() == "bin") {
        m_runtimeRoot = m_exePath.parent_path().parent_path();
    } else {
        m_runtimeRoot = m_exePath.parent_path();
    }

    m_initialized = true;
    return true;
}

bool RuntimePaths::ResolveExecutablePath() {
#ifdef _WIN32
    wchar_t buffer[MAX_PATH];
    DWORD result = GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (result == 0 || result == MAX_PATH) {
        return false;
    }
    m_exePath = std::filesystem::path(buffer);
#else
    char buffer[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len == -1) {
        return false;
    }
    buffer[len] = '\0';
    m_exePath = std::filesystem::path(buffer);
#endif
    return true;
}

std::filesystem::path RuntimePaths::GetExecutablePath() const {
    return m_exePath;
}

std::filesystem::path RuntimePaths::GetRuntimeRoot() const {
    return m_runtimeRoot;
}

std::filesystem::path RuntimePaths::GetBinPath() const {
    return m_runtimeRoot / "bin";
}

std::filesystem::path RuntimePaths::GetKernelsPath() const {
    return m_runtimeRoot / "runtime" / "kernels";
}

std::filesystem::path RuntimePaths::GetModelsPath() const {
    return m_runtimeRoot / "models";
}

std::filesystem::path RuntimePaths::GetConfigPath() const {
    return m_runtimeRoot / "config";
}

std::filesystem::path RuntimePaths::GetLogsPath() const {
    return m_runtimeRoot / "logs";
}

std::filesystem::path RuntimePaths::GetTelemetryPath() const {
    return GetLogsPath() / "telemetry";
}

std::filesystem::path RuntimePaths::GetKernelBinary(const std::string& name) const {
    return GetKernelsPath() / (name + ".bin");
}

std::filesystem::path RuntimePaths::GetConfigFile(const std::string& name) const {
    return GetConfigPath() / (name + ".json");
}

std::filesystem::path RuntimePaths::GetModelPath(const std::string& name) const {
    return GetModelsPath() / name;
}

bool RuntimePaths::ValidateStructure() const {
    if (!m_initialized) return false;

    // Check required directories
    std::vector<std::filesystem::path> requiredDirs = {
        GetRuntimeRoot(),
        GetBinPath(),
        GetKernelsPath(),
        GetModelsPath(),
        GetConfigPath(),
        GetLogsPath(),
        GetTelemetryPath()
    };

    for (const auto& dir : requiredDirs) {
        if (!std::filesystem::exists(dir)) {
            return false;
        }
        if (!std::filesystem::is_directory(dir)) {
            return false;
        }
    }

    return true;
}

bool RuntimePaths::EnsureDirectories() const {
    if (!m_initialized) return false;

    std::vector<std::filesystem::path> dirs = {
        GetRuntimeRoot(),
        GetBinPath(),
        GetKernelsPath(),
        GetModelsPath(),
        GetConfigPath(),
        GetLogsPath(),
        GetTelemetryPath()
    };

    try {
        for (const auto& dir : dirs) {
            if (!std::filesystem::exists(dir)) {
                std::filesystem::create_directories(dir);
            }
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::string RuntimePaths::GetPathSummary() const {
    std::stringstream ss;
    ss << "Runtime Paths:\n";
    ss << "  Executable: " << GetExecutablePath().string() << "\n";
    ss << "  Runtime Root: " << GetRuntimeRoot().string() << "\n";
    ss << "  Bin: " << GetBinPath().string() << "\n";
    ss << "  Kernels: " << GetKernelsPath().string() << "\n";
    ss << "  Models: " << GetModelsPath().string() << "\n";
    ss << "  Config: " << GetConfigPath().string() << "\n";
    ss << "  Logs: " << GetLogsPath().string() << "\n";
    ss << "  Telemetry: " << GetTelemetryPath().string() << "\n";
    return ss.str();
}

// C API exports
static RuntimePaths g_runtimePaths;

extern "C" {

__declspec(dllexport) const char* RawrXD_GetRuntimeRoot() {
    if (!g_runtimePaths.Initialize()) {
        return nullptr;
    }
    static std::string path = g_runtimePaths.GetRuntimeRoot().string();
    return path.c_str();
}

__declspec(dllexport) const char* RawrXD_GetKernelsPath() {
    if (!g_runtimePaths.Initialize()) {
        return nullptr;
    }
    static std::string path = g_runtimePaths.GetKernelsPath().string();
    return path.c_str();
}

__declspec(dllexport) const char* RawrXD_GetModelsPath() {
    if (!g_runtimePaths.Initialize()) {
        return nullptr;
    }
    static std::string path = g_runtimePaths.GetModelsPath().string();
    return path.c_str();
}

__declspec(dllexport) int RawrXD_ValidateRuntimeStructure() {
    if (!g_runtimePaths.Initialize()) {
        return -1;
    }
    return g_runtimePaths.ValidateStructure() ? 0 : 1;
}

} // extern "C"

} // namespace Runtime
} // namespace RawrXD
