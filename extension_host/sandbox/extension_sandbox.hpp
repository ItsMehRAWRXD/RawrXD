// extension_sandbox.hpp — Extension Sandbox Environment
#pragma once
#include <string>
#include <memory>
#include <functional>
#include <filesystem>

namespace RawrXD {
namespace ExtensionHost {

// ============================================================================
// Sandbox Configuration
// ============================================================================
struct SandboxConfig {
    bool enableFilesystemRead = true;
    bool enableFilesystemWrite = false;
    bool enableNetwork = false;
    bool enableTerminal = false;
    bool enableClipboard = false;
    bool enableProcessSpawn = false;
    bool enableDebugger = false;
    std::filesystem::path restrictedRoot;
    size_t maxMemoryBytes = 256 * 1024 * 1024; // 256MB
    int maxCpuPercent = 50;
    int maxFileSizeBytes = 10 * 1024 * 1024; // 10MB
};

// ============================================================================
// Sandbox Statistics
// ============================================================================
struct SandboxStats {
    size_t memoryUsedBytes = 0;
    size_t fileOperations = 0;
    size_t networkRequests = 0;
    size_t processSpawns = 0;
    int cpuUsagePercent = 0;
    bool exceededLimits = false;
};

// ============================================================================
// Extension Sandbox
// ============================================================================
class ExtensionSandbox {
public:
    ExtensionSandbox(const SandboxConfig& config);
    ~ExtensionSandbox();

    bool Initialize();
    void Shutdown();

    // File system operations (sandboxed)
    bool ReadFile(const std::filesystem::path& path, std::string& content);
    bool WriteFile(const std::filesystem::path& path, const std::string& content);
    bool DeleteFile(const std::filesystem::path& path);
    bool ListDirectory(const std::filesystem::path& path, std::vector<std::filesystem::path>& files);

    // Network operations (sandboxed)
    bool HttpGet(const std::string& url, std::string& response);
    bool HttpPost(const std::string& url, const std::string& body, std::string& response);

    // Process operations (sandboxed)
    bool SpawnProcess(const std::string& command, const std::vector<std::string>& args, int& exitCode);

    // Statistics
    SandboxStats GetStats() const { return m_stats; }
    bool HasExceededLimits() const { return m_stats.exceededLimits; }

    // Permission check
    bool CheckPermission(const std::string& operation) const;

private:
    bool ValidatePath(const std::filesystem::path& path) const;
    void TrackOperation(const std::string& operation);

    SandboxConfig m_config;
    SandboxStats m_stats;
    bool m_initialized = false;
};

} // namespace ExtensionHost
} // namespace RawrXD
