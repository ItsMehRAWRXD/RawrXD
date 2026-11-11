// ============================================================================
// sandbox.h — Agent Sandbox for Safe Tool Execution
// Win32 native implementation (no Qt dependency)
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <set>
#include <functional>
#include <memory>
#include <chrono>

namespace RawrXD {
namespace Sandbox {

// ============================================================================
// Sandbox Configuration
// ============================================================================
struct SandboxConfig {
    std::set<std::string> allowList;        // Allowed commands
    std::set<std::string> denyList;         // Denied commands
    std::set<std::string> allowedPaths;     // Allowed file paths
    std::set<std::string> deniedPaths;      // Denied file paths
    uint32_t timeoutMs = 30000;             // Command timeout
    uint32_t maxOutputSize = 10 * 1024 * 1024; // 10MB max output
    bool enableLogging = true;
    bool requireApproval = false;
};

// ============================================================================
// Execution Result
// ============================================================================
struct ExecutionResult {
    bool success = false;
    int exitCode = -1;
    std::string stdout_output;
    std::string stderr_output;
    std::string error;
    uint64_t durationMs = 0;
};

// ============================================================================
// Sandbox — Safe Command Execution
// ============================================================================
class Sandbox {
public:
    Sandbox();
    ~Sandbox();

    bool Initialize(const SandboxConfig& config);
    void Shutdown();

    // Command execution
    ExecutionResult Execute(const std::string& command, 
                            const std::vector<std::string>& arguments = {},
                            const std::string& workingDir = "");

    // File operations
    bool ReadFile(const std::string& path, std::string& content);
    bool WriteFile(const std::string& path, const std::string& content);
    bool DeleteFile(const std::string& path);
    bool CreateDirectory(const std::string& path);

    // Validation
    bool IsCommandAllowed(const std::string& command) const;
    bool IsPathAllowed(const std::string& path) const;
    std::string SanitizePath(const std::string& path) const;

    // Statistics
    uint64_t GetExecutionCount() const { return m_execCount; }
    uint64_t GetDeniedCount() const { return m_deniedCount; }

private:
    ExecutionResult ExecuteWindows(const std::string& command,
                                    const std::vector<std::string>& arguments,
                                    const std::string& workingDir);
    ExecutionResult ExecutePosix(const std::string& command,
                                  const std::vector<std::string>& arguments,
                                  const std::string& workingDir);

private:
    SandboxConfig m_config;
    uint64_t m_execCount = 0;
    uint64_t m_deniedCount = 0;
    bool m_initialized = false;
};

} // namespace Sandbox
} // namespace RawrXD
