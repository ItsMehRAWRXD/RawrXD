// ============================================================================
// AgentSandbox.hpp - Agent Sandbox for Secure Execution
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {

// Sandbox configuration
struct SandboxConfig {
    bool enableProcessIsolation = true;
    bool enableMemoryLimits = true;
    bool enableNetworkIsolation = true;
    bool enableFilesystemIsolation = true;
    size_t maxMemoryMB = 1024;
    size_t maxCPUTimeMs = 30000;
    std::vector<std::string> allowedPaths;
    std::vector<std::string> allowedDomains;
    std::vector<std::string> allowedTools;
    std::string tempDirectory;
};

// Sandbox statistics
struct SandboxStats {
    uint64_t totalExecutions = 0;
    uint64_t blockedExecutions = 0;
    uint64_t memoryViolations = 0;
    uint64_t networkViolations = 0;
    uint64_t filesystemViolations = 0;
    uint64_t timeViolations = 0;
    size_t peakMemoryBytes = 0;
};

// Resource limits
struct ResourceLimits {
    size_t maxMemoryBytes;
    uint64_t maxCPUTimeNs;
    size_t maxFileSizeBytes;
    size_t maxOpenFiles;
    size_t maxChildProcesses;
};

// Sandboxed agent execution
class AgentSandbox {
public:
    AgentSandbox();
    ~AgentSandbox();

    // Configuration
    void Configure(const SandboxConfig& config);
    const SandboxConfig& GetConfig() const { return config_; }

    // Execution
    bool Execute(const std::string& agentId, 
                 const std::string& tool,
                 const std::string& args,
                 std::string& output);
    
    bool ExecuteAsync(const std::string& agentId,
                      const std::string& tool,
                      const std::string& args,
                      std::function<void(bool, const std::string&)> callback);

    // Permission checks
    bool CheckPermission(const std::string& agentId, const std::string& tool);
    bool CheckFileAccess(const std::string& path);
    bool CheckNetworkAccess(const std::string& domain);
    bool CheckMemoryLimit(size_t bytes);

    // Resource tracking
    void TrackAllocation(const std::string& agentId, size_t bytes);
    void TrackDeallocation(const std::string& agentId, size_t bytes);
    size_t GetAgentMemoryUsage(const std::string& agentId) const;

    // Timeout management
    void SetTimeout(const std::string& agentId, uint64_t ms);
    bool IsTimedOut(const std::string& agentId) const;

    // Statistics
    SandboxStats GetStats() const;
    void ResetStats();

    // Cleanup
    void TerminateAgent(const std::string& agentId);
    void TerminateAll();

private:
    SandboxConfig config_;
    SandboxStats stats_;
    mutable std::mutex mutex_;
    
    struct AgentState {
        size_t memoryBytes = 0;
        uint64_t startTime = 0;
        uint64_t timeoutMs = 0;
        std::vector<std::string> activeTools;
    };
    std::unordered_map<std::string, AgentState> agents_;
    
    bool ValidatePath(const std::string& path) const;
    bool ValidateDomain(const std::string& domain) const;
};

} // namespace Sovereign
