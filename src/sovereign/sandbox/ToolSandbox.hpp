// ============================================================================
// ToolSandbox.hpp - Tool Sandbox for Secure Tool Execution
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>
#include <unordered_map>

namespace Sovereign {

// Tool sandbox configuration
struct ToolSandboxConfig {
    bool enableTimeout = true;
    uint64_t defaultTimeoutMs = 30000;
    bool enableOutputLimit = true;
    size_t maxOutputBytes = 1048576; // 1MB
    bool enablePathRestriction = true;
    std::vector<std::string> allowedPaths;
    bool enableNetworkRestriction = false;
    std::vector<std::string> allowedDomains;
    bool enableRateLimiting = true;
    size_t maxCallsPerMinute = 60;
    bool enableAuditLogging = true;
    std::string auditLogPath = ".sovereign/audit.log";
};

// Tool execution context
struct ToolExecutionContext {
    std::string toolName;
    std::string arguments;
    std::string agentId;
    uint64_t sessionId;
    uint64_t timestamp;
    std::vector<std::string> allowedPaths;
};

// Tool execution result
struct ToolExecutionResult {
    bool success;
    std::string output;
    std::string error;
    uint64_t durationMs;
    bool timedOut;
    bool permissionDenied;
    size_t outputBytes;
};

// Tool sandbox
class ToolSandbox {
public:
    ToolSandbox();
    ~ToolSandbox();

    // Configuration
    void Configure(const ToolSandboxConfig& config);
    const ToolSandboxConfig& GetConfig() const { return config_; }

    // Execution with sandbox
    ToolExecutionResult Execute(
        const std::string& toolName,
        const std::string& arguments,
        const ToolExecutionContext& context
    );

    // Validation
    bool ValidateToolCall(const std::string& toolName, const std::string& arguments);
    bool ValidatePath(const std::string& path);
    bool ValidateOutput(const std::string& output);

    // Rate limiting
    bool CheckRateLimit(const std::string& agentId);
    void UpdateRateLimit(const std::string& agentId);

    // Audit logging
    void LogExecution(const ToolExecutionResult& result, const ToolExecutionContext& context);
    std::vector<std::string> GetAuditLog(uint64_t since = 0);

    // Statistics
    struct ToolSandboxStats {
        uint64_t totalExecutions = 0;
        uint64_t blockedExecutions = 0;
        uint64_t timedOutExecutions = 0;
        uint64_t permissionDenied = 0;
        uint64_t rateLimited = 0;
    };
    ToolSandboxStats GetStats() const;
    void ResetStats();

private:
    ToolSandboxConfig config_;
    ToolSandboxStats stats_;
    mutable std::mutex mutex_;
    
    // Rate limiting state
    struct RateLimitState {
        std::vector<uint64_t> callTimestamps;
    };
    std::unordered_map<std::string, RateLimitState> rateLimits_;
    
    // Audit log
    void WriteAuditLog(const std::string& entry);
};

} // namespace Sovereign
