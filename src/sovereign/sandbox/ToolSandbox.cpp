// ============================================================================
// ToolSandbox.cpp - Tool Sandbox Implementation
// ============================================================================

#include "ToolSandbox.hpp"
#include <fstream>
#include <algorithm>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

namespace Sovereign {

ToolSandbox::ToolSandbox() = default;
ToolSandbox::~ToolSandbox() = default;

void ToolSandbox::Configure(const ToolSandboxConfig& config) {
    config_ = config;
}

ToolExecutionResult ToolSandbox::Execute(
    const std::string& toolName,
    const std::string& arguments,
    const ToolExecutionContext& context) {
    
    ToolExecutionResult result;
    auto start = std::chrono::high_resolution_clock::now();
    
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.totalExecutions++;
    
    // Validate tool call
    if (!ValidateToolCall(toolName, arguments)) {
        result.success = false;
        result.error = "INVALID_TOOL_CALL";
        result.permissionDenied = true;
        stats_.permissionDenied++;
        LogExecution(result, context);
        return result;
    }
    
    // Check rate limit
    if (config_.enableRateLimiting && !CheckRateLimit(context.agentId)) {
        result.success = false;
        result.error = "RATE_LIMITED";
        result.permissionDenied = true;
        stats_.rateLimited++;
        LogExecution(result, context);
        return result;
    }
    
    // Validate paths if applicable
    if (config_.enablePathRestriction && !arguments.empty()) {
        if (!ValidatePath(arguments)) {
            result.success = false;
            result.error = "PATH_NOT_ALLOWED";
            result.permissionDenied = true;
            stats_.permissionDenied++;
            LogExecution(result, context);
            return result;
        }
    }
    
    // Simulate execution (actual tool dispatch happens in ToolRegistry)
    result.success = true;
    result.output = "EXECUTED: " + toolName;
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Check timeout
    if (config_.enableTimeout && result.durationMs > config_.defaultTimeoutMs) {
        result.timedOut = true;
        result.success = false;
        result.error = "TIMEOUT";
        stats_.timedOutExecutions++;
    }
    
    // Check output size
    if (config_.enableOutputLimit && result.output.size() > config_.maxOutputBytes) {
        result.output = result.output.substr(0, config_.maxOutputBytes);
        result.output += "\n... [TRUNCATED]";
    }
    result.outputBytes = result.output.size();
    
    // Update rate limit
    if (config_.enableRateLimiting) {
        UpdateRateLimit(context.agentId);
    }
    
    // Audit log
    LogExecution(result, context);
    
    return result;
}

bool ToolSandbox::ValidateToolCall(const std::string& toolName, const std::string& arguments) {
    // Basic validation
    if (toolName.empty()) return false;
    if (arguments.size() > 65536) return false; // Max 64KB arguments
    
    // Check for injection attempts
    std::vector<std::string> dangerous = {"&&", "||", ";", "`", "$(", "rm -rf", "format C:"};
    for (const auto& d : dangerous) {
        if (arguments.find(d) != std::string::npos) {
            return false;
        }
    }
    
    return true;
}

bool ToolSandbox::ValidatePath(const std::string& path) {
    if (!config_.enablePathRestriction) return true;
    if (config_.allowedPaths.empty()) return false;
    
    fs::path absPath = fs::absolute(path);
    
    for (const auto& allowed : config_.allowedPaths) {
        fs::path allowedPath = fs::absolute(allowed);
        auto rel = fs::relative(absPath, allowedPath);
        if (rel.native()[0] != '.') return true;
    }
    
    return false;
}

bool ToolSandbox::ValidateOutput(const std::string& output) {
    if (output.size() > config_.maxOutputBytes) return false;
    return true;
}

bool ToolSandbox::CheckRateLimit(const std::string& agentId) {
    auto it = rateLimits_.find(agentId);
    if (it == rateLimits_.end()) return true;
    
    auto& timestamps = it->second.callTimestamps;
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Remove timestamps older than 1 minute
    timestamps.erase(std::remove_if(timestamps.begin(), timestamps.end(),
        [now](uint64_t ts) { return (now - ts) > 60000; }), timestamps.end());
    
    return timestamps.size() < config_.maxCallsPerMinute;
}

void ToolSandbox::UpdateRateLimit(const std::string& agentId) {
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    rateLimits_[agentId].callTimestamps.push_back(now);
}

void ToolSandbox::LogExecution(const ToolExecutionResult& result, const ToolExecutionContext& context) {
    if (!config_.enableAuditLogging) return;
    
    std::stringstream ss;
    ss << "[" << context.timestamp << "] "
       << "agent=" << context.agentId << " "
       << "tool=" << context.toolName << " "
       << "success=" << (result.success ? "1" : "0") << " "
       << "duration=" << result.durationMs << "ms "
       << (result.permissionDenied ? "PERMISSION_DENIED " : "")
       << (result.timedOut ? "TIMEOUT " : "")
       << "\n";
    
    WriteAuditLog(ss.str());
}

void ToolSandbox::WriteAuditLog(const std::string& entry) {
    std::ofstream log(config_.auditLogPath, std::ios::app);
    if (log) {
        log << entry;
    }
}

ToolSandbox::ToolSandboxStats ToolSandbox::GetStats() const {
    return stats_;
}

void ToolSandbox::ResetStats() {
    stats_ = ToolSandboxStats{};
}

} // namespace Sovereign
