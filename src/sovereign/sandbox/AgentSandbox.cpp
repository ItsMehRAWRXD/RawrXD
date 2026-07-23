// ============================================================================
// AgentSandbox.cpp - Agent Sandbox Implementation
// ============================================================================

#include "AgentSandbox.hpp"
#include <algorithm>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

namespace Sovereign {

AgentSandbox::AgentSandbox() = default;
AgentSandbox::~AgentSandbox() {
    TerminateAll();
}

void AgentSandbox::Configure(const SandboxConfig& config) {
    config_ = config;
}

bool AgentSandbox::Execute(const std::string& agentId, const std::string& tool,
                          const std::string& args, std::string& output) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.totalExecutions++;
    
    // Check permission
    if (!CheckPermission(agentId, tool)) {
        stats_.blockedExecutions++;
        output = "PERMISSION_DENIED: " + tool;
        return false;
    }
    
    // Track agent state
    auto& state = agents_[agentId];
    state.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    state.activeTools.push_back(tool);
    
    // Check timeout
    if (IsTimedOut(agentId)) {
        stats_.timeViolations++;
        output = "TIMEOUT";
        return false;
    }
    
    output = "EXECUTED: " + tool;
    return true;
}

bool AgentSandbox::CheckPermission(const std::string& agentId, const std::string& tool) {
    if (config_.allowedTools.empty()) return true;
    return std::find(config_.allowedTools.begin(), config_.allowedTools.end(), tool) != config_.allowedTools.end();
}

bool AgentSandbox::CheckFileAccess(const std::string& path) {
    if (!config_.enableFilesystemIsolation) return true;
    if (config_.allowedPaths.empty()) return false;
    
    fs::path absPath = fs::absolute(path);
    for (const auto& allowed : config_.allowedPaths) {
        fs::path allowedPath = fs::absolute(allowed);
        auto rel = fs::relative(absPath, allowedPath);
        if (rel.native()[0] != '.') return true;
    }
    
    stats_.filesystemViolations++;
    return false;
}

bool AgentSandbox::CheckNetworkAccess(const std::string& domain) {
    if (!config_.enableNetworkIsolation) return true;
    if (config_.allowedDomains.empty()) return false;
    
    for (const auto& allowed : config_.allowedDomains) {
        if (domain.find(allowed) != std::string::npos) return true;
    }
    
    stats_.networkViolations++;
    return false;
}

bool AgentSandbox::CheckMemoryLimit(size_t bytes) {
    if (!config_.enableMemoryLimits) return true;
    if (bytes > config_.maxMemoryMB * 1024 * 1024) {
        stats_.memoryViolations++;
        return false;
    }
    return true;
}

void AgentSandbox::TrackAllocation(const std::string& agentId, size_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& state = agents_[agentId];
    state.memoryBytes += bytes;
    stats_.peakMemoryBytes = std::max(stats_.peakMemoryBytes, state.memoryBytes);
}

void AgentSandbox::TrackDeallocation(const std::string& agentId, size_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& state = agents_[agentId];
    state.memoryBytes = state.memoryBytes > bytes ? state.memoryBytes - bytes : 0;
}

size_t AgentSandbox::GetAgentMemoryUsage(const std::string& agentId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = agents_.find(agentId);
    return it != agents_.end() ? it->second.memoryBytes : 0;
}

void AgentSandbox::SetTimeout(const std::string& agentId, uint64_t ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    agents_[agentId].timeoutMs = ms;
}

bool AgentSandbox::IsTimedOut(const std::string& agentId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = agents_.find(agentId);
    if (it == agents_.end()) return false;
    if (it->second.timeoutMs == 0) return false;
    
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return (now - it->second.startTime) > it->second.timeoutMs;
}

SandboxStats AgentSandbox::GetStats() const {
    return stats_;
}

void AgentSandbox::ResetStats() {
    stats_ = SandboxStats{};
}

void AgentSandbox::TerminateAgent(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    agents_.erase(agentId);
}

void AgentSandbox::TerminateAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    agents_.clear();
}

} // namespace Sovereign
