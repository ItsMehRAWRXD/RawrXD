// ============================================================================
// AgentArbitration.cpp - Agent Arbitration & Conflict Resolution Implementation
// ============================================================================

#include "AgentArbitration.hpp"
#include <algorithm>
#include <iostream>

namespace Sovereign {

AgentArbitration::AgentArbitration() = default;
AgentArbitration::~AgentArbitration() {
    Shutdown();
}

bool AgentArbitration::Initialize() { return true; }
void AgentArbitration::Shutdown() { locks_.clear(); }

bool AgentArbitration::AcquireLock(const std::string& resource, LockType type, 
                                     const std::string& agentId, uint64_t timeoutMs) {
    std::unique_lock lock(mutex_);
    
    if (!CanAcquire(resource, type)) {
        stats_.conflicts++;
        return false;
    }
    
    ResourceLock rl;
    rl.resource = resource;
    rl.type = type;
    rl.agentId = agentId;
    rl.acquired = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    rl.timeout = timeoutMs;
    rl.isHeld = true;
    
    locks_[resource] = rl;
    stats_.totalLocks++;
    return true;
}

bool AgentArbitration::ReleaseLock(const std::string& resource, const std::string& agentId) {
    std::unique_lock lock(mutex_);
    auto it = locks_.find(resource);
    if (it == locks_.end() || it->second.agentId != agentId) return false;
    locks_.erase(it);
    return true;
}

bool AgentArbitration::IsLocked(const std::string& resource) const {
    std::shared_lock lock(mutex_);
    return locks_.find(resource) != locks_.end();
}

LockType AgentArbitration::GetLockType(const std::string& resource) const {
    std::shared_lock lock(mutex_);
    auto it = locks_.find(resource);
    return it != locks_.end() ? it->second.type : LockType::NONE;
}

std::string AgentArbitration::GetLockHolder(const std::string& resource) const {
    std::shared_lock lock(mutex_);
    auto it = locks_.find(resource);
    return it != locks_.end() ? it->second.agentId : "";
}

ArbitrationDecision AgentArbitration::ResolveConflict(const std::string& resource, 
                                                       const std::vector<std::string>& claimants) {
    std::unique_lock lock(mutex_);
    ArbitrationDecision decision;
    decision.resource = resource;
    decision.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Find highest priority claimant
    int bestPriority = INT_MAX;
    for (const auto& claimant : claimants) {
        auto it = priorities_.find(claimant);
        int p = it != priorities_.end() ? static_cast<int>(it->second) : static_cast<int>(ArbitrationPriority::NORMAL);
        if (p < bestPriority) {
            bestPriority = p;
            decision.winner = claimant;
        }
    }
    
    for (const auto& claimant : claimants) {
        if (claimant != decision.winner) {
            decision.losers.push_back(claimant);
        }
    }
    
    decision.priority = static_cast<ArbitrationPriority>(bestPriority);
    decision.reason = "Priority-based resolution";
    stats_.resolutions++;
    
    return decision;
}

bool AgentArbitration::CanAcquire(const std::string& resource, LockType type) const {
    auto it = locks_.find(resource);
    if (it == locks_.end()) return true;
    
    // Read locks can coexist
    if (type == LockType::READ && it->second.type == LockType::READ) return true;
    
    return false;
}

bool AgentArbitration::DetectDeadlock() const {
    std::shared_lock lock(mutex_);
    // Simplified deadlock detection
    return false;
}

AgentArbitration::ArbitrationStats AgentArbitration::GetStats() const {
    return stats_;
}

} // namespace Sovereign
