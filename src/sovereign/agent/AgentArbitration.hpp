// ============================================================================
// AgentArbitration.hpp - Agent Arbitration & Conflict Resolution
// Supervisor decides priority, locks files, prevents conflicting patches
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <shared_mutex>

namespace Sovereign {

// Arbitration priority
enum class ArbitrationPriority {
    CRITICAL = 0,
    HIGH = 1,
    NORMAL = 2,
    LOW = 3,
    BACKGROUND = 4
};

// Lock type
enum class LockType {
    NONE,
    READ,
    WRITE,
    EXCLUSIVE
};

// Resource lock
struct ResourceLock {
    std::string resource;
    LockType type;
    std::string agentId;
    uint64_t acquired;
    uint64_t timeout;
    bool isHeld;
};

// Arbitration decision
struct ArbitrationDecision {
    std::string winner;
    std::vector<std::string> losers;
    std::string resource;
    std::string reason;
    ArbitrationPriority priority;
    uint64_t timestamp;
};

// Agent arbitration system
class AgentArbitration {
public:
    AgentArbitration();
    ~AgentArbitration();

    bool Initialize();
    void Shutdown();

    // Lock management
    bool AcquireLock(const std::string& resource, LockType type, const std::string& agentId, uint64_t timeoutMs = 5000);
    bool ReleaseLock(const std::string& resource, const std::string& agentId);
    bool IsLocked(const std::string& resource) const;
    LockType GetLockType(const std::string& resource) const;
    std::string GetLockHolder(const std::string& resource) const;

    // Conflict resolution
    ArbitrationDecision ResolveConflict(const std::string& resource, const std::vector<std::string>& claimants);
    bool CanProceed(const std::string& agentId, const std::string& resource) const;

    // Priority management
    void SetAgentPriority(const std::string& agentId, ArbitrationPriority priority);
    ArbitrationPriority GetAgentPriority(const std::string& agentId) const;

    // Deadlock detection
    bool DetectDeadlock() const;
    std::vector<std::vector<std::string>> GetWaitChains() const;
    bool BreakDeadlock(const std::string& victim);

    // Statistics
    struct ArbitrationStats {
        uint64_t totalLocks;
        uint64_t conflicts;
        uint64_t deadlocks;
        uint64_t resolutions;
        uint64_t preemptions;
    };
    ArbitrationStats GetStats() const;
    void ResetStats();

private:
    std::unordered_map<std::string, ResourceLock> locks_;
    std::unordered_map<std::string, ArbitrationPriority> priorities_;
    ArbitrationStats stats_;
    mutable std::shared_mutex mutex_;
    
    bool CanAcquire(const std::string& resource, LockType type) const;
    void ResolveByPriority(const std::string& resource, const std::vector<std::string>& claimants);
};

} // namespace Sovereign
