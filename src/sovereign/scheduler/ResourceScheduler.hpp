// ============================================================================
// ResourceScheduler.hpp - CPU/GPU/RAM/Context/Tool Budgets per Agent
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <atomic>

namespace Sovereign {

// Resource types
enum class ResourceType {
    CPU_CORES,
    GPU_MEMORY,
    RAM,
    CONTEXT_TOKENS,
    TOOL_CALLS,
    DISK_IO,
    NETWORK_BANDWIDTH,
    TIME
};

// Resource budget
struct ResourceBudget {
    ResourceType type;
    uint64_t limit;
    uint64_t used;
    uint64_t peak;
    uint64_t period; // ms for rate limiting
};

// Agent resource allocation
struct AgentAllocation {
    std::string agentId;
    std::vector<ResourceBudget> budgets;
    uint64_t priority;
    bool isActive;
    uint64_t startTime;
    uint64_t cpuTimeMs;
    uint64_t memoryBytes;
};

// Resource scheduler
class ResourceScheduler {
public:
    ResourceScheduler();
    ~ResourceScheduler();

    bool Initialize();
    void Shutdown();

    bool RegisterAgent(const std::string& agentId, uint64_t priority = 2);
    bool UnregisterAgent(const std::string& agentId);
    bool SetBudget(const std::string& agentId, ResourceType type, uint64_t limit);

    bool Allocate(const std::string& agentId, ResourceType type, uint64_t amount);
    bool Release(const std::string& agentId, ResourceType type, uint64_t amount);
    uint64_t GetUsage(const std::string& agentId, ResourceType type) const;
    uint64_t GetLimit(const std::string& agentId, ResourceType type) const;
    uint64_t GetAvailable(const std::string& agentId, ResourceType type) const;

    bool CanAllocate(const std::string& agentId, ResourceType type, uint64_t amount) const;
    bool HasSufficientResources(const std::string& agentId) const;

    void SetGlobalLimit(ResourceType type, uint64_t limit);
    uint64_t GetGlobalUsage(ResourceType type) const;

    struct SchedulerStats {
        uint64_t totalAllocations;
        uint64_t deniedAllocations;
        uint64_t totalReleases;
        uint64_t agentsRegistered;
        uint64_t agentsStarved;
    };
    SchedulerStats GetStats() const;

private:
    struct AgentResources {
        std::string agentId;
        uint64_t priority;
        std::unordered_map<ResourceType, ResourceBudget> budgets;
        uint64_t startTime;
    };
    std::unordered_map<std::string, AgentResources> agents_;
    std::unordered_map<ResourceType, uint64_t> globalLimits_;
    std::unordered_map<ResourceType, uint64_t> globalUsage_;
    SchedulerStats stats_;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
