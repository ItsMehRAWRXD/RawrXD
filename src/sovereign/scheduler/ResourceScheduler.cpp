// ============================================================================
// ResourceScheduler.cpp - CPU/GPU/RAM/Context/Tool Budgets Implementation
// ============================================================================

#include "ResourceScheduler.hpp"
#include <algorithm>
#include <iostream>

namespace Sovereign {

ResourceScheduler::ResourceScheduler() = default;
ResourceScheduler::~ResourceScheduler() = default;

bool ResourceScheduler::Initialize() {
    // Set default global limits
    globalLimits_[ResourceType::CPU_CORES] = std::thread::hardware_concurrency();
    globalLimits_[ResourceType::RAM] = 16ULL * 1024 * 1024 * 1024; // 16GB
    globalLimits_[ResourceType::CONTEXT_TOKENS] = 128000;
    globalLimits_[ResourceType::TOOL_CALLS] = 1000;
    globalLimits_[ResourceType::TIME] = 3600000; // 1 hour
    return true;
}

void ResourceScheduler::Shutdown() {
    agents_.clear();
}

bool ResourceScheduler::RegisterAgent(const std::string& agentId, uint64_t priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    AgentResources res;
    res.agentId = agentId;
    res.priority = priority;
    res.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Set default budgets
    for (auto& [type, limit] : globalLimits_) {
        ResourceBudget budget;
        budget.type = type;
        budget.limit = limit / 4; // Default: 25% of global
        budget.used = 0;
        budget.peak = 0;
        budget.period = 60000; // 1 minute
        res.budgets[type] = budget;
    }
    
    agents_[agentId] = res;
    stats_.agentsRegistered++;
    return true;
}

bool ResourceScheduler::UnregisterAgent(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return agents_.erase(agentId) > 0;
}

bool ResourceScheduler::SetBudget(const std::string& agentId, ResourceType type, uint64_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = agents_.find(agentId);
    if (it == agents_.end()) return false;
    it->second.budgets[type].limit = limit;
    return true;
}

bool ResourceScheduler::Allocate(const std::string& agentId, ResourceType type, uint64_t amount) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = agents_.find(agentId);
    if (it == agents_.end()) return false;
    
    auto& budget = it->second.budgets[type];
    if (budget.used + amount > budget.limit) {
        stats_.deniedAllocations++;
        return false;
    }
    
    budget.used += amount;
    budget.peak = std::max(budget.peak, budget.used);
    globalUsage_[type] += amount;
    stats_.totalAllocations++;
    return true;
}

bool ResourceScheduler::Release(const std::string& agentId, ResourceType type, uint64_t amount) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = agents_.find(agentId);
    if (it == agents_.end()) return false;
    
    auto& budget = it->second.budgets[type];
    budget.used = budget.used > amount ? budget.used - amount : 0;
    globalUsage_[type] = globalUsage_[type] > amount ? globalUsage_[type] - amount : 0;
    stats_.totalReleases++;
    return true;
}

uint64_t ResourceScheduler::GetUsage(const std::string& agentId, ResourceType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = agents_.find(agentId);
    if (it == agents_.end()) return 0;
    return it->second.budgets.at(type).used;
}

uint64_t ResourceScheduler::GetAvailable(const std::string& agentId, ResourceType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = agents_.find(agentId);
    if (it == agents_.end()) return 0;
    auto& budget = it->second.budgets.at(type);
    return budget.limit - budget.used;
}

bool ResourceScheduler::CanAllocate(const std::string& agentId, ResourceType type, uint64_t amount) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = agents_.find(agentId);
    if (it == agents_.end()) return false;
    return it->second.budgets.at(type).used + amount <= it->second.budgets.at(type).limit;
}

ResourceScheduler::SchedulerStats ResourceScheduler::GetStats() const {
    return stats_;
}

} // namespace Sovereign
