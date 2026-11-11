#include "resource/ResourceAllocator.hpp"
#include <mutex>
#include <map>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;

struct Allocation {
    std::string id;
    std::string resourceType;
    double amount;
    std::string requester;
    int64_t allocatedAt;
    bool active;
};

static std::map<std::string, Allocation> s_allocations;
static std::map<std::string, double> s_resourceLimits;
static std::map<std::string, double> s_resourceUsage;
static size_t s_allocationCounter = 0;

static std::string GenerateAllocationId() {
    s_allocationCounter++;
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    return "alloc-" + std::to_string(now) + "-" + std::to_string(s_allocationCounter);
}

void ResourceAllocator::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_allocations.clear();
        s_resourceLimits.clear();
        s_resourceUsage.clear();
        s_allocationCounter = 0;
        
        // Initialize default resource limits
        s_resourceLimits["cpu"] = 100.0;      // percentage
        s_resourceLimits["memory"] = 8589934592.0;  // 8GB in bytes
        s_resourceLimits["storage"] = 1099511627776.0;  // 1TB in bytes
        s_resourceLimits["bandwidth"] = 125000000.0;  // 1Gbps in bytes/sec
        
        s_initialized = true;
    }
}

void ResourceAllocator::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Recalculate resource usage
    s_resourceUsage.clear();
    for (const auto& [id, alloc] : s_allocations) {
        if (alloc.active) {
            s_resourceUsage[alloc.resourceType] += alloc.amount;
        }
    }
}

bool ResourceAllocator::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json ResourceAllocator::Allocate(const std::string& resourceType, double amount, const std::string& requester) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    // Check resource limits
    auto limitIt = s_resourceLimits.find(resourceType);
    if (limitIt != s_resourceLimits.end()) {
        double currentUsage = s_resourceUsage[resourceType];
        if (currentUsage + amount > limitIt->second) {
            return {
                {"success", false},
                {"reason", "resource_limit_exceeded"},
                {"requested", amount},
                {"available", limitIt->second - currentUsage}
            };
        }
    }
    
    std::string allocId = GenerateAllocationId();
    Allocation alloc;
    alloc.id = allocId;
    alloc.resourceType = resourceType;
    alloc.amount = amount;
    alloc.requester = requester;
    alloc.allocatedAt = std::chrono::system_clock::now().time_since_epoch().count();
    alloc.active = true;
    
    s_allocations[allocId] = alloc;
    s_resourceUsage[resourceType] += amount;
    
    return {
        {"success", true},
        {"allocation_id", allocId},
        {"resource_type", resourceType},
        {"amount", amount}
    };
}

nlohmann::json ResourceAllocator::Deallocate(const std::string& allocationId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    auto it = s_allocations.find(allocationId);
    if (it != s_allocations.end()) {
        if (it->second.active) {
            it->second.active = false;
            s_resourceUsage[it->second.resourceType] -= it->second.amount;
        }
        return {
            {"success", true},
            {"allocation_id", allocationId}
        };
    }
    
    return {
        {"success", false},
        {"reason", "allocation_not_found"}
    };
}

nlohmann::json ResourceAllocator::GetAllocation(const std::string& allocationId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_allocations.find(allocationId);
    if (it != s_allocations.end()) {
        return {
            {"id", it->second.id},
            {"resource_type", it->second.resourceType},
            {"amount", it->second.amount},
            {"requester", it->second.requester},
            {"allocated_at", it->second.allocatedAt},
            {"active", it->second.active}
        };
    }
    return nlohmann::json{};
}

nlohmann::json ResourceAllocator::GetAvailableResources() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::object();
    for (const auto& [type, limit] : s_resourceLimits) {
        double used = s_resourceUsage[type];
        result[type] = {
            {"limit", limit},
            {"used", used},
            {"available", limit - used}
        };
    }
    return result;
}

nlohmann::json ResourceAllocator::GetAllocatedResources() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, alloc] : s_allocations) {
        if (alloc.active) {
            result.push_back({
                {"id", alloc.id},
                {"resource_type", alloc.resourceType},
                {"amount", alloc.amount},
                {"requester", alloc.requester}
            });
        }
    }
    return result;
}

nlohmann::json ResourceAllocator::GetResourceUtilization() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::object();
    for (const auto& [type, limit] : s_resourceLimits) {
        double used = s_resourceUsage[type];
        result[type] = {
            {"limit", limit},
            {"used", used},
            {"utilization", limit > 0 ? (used / limit) : 0.0}
        };
    }
    return result;
}

void ResourceAllocator::SetResourceLimit(const std::string& resourceType, double limit) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_resourceLimits[resourceType] = limit;
}

nlohmann::json ResourceAllocator::GetResourceLimits() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_resourceLimits;
}
