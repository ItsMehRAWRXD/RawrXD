#include "executive/ResourceArbiter.hpp"
#include <mutex>
#include <map>
#include <set>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, std::string> resourceAllocations;
static std::set<std::string> availableResources;

void ResourceArbiter::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        resourceAllocations.clear();
        availableResources = {"cpu", "memory", "network", "storage"};
        s_initialized = true;
    }
}

void ResourceArbiter::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    // Periodic resource rebalancing
}

bool ResourceArbiter::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

bool ResourceArbiter::RequestResource(const std::string& resource, const std::string& requester) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return false;
    
    if (availableResources.count(resource) > 0) {
        if (resourceAllocations.count(resource) == 0) {
            resourceAllocations[resource] = requester;
            return true;
        }
    }
    return false;
}

void ResourceArbiter::ReleaseResource(const std::string& resource) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    resourceAllocations.erase(resource);
}

nlohmann::json ResourceArbiter::GetResourceStatus() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json status = {
        {"allocated", nlohmann::json::object()},
        {"available", nlohmann::json::array()}
    };
    
    for (const auto& [resource, requester] : resourceAllocations) {
        status["allocated"][resource] = requester;
    }
    
    for (const auto& resource : availableResources) {
        if (resourceAllocations.count(resource) == 0) {
            status["available"].push_back(resource);
        }
    }
    
    return status;
}

nlohmann::json ResourceArbiter::ResolveConflict(const nlohmann::json& requests) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json resolution = {
        {"granted", nlohmann::json::array()},
        {"denied", nlohmann::json::array()}
    };
    
    // Simple first-come-first-served
    for (const auto& request : requests) {
        std::string resource = request.value("resource", "");
        std::string requester = request.value("requester", "");
        
        if (RequestResource(resource, requester)) {
            resolution["granted"].push_back(request);
        } else {
            resolution["denied"].push_back(request);
        }
    }
    
    return resolution;
}
