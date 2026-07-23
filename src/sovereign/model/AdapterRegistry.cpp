// ============================================================================
// AdapterRegistry.cpp - Adapter Registry Implementation
// ============================================================================

#include "AdapterRegistry.hpp"
#include <fstream>
#include <iostream>

namespace Sovereign {

AdapterRegistry::AdapterRegistry() = default;
AdapterRegistry::~AdapterRegistry() = default;

bool AdapterRegistry::Register(const std::string& name, AdapterType type, const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (adapters_.find(name) != adapters_.end()) return false;
    
    AdapterInfo info;
    info.name = name;
    info.type = type;
    info.path = path;
    info.scale = 1.0f;
    info.isActive = false;
    info.loadedAt = 0;
    info.weightCount = 0;
    info.totalParams = 0;
    
    adapters_[name] = info;
    stats_.totalRegistrations++;
    return true;
}

bool AdapterRegistry::Unregister(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    return adapters_.erase(name) > 0;
}

bool AdapterRegistry::Load(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = adapters_.find(name);
    if (it == adapters_.end()) return false;
    it->second.loadedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    stats_.loadedAdapters++;
    return true;
}

bool AdapterRegistry::Unload(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = adapters_.find(name);
    if (it == adapters_.end()) return false;
    it->second.isActive = false;
    stats_.loadedAdapters--;
    return true;
}

bool AdapterRegistry::Activate(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = adapters_.find(name);
    if (it == adapters_.end()) return false;
    it->second.isActive = true;
    stats_.activeAdapters++;
    return true;
}

bool AdapterRegistry::Deactivate(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = adapters_.find(name);
    if (it == adapters_.end()) return false;
    it->second.isActive = false;
    stats_.activeAdapters--;
    return true;
}

AdapterInfo AdapterRegistry::GetInfo(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = adapters_.find(name);
    if (it != adapters_.end()) return it->second;
    return {};
}

std::vector<AdapterInfo> AdapterRegistry::List() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AdapterInfo> result;
    for (const auto& [name, info] : adapters_) result.push_back(info);
    return result;
}

std::vector<AdapterInfo> AdapterRegistry::GetActive() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AdapterInfo> result;
    for (const auto& [name, info] : adapters_) {
        if (info.isActive) result.push_back(info);
    }
    return result;
}

} // namespace Sovereign
