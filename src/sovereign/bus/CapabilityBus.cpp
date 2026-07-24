// ============================================================================
// CapabilityBus.cpp - Dynamic Tool Discovery & Hot-Plug Implementation
// ============================================================================

#include "CapabilityBus.hpp"
#include <algorithm>
#include <iostream>
#include <chrono>

namespace Sovereign {

CapabilityBus::CapabilityBus() = default;
CapabilityBus::~CapabilityBus() {
    Shutdown();
}

bool CapabilityBus::Initialize() { return true; }
void CapabilityBus::Shutdown() { capabilities_.clear(); }

bool CapabilityBus::Register(const CapabilityDescriptor& desc) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (capabilities_.find(desc.name) != capabilities_.end()) return false;
    
    CapabilityDescriptor d = desc;
    d.state = CapabilityState::INSTALLED;
    capabilities_[desc.name] = d;
    stats_.totalCapabilities++;
    return true;
}

bool CapabilityBus::Unregister(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    return capabilities_.erase(name) > 0;
}

bool CapabilityBus::Load(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = capabilities_.find(name);
    if (it == capabilities_.end()) return false;
    
    it->second.state = CapabilityState::LOADING;
    it->second.state = CapabilityState::ACTIVE;
    it->second.loadTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    stats_.loadedCapabilities++;
    stats_.activeCapabilities++;
    return true;
}

bool CapabilityBus::Unload(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = capabilities_.find(name);
    if (it == capabilities_.end()) return false;
    
    it->second.state = CapabilityState::INSTALLED;
    stats_.activeCapabilities--;
    return true;
}

bool CapabilityBus::Attach(const std::string& name) {
    if (Load(name)) {
        if (attachHandler_) attachHandler_(name);
        stats_.attachEvents++;
        return true;
    }
    return false;
}

bool CapabilityBus::Detach(const std::string& name) {
    if (Unload(name)) {
        if (detachHandler_) detachHandler_(name);
        stats_.detachEvents++;
        return true;
    }
    return false;
}

std::vector<CapabilityDescriptor> CapabilityBus::Discover() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CapabilityDescriptor> result;
    for (const auto& [name, desc] : capabilities_) {
        result.push_back(desc);
    }
    return result;
}

std::vector<CapabilityDescriptor> CapabilityBus::GetByState(CapabilityState state) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CapabilityDescriptor> result;
    for (const auto& [name, desc] : capabilities_) {
        if (desc.state == state) result.push_back(desc);
    }
    return result;
}

CapabilityBus::BusStats CapabilityBus::GetStats() const {
    return stats_;
}

} // namespace Sovereign
