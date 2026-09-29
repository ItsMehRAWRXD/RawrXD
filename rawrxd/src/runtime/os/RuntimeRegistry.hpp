// ============================================================================
// RuntimeRegistry.hpp — Universal capability registry
// Every capability (inference, build, agent, IDE, GPU, OS services) registers
// here. This IS the "Capability Registry" from the Beaconism Build vision.
// ============================================================================
#pragma once
#include "RuntimeCapability.hpp"
#include <vector>
#include <memory>
#include <unordered_map>
#include <string>
#include <string_view>
#include <mutex>

namespace rawrxd::runtime {

class RuntimeRegistry {
public:
    bool registerCapability(std::unique_ptr<RuntimeCapability> cap) {
        if (!cap) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        auto name = std::string(cap->name());
        if (byName_.count(name)) return false;  // duplicate — fail-closed
        byId_[cap->id()] = cap.get();
        byName_[name] = cap.get();
        caps_.push_back(std::move(cap));
        return true;
    }

    RuntimeCapability* find(CapabilityId id) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = byId_.find(id);
        return (it != byId_.end()) ? it->second : nullptr;
    }

    RuntimeCapability* findByName(std::string_view name) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = byName_.find(std::string(name));
        return (it != byName_.end()) ? it->second : nullptr;
    }

    std::vector<RuntimeCapability*> all() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<RuntimeCapability*> result;
        result.reserve(caps_.size());
        for (auto& c : caps_) result.push_back(c.get());
        return result;
    }

    size_t size() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return caps_.size();
    }

    void clear() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        caps_.clear();
        byId_.clear();
        byName_.clear();
    }

private:
    mutable std::mutex mutex_;
    std::vector<std::unique_ptr<RuntimeCapability>> caps_;
    std::unordered_map<CapabilityId, RuntimeCapability*> byId_;
    std::unordered_map<std::string, RuntimeCapability*> byName_;
};

} // namespace rawrxd::runtime