// ============================================================================
// CapabilityBus.hpp - Dynamic Tool Discovery & Hot-Plug
// Tools appear dynamically like hardware devices: build, debug, git, search, model
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <atomic>
#include <mutex>

namespace Sovereign {

// Capability states
enum class CapabilityState {
    UNINSTALLED,
    INSTALLED,
    LOADING,
    ACTIVE,
    ERROR,
    DISABLED
};

// Capability descriptor
struct CapabilityDescriptor {
    std::string name;
    std::string version;
    std::string description;
    std::vector<std::string> provides; // tools, commands, events
    std::vector<std::string> dependencies; // required capabilities
    std::string entryPoint;
    CapabilityState state;
    uint64_t loadTime;
    std::string error;
};

// Capability bus - dynamic tool discovery
class CapabilityBus {
public:
    CapabilityBus();
    ~CapabilityBus();

    bool Initialize();
    void Shutdown();

    // Registration
    bool Register(const CapabilityDescriptor& desc);
    bool Unregister(const std::string& name);
    bool IsRegistered(const std::string& name) const;

    // Lifecycle
    bool Load(const std::string& name);
    bool Unload(const std::string& name);
    bool Enable(const std::string& name);
    bool Disable(const std::string& name);

    // Discovery
    std::vector<CapabilityDescriptor> Discover() const;
    std::vector<CapabilityDescriptor> GetByState(CapabilityState state) const;
    std::vector<CapabilityDescriptor> GetByProvide(const std::string& tool) const;
    CapabilityDescriptor GetCapability(const std::string& name) const;

    // Hot-plug
    bool Attach(const std::string& name);
    bool Detach(const std::string& name);
    bool IsAttached(const std::string& name) const;

    // Events
    void SetAttachHandler(std::function<void(const std::string&)> handler);
    void SetDetachHandler(std::function<void(const std::string&)> handler);
    void SetErrorHandler(std::function<void(const std::string&, const std::string&)> handler);

    // Statistics
    struct BusStats {
        uint64_t totalCapabilities;
        uint64_t activeCapabilities;
        uint64_t loadedCapabilities;
        uint64_t failedCapabilities;
        uint64_t attachEvents;
        uint64_t detachEvents;
    };
    BusStats GetStats() const;

private:
    std::unordered_map<std::string, CapabilityDescriptor> capabilities_;
    BusStats stats_;
    mutable std::mutex mutex_;
    
    std::function<void(const std::string&)> attachHandler_;
    std::function<void(const std::string&)> detachHandler_;
    std::function<void(const std::string&, const std::string&)> errorHandler_;
};

} // namespace Sovereign
