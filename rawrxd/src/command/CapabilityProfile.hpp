#pragma once
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <memory>
#include <mutex>

namespace rawrxd::command {

// ───────────────────────────────────────────────────────────────
// Command capability descriptor
// ───────────────────────────────────────────────────────────────
struct Capability {
    std::string name;
    std::string version;
    bool requires_auth = false;
    std::vector<std::string> permissions;
    std::map<std::string, std::string> metadata;
};

// ───────────────────────────────────────────────────────────────
// Capability profile — describes what a peer can do
// ───────────────────────────────────────────────────────────────
class CapabilityProfile {
public:
    CapabilityProfile();
    ~CapabilityProfile();

    // Registration
    bool RegisterCapability(const Capability& cap);
    bool UnregisterCapability(const std::string& name);
    void ClearCapabilities();

    // Query
    bool HasCapability(const std::string& name) const;
    std::optional<Capability> GetCapability(const std::string& name) const;
    std::vector<Capability> GetAllCapabilities() const;
    std::vector<Capability> GetCapabilitiesByPermission(const std::string& perm) const;

    // Filtering
    bool HasAllPermissions(const std::vector<std::string>& perms) const;
    bool HasAnyPermission(const std::vector<std::string>& perms) const;

    // Serialization
    std::string ToJSON() const;
    bool FromJSON(const std::string& json);

    // Comparison
    bool IsSupersetOf(const CapabilityProfile& other) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::command
