#pragma once
#include <string>
#include <vector>
#include <functional>
#include <optional>

namespace rawrxd::bridge {

// ───────────────────────────────────────────────────────────────
// IAT (Import Address Table) hook descriptor for swarm agents
// ───────────────────────────────────────────────────────────────
struct IATHookDescriptor {
    std::string module_name;
    std::string import_name;
    uint64_t original_rva = 0;
    uint64_t hook_rva = 0;
    bool is_ordinal = false;
    uint16_t ordinal = 0;
    std::vector<uint8_t> original_bytes;
    std::vector<uint8_t> trampoline;
};

// ───────────────────────────────────────────────────────────────
// Swarm agent IAT registration entry
// ───────────────────────────────────────────────────────────────
struct SwarmAgentRegistration {
    uint32_t agent_id = 0;
    std::string agent_name;
    std::string agent_version;
    std::vector<IATHookDescriptor> hooks;
    uint32_t priority = 0;        // lower = higher priority
    bool enabled = true;
    uint64_t registration_timestamp = 0;
    std::string signature;        // SHA256 of agent binary
    std::vector<std::string> capabilities;
};

// ───────────────────────────────────────────────────────────────
// SwarmIATRegistration — Agent hook registry & coordinator
// ───────────────────────────────────────────────────────────────
class SwarmIATRegistration {
public:
    SwarmIATRegistration();
    ~SwarmIATRegistration();

    // Registration API
    bool RegisterAgent(const SwarmAgentRegistration& reg);
    bool UnregisterAgent(uint32_t agent_id);
    bool IsAgentRegistered(uint32_t agent_id) const;
    std::optional<SwarmAgentRegistration> GetAgent(uint32_t agent_id) const;
    std::vector<SwarmAgentRegistration> GetAllAgents() const;

    // Hook management
    bool EnableHook(uint32_t agent_id, const std::string& import_name);
    bool DisableHook(uint32_t agent_id, const std::string& import_name);
    bool IsHookActive(uint32_t agent_id, const std::string& import_name) const;

    // Conflict resolution
    struct ConflictResolution {
        uint32_t winning_agent_id = 0;
        std::string reason;
        std::vector<uint32_t> conflicting_agents;
    };
    ConflictResolution ResolveHookConflict(const std::string& import_name) const;

    // Batch operations
    bool EnableAllHooksForAgent(uint32_t agent_id);
    bool DisableAllHooksForAgent(uint32_t agent_id);
    size_t GetActiveHookCount() const;
    size_t GetAgentCount() const;

    // Validation
    bool ValidateAgentSignature(uint32_t agent_id, const std::string& expected_sha256) const;
    bool ValidateAllSignatures() const;

    // Serialization
    std::vector<uint8_t> SerializeRegistry() const;
    bool DeserializeRegistry(const std::vector<uint8_t>& data);

    // Callbacks
    using RegistrationCallback = std::function<void(uint32_t agent_id, bool registered)>;
    using HookStateCallback    = std::function<void(uint32_t agent_id, const std::string& import_name, bool enabled)>;
    void SetRegistrationCallback(RegistrationCallback cb) { reg_cb_ = std::move(cb); }
    void SetHookStateCallback(HookStateCallback cb) { hook_cb_ = std::move(cb); }

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    RegistrationCallback reg_cb_;
    HookStateCallback hook_cb_;
};

} // namespace rawrxd::bridge
