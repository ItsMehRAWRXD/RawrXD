// AgentLease.hpp
// Coordination Primitive #4: Agent Lease System
// Agents don't "exist" - they lease existence with heartbeat

#pragma once
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <optional>
#include <functional>
#include <atomic>

namespace Sovereign {

// Agent capabilities
enum class AgentCapability {
    FILE_READ,
    FILE_WRITE,
    FILE_DELETE,
    TERMINAL_EXECUTE,
    TERMINAL_KILL,
    BUILD_TRIGGER,
    BUILD_CANCEL,
    NETWORK_REQUEST,
    UI_RENDER,
    UI_INTERACT,
    AGENT_SPAWN,      // Can spawn sub-agents
    AGENT_KILL,       // Can kill other agents
    SYSTEM_CONFIG     // Can modify system settings
};

// Lease tier - determines resource limits
enum class LeaseTier {
    EPHEMERAL,        // Temporary, no persistence
    STANDARD,         // Normal agent lease
    PRIVILEGED,       // Extended capabilities
    SYSTEM            // Core system agents only
};

// Agent lease - proof of existence
struct AgentLease {
    std::string lease_id;
    std::string agent_id;
    std::string parent_agent_id;  // Empty if root agent
    LeaseTier tier;
    std::chrono::time_point<std::chrono::steady_clock> issued_at;
    std::chrono::time_point<std::chrono::steady_clock> expires_at;
    std::chrono::time_point<std::chrono::steady_clock> last_heartbeat;
    std::vector<AgentCapability> capabilities;
    std::map<std::string, std::string> metadata;
    bool is_suspended;
    uint32_t heartbeat_interval_ms;
    uint32_t missed_heartbeats;
    uint32_t max_missed_heartbeats;
    
    bool IsValid() const {
        if (is_suspended) return false;
        auto now = std::chrono::steady_clock::now();
        if (now > expires_at) return false;
        if (missed_heartbeats > max_missed_heartbeats) return false;
        return true;
    }
    
    bool HasCapability(AgentCapability cap) const {
        return std::find(capabilities.begin(), capabilities.end(), cap) != capabilities.end();
    }
    
    std::chrono::milliseconds TimeUntilExpiry() const {
        auto now = std::chrono::steady_clock::now();
        if (now >= expires_at) return std::chrono::milliseconds(0);
        return std::chrono::duration_cast<std::chrono::milliseconds>(expires_at - now);
    }
};

// Agent state
enum class AgentState {
    SPAWNING,         // Lease requested, not yet active
    ACTIVE,           // Running with valid lease
    SUSPENDED,        // Paused, can resume
    DEGRADED,         // Running but lost some capabilities
    EXPIRING,         // Lease about to expire
    EXPIRED,          // Lease expired
    TERMINATED        // Clean shutdown
};

// Agent descriptor
struct AgentDescriptor {
    std::string agent_id;
    std::string agent_type;       // "editor", "builder", "debugger", etc.
    std::string purpose;          // Human-readable purpose
    std::vector<std::string> required_capabilities;
    LeaseTier requested_tier;
    std::chrono::seconds requested_duration;
    std::optional<std::string> parent_agent_id;
    std::map<std::string, std::string> context;
};

// Agent event types
enum class AgentEventType {
    LEASE_GRANTED,
    LEASE_RENEWED,
    LEASE_EXPIRED,
    LEASE_REVOKED,
    HEARTBEAT_RECEIVED,
    HEARTBEAT_MISSED,
    CAPABILITY_GRANTED,
    CAPABILITY_REVOKED,
    STATE_CHANGED,
    AGENT_SPAWNED,
    AGENT_TERMINATED
};

// Agent event
struct AgentEvent {
    AgentEventType type;
    std::string lease_id;
    std::string agent_id;
    std::chrono::time_point<std::chrono::steady_clock> timestamp;
    std::optional<std::string> reason;
    std::map<std::string, std::string> data;
};

// Agent lease manager - singleton
class AgentLeaseManager {
public:
    static AgentLeaseManager& Instance();
    
    // Lease lifecycle
    std::optional<AgentLease> RequestLease(const AgentDescriptor& descriptor);
    bool RenewLease(const std::string& lease_id, std::chrono::seconds extension);
    bool Heartbeat(const std::string& lease_id);
    bool SuspendLease(const std::string& lease_id, const std::string& reason);
    bool ResumeLease(const std::string& lease_id);
    bool TerminateLease(const std::string& lease_id, const std::string& reason);
    
    // Capability management
    bool GrantCapability(const std::string& lease_id, AgentCapability capability);
    bool RevokeCapability(const std::string& lease_id, AgentCapability capability);
    bool TransferCapability(const std::string& from_lease, const std::string& to_lease, AgentCapability capability);
    
    // Verification
    bool VerifyLease(const std::string& lease_id) const;
    bool VerifyCapability(const std::string& lease_id, AgentCapability capability) const;
    std::optional<AgentLease> GetLease(const std::string& lease_id) const;
    AgentState GetAgentState(const std::string& lease_id) const;
    
    // Queries
    std::vector<AgentLease> GetActiveLeases() const;
    std::vector<AgentLease> GetLeasesByAgent(const std::string& agent_id) const;
    std::vector<AgentLease> GetChildLeases(const std::string& parent_lease_id) const;
    std::vector<AgentLease> GetExpiredLeases() const;
    size_t GetActiveAgentCount() const;
    size_t GetAgentCountByTier(LeaseTier tier) const;
    
    // Event subscription
    using EventCallback = std::function<void(const AgentEvent&)>;
    std::string Subscribe(EventCallback callback);
    void Unsubscribe(const std::string& subscription_id);
    
    // Maintenance
    void ExpireStaleLeases();
    void ForceTerminateAll(const std::string& reason);  // Emergency shutdown
    void SetDefaultHeartbeatInterval(uint32_t interval_ms);
    
    // Statistics
    struct LeaseStats {
        uint64_t total_leases_issued;
        uint64_t total_leases_expired;
        uint64_t total_leases_revoked;
        uint64_t total_heartbeats_received;
        uint64_t total_heartbeats_missed;
        uint64_t active_leases;
        uint64_t suspended_leases;
        double average_lease_duration_ms;
    };
    LeaseStats GetStats() const;

private:
    AgentLeaseManager();
    ~AgentLeaseManager();
    
    AgentLeaseManager(const AgentLeaseManager&) = delete;
    AgentLeaseManager& operator=(const AgentLeaseManager&) = delete;
    
    std::string GenerateLeaseId();
    std::vector<AgentCapability> GetCapabilitiesForTier(LeaseTier tier);
    void EmitEvent(const AgentEvent& event);
    void UpdateAgentState(const std::string& lease_id, AgentState new_state);
    
    std::map<std::string, AgentLease> leases_;
    std::map<std::string, AgentState> agent_states_;
    std::map<std::string, EventCallback> subscribers_;
    mutable std::mutex mutex_;
    uint64_t lease_counter_;
    uint32_t default_heartbeat_interval_ms_;
    LeaseStats stats_;
};

// RAII lease guard
class AgentLeaseGuard {
public:
    AgentLeaseGuard(const std::string& lease_id);
    ~AgentLeaseGuard();
    
    AgentLeaseGuard(const AgentLeaseGuard&) = delete;
    AgentLeaseGuard& operator=(const AgentLeaseGuard&) = delete;
    
    AgentLeaseGuard(AgentLeaseGuard&& other) noexcept;
    AgentLeaseGuard& operator=(AgentLeaseGuard&& other) noexcept;
    
    bool IsValid() const;
    bool Heartbeat();
    const std::string& GetLeaseId() const { return lease_id_; }

private:
    std::string lease_id_;
    bool valid_;
};

// Capability guard - temporary capability grant
class CapabilityGuard {
public:
    CapabilityGuard(const std::string& lease_id, AgentCapability capability);
    ~CapabilityGuard();
    
    CapabilityGuard(const CapabilityGuard&) = delete;
    CapabilityGuard& operator=(const CapabilityGuard&) = delete;

private:
    std::string lease_id_;
    AgentCapability capability_;
    bool released_;
};

} // namespace Sovereign
