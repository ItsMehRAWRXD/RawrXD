// BeaconBus.hpp
// Coordination Primitive #5: Beacon Event Bus
// No more polling - agents emit beacons, others subscribe

#pragma once
#include <string>
#include <vector>
#include <map>
#include <queue>
#include <chrono>
#include <functional>
#include <variant>
#include <memory>
#include <mutex>

namespace Sovereign {

// Beacon priority levels
enum class BeaconPriority {
    CRITICAL,    // System failure, immediate attention
    HIGH,        // Important events
    NORMAL,      // Standard events
    LOW,         // Background events
    TELEMETRY    // Metrics, can be dropped if overloaded
};

// Beacon types
enum class BeaconType {
    // System beacons
    SYSTEM_STARTUP,
    SYSTEM_SHUTDOWN,
    SYSTEM_ERROR,
    SYSTEM_WARNING,
    
    // Build beacons
    BUILD_STARTED,
    BUILD_PROGRESS,
    BUILD_COMPLETED,
    BUILD_FAILED,
    BUILD_CANCELLED,
    
    // Agent beacons
    AGENT_SPAWNED,
    AGENT_HEARTBEAT,
    AGENT_TERMINATED,
    AGENT_ERROR,
    
    // Terminal beacons
    TERMINAL_CREATED,
    TERMINAL_OUTPUT,
    TERMINAL_CLOSED,
    
    // File beacons
    FILE_CREATED,
    FILE_MODIFIED,
    FILE_DELETED,
    FILE_WATCH_ERROR,
    
    // UI beacons
    UI_REQUEST_RENDER,
    UI_REQUEST_UPDATE,
    UI_USER_ACTION,
    
    // Custom
    CUSTOM
};

// Beacon - event with routing information
struct Beacon {
    std::string beacon_id;
    BeaconType type;
    BeaconPriority priority;
    std::string source_agent_id;
    std::string source_component;
    std::chrono::time_point<std::chrono::steady_clock> timestamp;
    std::chrono::time_point<std::chrono::steady_clock> expiry;
    std::map<std::string, std::string> headers;
    std::variant<
        std::string,           // Text payload
        std::vector<uint8_t>,  // Binary payload
        int,                   // Integer payload
        double,                // Float payload
        bool                   // Boolean payload
    > payload;
    bool persistent;           // If true, kept in history
    uint32_t delivery_attempts;
    
    bool IsExpired() const {
        return std::chrono::steady_clock::now() > expiry;
    }
    
    template<typename T>
    std::optional<T> GetPayload() const {
        if (std::holds_alternative<T>(payload)) {
            return std::get<T>(payload);
        }
        return std::nullopt;
    }
};

// Subscription filter
struct BeaconFilter {
    std::vector<BeaconType> types;
    std::vector<std::string> source_agents;
    std::vector<std::string> source_components;
    BeaconPriority min_priority = BeaconPriority::TELEMETRY;
    std::function<bool(const Beacon&)> custom_filter;
    
    bool Matches(const Beacon& beacon) const {
        if (!types.empty() && std::find(types.begin(), types.end(), beacon.type) == types.end()) {
            return false;
        }
        if (!source_agents.empty() && std::find(source_agents.begin(), source_agents.end(), beacon.source_agent_id) == source_agents.end()) {
            return false;
        }
        if (!source_components.empty() && std::find(source_components.begin(), source_components.end(), beacon.source_component) == source_components.end()) {
            return false;
        }
        if (static_cast<int>(beacon.priority) > static_cast<int>(min_priority)) {
            return false;
        }
        if (custom_filter && !custom_filter(beacon)) {
            return false;
        }
        return true;
    }
};

// Subscription handle
struct Subscription {
    std::string subscription_id;
    BeaconFilter filter;
    std::function<void(const Beacon&)> callback;
    std::chrono::time_point<std::chrono::steady_clock> created;
    uint64_t beacons_received;
    bool active;
};

// Beacon bus - central event distribution
class BeaconBus {
public:
    static BeaconBus& Instance();
    
    // Beacon emission
    std::string Emit(const Beacon& beacon);
    std::string Emit(BeaconType type, BeaconPriority priority, const std::string& source_agent,
                     const std::string& source_component, const std::variant<std::string, std::vector<uint8_t>, int, double, bool>& payload,
                     bool persistent = false);
    
    // Convenience emitters
    std::string EmitCritical(BeaconType type, const std::string& source_agent, const std::string& message);
    std::string EmitError(BeaconType type, const std::string& source_agent, const std::string& message);
    std::string EmitWarning(BeaconType type, const std::string& source_agent, const std::string& message);
    std::string EmitInfo(BeaconType type, const std::string& source_agent, const std::string& message);
    std::string EmitTelemetry(BeaconType type, const std::string& source_agent, double value);
    
    // Subscription
    std::string Subscribe(const BeaconFilter& filter, std::function<void(const Beacon&)> callback);
    std::string Subscribe(BeaconType type, std::function<void(const Beacon&)> callback);
    std::string Subscribe(std::function<void(const Beacon&)> callback);  // Subscribe to all
    void Unsubscribe(const std::string& subscription_id);
    void PauseSubscription(const std::string& subscription_id);
    void ResumeSubscription(const std::string& subscription_id);
    
    // Request/response pattern
    using ResponseCallback = std::function<void(const Beacon&)>;
    std::string Request(const std::string& target_agent, BeaconType request_type, 
                        const std::variant<std::string, std::vector<uint8_t>, int, double, bool>& payload,
                        ResponseCallback on_response, std::chrono::milliseconds timeout);
    void Respond(const std::string& request_beacon_id, const std::variant<std::string, std::vector<uint8_t>, int, double, bool>& payload);
    
    // History
    std::vector<Beacon> GetHistory(const BeaconFilter& filter, size_t limit = 100) const;
    std::vector<Beacon> GetHistory(BeaconType type, size_t limit = 100) const;
    std::optional<Beacon> GetBeacon(const std::string& beacon_id) const;
    void ClearHistory();
    void SetHistoryLimit(size_t limit);
    
    // Query
    size_t GetSubscriberCount() const;
    size_t GetPendingBeaconCount() const;
    std::vector<std::string> GetActiveSubscriptions() const;
    
    // Statistics
    struct BusStats {
        uint64_t total_beacons_emitted;
        uint64_t total_beacons_delivered;
        uint64_t total_beacons_dropped;
        uint64_t total_beacons_expired;
        uint64_t total_subscriptions;
        uint64_t active_subscriptions;
        double average_delivery_time_ms;
        size_t history_size;
    };
    BusStats GetStats() const;
    
    // Control
    void Start();
    void Stop();
    void Pause();  // Temporarily stop processing
    void Resume();
    bool IsRunning() const;

private:
    BeaconBus();
    ~BeaconBus();
    
    BeaconBus(const BeaconBus&) = delete;
    BeaconBus& operator=(const BeaconBus&) = delete;
    
    std::string GenerateBeaconId();
    std::string GenerateSubscriptionId();
    void ProcessQueue();
    void DeliverBeacon(const Beacon& beacon);
    void CleanupExpiredBeacons();
    void CleanupExpiredSubscriptions();
    
    std::queue<Beacon> pending_beacons_;
    std::map<std::string, Subscription> subscriptions_;
    std::vector<Beacon> history_;
    std::map<std::string, ResponseCallback> pending_requests_;
    std::map<std::string, std::chrono::time_point<std::chrono::steady_clock>> request_timeouts_;
    
    mutable std::mutex mutex_;
    uint64_t beacon_counter_;
    uint64_t subscription_counter_;
    size_t history_limit_;
    bool running_;
    bool paused_;
    BusStats stats_;
};

// Scoped beacon emitter - RAII for beacon context
class BeaconContext {
public:
    BeaconContext(const std::string& agent_id, const std::string& component);
    ~BeaconContext();
    
    std::string Emit(BeaconType type, BeaconPriority priority, const std::variant<std::string, std::vector<uint8_t>, int, double, bool>& payload);
    std::string EmitCritical(BeaconType type, const std::string& message);
    std::string EmitError(BeaconType type, const std::string& message);
    std::string EmitWarning(BeaconType type, const std::string& message);
    std::string EmitInfo(BeaconType type, const std::string& message);
    
private:
    std::string agent_id_;
    std::string component_;
};

// Helper to convert beacon type to string
const char* BeaconTypeToString(BeaconType type);
const char* BeaconPriorityToString(BeaconPriority priority);

} // namespace Sovereign
