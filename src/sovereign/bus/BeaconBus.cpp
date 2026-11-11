// BeaconBus.cpp
// Coordination Primitive #5: Beacon Event Bus Implementation

#include "BeaconBus.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace Sovereign {

// BeaconBus implementation
BeaconBus::BeaconBus() = default;
BeaconBus::~BeaconBus() {
    Stop();
}

BeaconBus& BeaconBus::Instance() {
    static BeaconBus instance;
    return instance;
}

void BeaconBus::Start() {
    // Start processing thread
}

void BeaconBus::Stop() {
    // Stop processing thread
}

void BeaconBus::Pause() {
    // Pause processing
}

void BeaconBus::Resume() {
    // Resume processing
}

bool BeaconBus::IsRunning() const {
    return true;
}

std::string BeaconBus::GenerateBeaconId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << "beacon-";
    for (int i = 0; i < 16; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

std::string BeaconBus::GenerateSubscriptionId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::mt19937 counter(rd());
    
    std::stringstream ss;
    ss << "sub-" << counter() << "-" << std::chrono::steady_clock::now().time_since_epoch().count();
    return ss.str();
}

std::string BeaconBus::Emit(const Beacon& beacon) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Beacon mutable_beacon = beacon;
    if (mutable_beacon.beacon_id.empty()) {
        mutable_beacon.beacon_id = GenerateBeaconId();
    }
    
    pending_beacons_.push(mutable_beacon);
    ProcessQueue();
    
    return mutable_beacon.beacon_id;
}

std::string BeaconBus::Emit(BeaconType type, BeaconPriority priority, const std::string& source_agent,
                              const std::string& source_component, const std::variant<std::string, std::vector<uint8_t>, int, double, bool>& payload,
                              bool persistent) {
    Beacon beacon;
    beacon.beacon_id = GenerateBeaconId();
    beacon.type = type;
    beacon.priority = priority;
    beacon.source_agent_id = source_agent;
    beacon.source_component = source_component;
    beacon.timestamp = std::chrono::steady_clock::now();
    beacon.expiry = beacon.timestamp + std::chrono::minutes(5);
    beacon.payload = payload;
    beacon.persistent = persistent;
    beacon.delivery_attempts = 0;
    
    return Emit(beacon);
}

std::string BeaconBus::EmitCritical(BeaconType type, const std::string& source_agent, const std::string& message) {
    return Emit(type, BeaconPriority::CRITICAL, source_agent, "system", message, true);
}

std::string BeaconBus::EmitError(BeaconType type, const std::string& source_agent, const std::string& message) {
    return Emit(type, BeaconPriority::HIGH, source_agent, "system", message, true);
}

std::string BeaconBus::EmitWarning(BeaconType type, const std::string& source_agent, const std::string& message) {
    return Emit(type, BeaconPriority::NORMAL, source_agent, "system", message, false);
}

std::string BeaconBus::EmitInfo(BeaconType type, const std::string& source_agent, const std::string& message) {
    return Emit(type, BeaconPriority::NORMAL, source_agent, "system", message, false);
}

std::string BeaconBus::EmitTelemetry(BeaconType type, const std::string& source_agent, double value) {
    return Emit(type, BeaconPriority::TELEMETRY, source_agent, "telemetry", value, false);
}

std::string BeaconBus::Subscribe(const BeaconFilter& filter, std::function<void(const Beacon&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string id = GenerateSubscriptionId();
    Subscription sub;
    sub.subscription_id = id;
    sub.filter = filter;
    sub.callback = callback;
    sub.created = std::chrono::steady_clock::now();
    sub.beacons_received = 0;
    sub.active = true;
    
    subscriptions_[id] = sub;
    return id;
}

std::string BeaconBus::Subscribe(BeaconType type, std::function<void(const Beacon&)> callback) {
    BeaconFilter filter;
    filter.types.push_back(type);
    return Subscribe(filter, callback);
}

std::string BeaconBus::Subscribe(std::function<void(const Beacon&)> callback) {
    BeaconFilter filter;
    return Subscribe(filter, callback);
}

void BeaconBus::Unsubscribe(const std::string& subscription_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    subscriptions_.erase(subscription_id);
}

void BeaconBus::PauseSubscription(const std::string& subscription_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = subscriptions_.find(subscription_id);
    if (it != subscriptions_.end()) {
        it->second.active = false;
    }
}

void BeaconBus::ResumeSubscription(const std::string& subscription_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = subscriptions_.find(subscription_id);
    if (it != subscriptions_.end()) {
        it->second.active = true;
    }
}

void BeaconBus::ProcessQueue() {
    while (!pending_beacons_.empty()) {
        Beacon beacon = pending_beacons_.front();
        pending_beacons_.pop();
        DeliverBeacon(beacon);
        
        if (beacon.persistent) {
            history_.push_back(beacon);
        }
    }
}

void BeaconBus::DeliverBeacon(const Beacon& beacon) {
    for (auto& [id, sub] : subscriptions_) {
        if (!sub.active) continue;
        if (!sub.filter.Matches(beacon)) continue;
        
        sub.callback(beacon);
        sub.beacons_received++;
    }
}

std::vector<Beacon> BeaconBus::GetHistory(const BeaconFilter& filter, size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Beacon> result;
    
    for (auto it = history_.rbegin(); it != history_.rend() && result.size() < limit; ++it) {
        if (filter.Matches(*it)) {
            result.push_back(*it);
        }
    }
    
    return result;
}

std::vector<Beacon> BeaconBus::GetHistory(BeaconType type, size_t limit) const {
    BeaconFilter filter;
    filter.types.push_back(type);
    return GetHistory(filter, limit);
}

std::optional<Beacon> BeaconBus::GetBeacon(const std::string& beacon_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& beacon : history_) {
        if (beacon.beacon_id == beacon_id) {
            return beacon;
        }
    }
    
    return std::nullopt;
}

void BeaconBus::ClearHistory() {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.clear();
}

void BeaconBus::SetHistoryLimit(size_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    while (history_.size() > limit) {
        history_.erase(history_.begin());
    }
}

size_t BeaconBus::GetSubscriberCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return subscriptions_.size();
}

size_t BeaconBus::GetPendingBeaconCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_beacons_.size();
}

std::vector<std::string> BeaconBus::GetActiveSubscriptions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [id, sub] : subscriptions_) {
        if (sub.active) {
            result.push_back(id);
        }
    }
    return result;
}

BeaconBus::BusStats BeaconBus::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    BusStats stats{};
    stats.history_size = history_.size();
    stats.active_subscriptions = std::count_if(subscriptions_.begin(), subscriptions_.end(),
        [](const auto& pair) { return pair.second.active; });
    return stats;
}

std::string BeaconBus::Request(const std::string& target_agent, BeaconType request_type,
                                 const std::variant<std::string, std::vector<uint8_t>, int, double, bool>& payload,
                                 ResponseCallback on_response, std::chrono::milliseconds timeout) {
    (void)timeout;
    
    std::string request_id = Emit(request_type, BeaconPriority::HIGH, "", target_agent, payload, true);
    
    // Subscribe to response
    BeaconFilter filter;
    filter.custom_filter = [request_id](const Beacon& b) {
        auto req_id = b.GetPayload<std::string>();
        return req_id && *req_id == request_id;
    };
    
    Subscribe(filter, on_response);
    
    return request_id;
}

void BeaconBus::Respond(const std::string& request_beacon_id, const std::variant<std::string, std::vector<uint8_t>, int, double, bool>& payload) {
    Beacon beacon;
    beacon.beacon_id = GenerateBeaconId();
    beacon.type = BeaconType::CUSTOM;
    beacon.priority = BeaconPriority::NORMAL;
    beacon.payload = payload;
    beacon.headers["request_id"] = request_beacon_id;
    Emit(beacon);
}

void BeaconBus::CleanupExpiredBeacons() {
    // Remove expired beacons from history
}

void BeaconBus::CleanupExpiredSubscriptions() {
    // Remove old subscriptions
}

} // namespace Sovereign
