#include "governance/AuditLogger.hpp"
#include <mutex>
#include <deque>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;

struct AuditEvent {
    std::string id;
    std::string eventType;
    std::string actor;
    nlohmann::json details;
    int64_t timestamp;
    bool success;
};

static std::deque<AuditEvent> s_events;
static size_t s_eventCounter = 0;
static const size_t MAX_EVENTS = 10000;

static std::string GenerateEventId() {
    s_eventCounter++;
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    return "evt-" + std::to_string(now) + "-" + std::to_string(s_eventCounter);
}

void AuditLogger::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_events.clear();
        s_eventCounter = 0;
        s_initialized = true;
    }
}

void AuditLogger::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Trim old events
    while (s_events.size() > MAX_EVENTS) {
        s_events.pop_front();
    }
}

bool AuditLogger::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void AuditLogger::LogEvent(const std::string& eventType, const std::string& actor, const nlohmann::json& details) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    AuditEvent event;
    event.id = GenerateEventId();
    event.eventType = eventType;
    event.actor = actor;
    event.details = details;
    event.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    event.success = true;
    
    s_events.push_back(event);
}

void AuditLogger::LogAction(const std::string& action, const std::string& actor, bool success, const nlohmann::json& details) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    AuditEvent event;
    event.id = GenerateEventId();
    event.eventType = "action";
    event.actor = actor;
    event.details = details;
    event.details["action"] = action;
    event.details["success"] = success;
    event.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    event.success = success;
    
    s_events.push_back(event);
}

nlohmann::json AuditLogger::GetRecentEvents(size_t count) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    size_t start = s_events.size() > count ? s_events.size() - count : 0;
    
    for (size_t i = start; i < s_events.size(); i++) {
        const auto& event = s_events[i];
        result.push_back({
            {"id", event.id},
            {"type", event.eventType},
            {"actor", event.actor},
            {"timestamp", event.timestamp},
            {"success", event.success}
        });
    }
    return result;
}

nlohmann::json AuditLogger::GetEventsByType(const std::string& eventType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& event : s_events) {
        if (event.eventType == eventType) {
            result.push_back({
                {"id", event.id},
                {"actor", event.actor},
                {"timestamp", event.timestamp},
                {"success", event.success}
            });
        }
    }
    return result;
}

nlohmann::json AuditLogger::GetEventsByActor(const std::string& actor) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& event : s_events) {
        if (event.actor == actor) {
            result.push_back({
                {"id", event.id},
                {"type", event.eventType},
                {"timestamp", event.timestamp},
                {"success", event.success}
            });
        }
    }
    return result;
}

nlohmann::json AuditLogger::GetEventsByTimeRange(int64_t startTime, int64_t endTime) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& event : s_events) {
        if (event.timestamp >= startTime && event.timestamp <= endTime) {
            result.push_back({
                {"id", event.id},
                {"type", event.eventType},
                {"actor", event.actor},
                {"timestamp", event.timestamp}
            });
        }
    }
    return result;
}

nlohmann::json AuditLogger::ExportAuditLog() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& event : s_events) {
        result.push_back({
            {"id", event.id},
            {"type", event.eventType},
            {"actor", event.actor},
            {"timestamp", event.timestamp},
            {"details", event.details},
            {"success", event.success}
        });
    }
    return result;
}

void AuditLogger::ClearAuditLog() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_events.clear();
}

nlohmann::json AuditLogger::GetAuditMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t successCount = 0;
    size_t failureCount = 0;
    std::map<std::string, size_t> typeCounts;
    
    for (const auto& event : s_events) {
        if (event.success) successCount++;
        else failureCount++;
        typeCounts[event.eventType]++;
    }
    
    nlohmann::json typeBreakdown = nlohmann::json::object();
    for (const auto& [type, count] : typeCounts) {
        typeBreakdown[type] = count;
    }
    
    return {
        {"total_events", s_events.size()},
        {"success_count", successCount},
        {"failure_count", failureCount},
        {"event_types", typeBreakdown}
    };
}
