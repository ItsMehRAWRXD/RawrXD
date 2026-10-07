#include "emergence/EmergentPatternTracker.hpp"
#include <deque>

static std::deque<nlohmann::json> eventHistory;
static const size_t MAX_HISTORY = 1000;

void EmergentPatternTracker::Init() {
    eventHistory.clear();
}

void EmergentPatternTracker::Record(const nlohmann::json& event) {
    eventHistory.push_back(event);
    if (eventHistory.size() > MAX_HISTORY) {
        eventHistory.pop_front();
    }
}

std::vector<nlohmann::json> EmergentPatternTracker::DetectPatterns() {
    std::vector<nlohmann::json> patterns;
    
    // stub: detect recurring patterns in event history
    std::unordered_map<std::string, int> frequency;
    for (const auto& evt : eventHistory) {
        if (evt.contains("type")) {
            frequency[evt["type"]]++;
        }
    }
    
    for (const auto& [type, count] : frequency) {
        if (count > 10) {
            patterns.push_back({
                {"pattern", "recurring"},
                {"type", type},
                {"frequency", count}
            });
        }
    }
    
    return patterns;
}

nlohmann::json EmergentPatternTracker::GetEmergentState() {
    return {
        {"event_count", eventHistory.size()},
        {"patterns_detected", DetectPatterns().size()}
    };
}
