#include "temporal/TimelineReasoner.hpp"
#include "temporal/TemporalMemory.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void TimelineReasoner::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = true;
}

nlohmann::json TimelineReasoner::Analyze() {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto tl = TemporalMemory::GetTimeline();
    
    return {
        {"length", tl.size()},
        {"first", tl.size() > 0 ? tl.front() : nlohmann::json{}},
        {"last", tl.size() > 0 ? tl.back() : nlohmann::json{}};
}

nlohmann::json TimelineReasoner::GetTrends() {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto tl = TemporalMemory::GetTimeline();
    
    if (tl.size() < 2) {
        return {"trend", "insufficient_data"};
    }
    
    // Simple trend detection: compare first and last
    bool growing = tl.size() > 10;
    return {
        {"trend", growing ? "accumulating" : "stable"},
        {"samples", tl.size()}
    };
}
