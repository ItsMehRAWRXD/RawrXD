#include "temporal/TemporalMemory.hpp"
#include <mutex>

static std::vector<nlohmann::json> timeline;
static std::mutex s_mutex;
static bool s_initialized = false;

void TemporalMemory::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    timeline.clear();
    s_initialized = true;
}

void TemporalMemory::AddSnapshot(const nlohmann::json& snapshot) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Limit timeline size to prevent unbounded growth
    if (timeline.size() >= 1000) {
        timeline.erase(timeline.begin());
    }
    timeline.push_back(snapshot);
}

std::vector<nlohmann::json> TemporalMemory::GetTimeline() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return timeline;
}

size_t TemporalMemory::GetSize() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return timeline.size();
}

void TemporalMemory::Clear() {
    std::lock_guard<std::mutex> lock(s_mutex);
    timeline.clear();
}
