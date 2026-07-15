#include "temporal/CausalInference.hpp"
#include "temporal/TemporalMemory.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void CausalInference::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = true;
}

nlohmann::json CausalInference::Infer() {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto tl = TemporalMemory::GetTimeline();
    
    // Detect if last state differs from first
    bool changed = tl.size() > 1 && tl.front() != tl.back();
    
    return {
        {"change_detected", changed},
        {"timeline_length", tl.size()}
    };
}

nlohmann::json CausalInference::DetectChanges() {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto tl = TemporalMemory::GetTimeline();
    
    size_t changes = 0;
    for (size_t i = 1; i < tl.size(); ++i) {
        if (tl[i] != tl[i-1]) {
            changes++;
        }
    }
    
    return {
        {"total_changes", changes},
        {"change_rate", tl.size() > 0 ? (double)changes / tl.size() : 0.0}
    };
}
