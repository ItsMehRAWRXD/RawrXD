#include "causal/Counterfactual.hpp"
#include "temporal/TemporalMemory.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void Counterfactual::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = true;
}

nlohmann::json Counterfactual::Evaluate(const nlohmann::json& hypothetical) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto tl = TemporalMemory::GetTimeline();
    
    bool diverged = tl.size() > 0 && tl.back() != hypothetical;
    
    return {
        {"hypothetical", hypothetical},
        {"diverged", diverged},
        {"timeline_size", tl.size()}
    };
}

nlohmann::json Counterfactual::CompareWithActual(const nlohmann::json& hypothetical) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto tl = TemporalMemory::GetTimeline();
    
    if (tl.size() == 0) {
        return {"error", "no_timeline_data"};
    }
    
    auto actual = tl.back();
    bool matches = (actual == hypothetical);
    
    return {
        {"matches_actual", matches},
        {"actual_state", actual},
        {"hypothetical_state", hypothetical}
    };
}
