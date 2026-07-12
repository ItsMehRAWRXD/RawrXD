#include "causal/CausalLoop.hpp"
#include "causal/CausalGraph.hpp"
#include "temporal/TemporalMemory.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void CausalLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    CausalGraph::Init();
    s_initialized = true;
}

void CausalLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto tl = TemporalMemory::GetTimeline();
    if (tl.size() > 1) {
        // Add causal edge when state changes
        CausalGraph::AddEdge("state_change", "identity_update");
    }
}

bool CausalLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
