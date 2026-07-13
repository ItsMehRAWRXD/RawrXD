#include "unity/UnityLoop.hpp"
#include "unity/SynthesisEngine.hpp"

namespace RawrXD {
namespace Sovereign {
namespace Unity {

std::mutex UnityLoop::s_mutex;
bool UnityLoop::s_alive = false;
int UnityLoop::s_tickCount = 0;

void UnityLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    SynthesisEngine::Init();
    
    s_alive = true;
    s_tickCount = 0;
}

void UnityLoop::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    SynthesisEngine::OnTick();
    
    s_tickCount++;
}

bool UnityLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

nlohmann::json UnityLoop::GetUnityState() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json state;
    state["tickCount"] = s_tickCount;
    state["alive"] = s_alive;
    
    return state;
}

nlohmann::json UnityLoop::GetUnityMetrics() {
    nlohmann::json metrics;
    
    metrics["synthesis"] = SynthesisEngine::GetSynthesisMetrics();
    metrics["coherence"] = SynthesisEngine::GetCoherenceReport();
    
    return metrics;
}

} // namespace Unity
} // namespace Sovereign
} // namespace RawrXD
