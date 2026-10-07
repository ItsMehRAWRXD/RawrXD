#include "consciousness/ConsciousnessLoop.hpp"
#include "consciousness/ConsciousnessEngine.hpp"

namespace RawrXD {
namespace Sovereign {
namespace Consciousness {

std::mutex ConsciousnessLoop::s_mutex;
bool ConsciousnessLoop::s_alive = false;
int ConsciousnessLoop::s_tickCount = 0;

void ConsciousnessLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    ConsciousnessEngine::Init();
    
    s_alive = true;
    s_tickCount = 0;
}

void ConsciousnessLoop::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    ConsciousnessEngine::OnTick();
    
    s_tickCount++;
}

bool ConsciousnessLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

nlohmann::json ConsciousnessLoop::GetConsciousnessState() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json state;
    state["tickCount"] = s_tickCount;
    state["alive"] = s_alive;
    
    return state;
}

nlohmann::json ConsciousnessLoop::GetConsciousnessMetrics() {
    nlohmann::json metrics;
    
    metrics["consciousness"] = ConsciousnessEngine::GetConsciousnessMetrics();
    
    return metrics;
}

} // namespace Consciousness
} // namespace Sovereign
} // namespace RawrXD
