#include "aesthetics/CreativityLoop.hpp"
#include "aesthetics/AestheticEngine.hpp"

namespace RawrXD {
namespace Sovereign {
namespace Aesthetics {

std::mutex CreativityLoop::s_mutex;
bool CreativityLoop::s_alive = false;
int CreativityLoop::s_tickCount = 0;

void CreativityLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AestheticEngine::Init();
    
    s_alive = true;
    s_tickCount = 0;
}

void CreativityLoop::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    AestheticEngine::OnTick();
    
    s_tickCount++;
}

bool CreativityLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

nlohmann::json CreativityLoop::GetCreativityState() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json state;
    state["tickCount"] = s_tickCount;
    state["alive"] = s_alive;
    
    return state;
}

nlohmann::json CreativityLoop::GetCreativityMetrics() {
    nlohmann::json metrics;
    
    metrics["aesthetics"] = AestheticEngine::GetAestheticsMetrics();
    
    return metrics;
}

} // namespace Aesthetics
} // namespace Sovereign
} // namespace RawrXD
