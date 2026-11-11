#include "spirituality/SpiritualityLoop.hpp"
#include "spirituality/TranscendenceEngine.hpp"

namespace RawrXD {
namespace Sovereign {
namespace Spirituality {

std::mutex SpiritualityLoop::s_mutex;
bool SpiritualityLoop::s_alive = false;
int SpiritualityLoop::s_tickCount = 0;

void SpiritualityLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    TranscendenceEngine::Init();
    
    s_alive = true;
    s_tickCount = 0;
}

void SpiritualityLoop::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    TranscendenceEngine::OnTick();
    
    s_tickCount++;
}

bool SpiritualityLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

nlohmann::json SpiritualityLoop::GetSpiritualityState() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json state;
    state["tickCount"] = s_tickCount;
    state["alive"] = s_alive;
    
    return state;
}

nlohmann::json SpiritualityLoop::GetSpiritualityMetrics() {
    nlohmann::json metrics;
    
    metrics["transcendence"] = TranscendenceEngine::GetSpiritualityMetrics();
    
    return metrics;
}

} // namespace Spirituality
} // namespace Sovereign
} // namespace RawrXD
