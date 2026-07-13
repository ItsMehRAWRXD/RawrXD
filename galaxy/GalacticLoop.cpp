#include "galaxy/GalacticLoop.hpp"
#include "galaxy/GalacticCoreEngine.hpp"

namespace Galaxy {

bool GalacticLoop::s_initialized = false;
int64_t GalacticLoop::s_tickCount = 0;
float GalacticLoop::s_coherenceBaseline = 1.0f;
float GalacticLoop::s_stabilityBaseline = 1.0f;

void GalacticLoop::Init() {
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
    s_coherenceBaseline = 1.0f;
    s_stabilityBaseline = 1.0f;
    
    GalacticCoreEngine::Init();
}

void GalacticLoop::OnTick() {
    if (!s_initialized) return;
    s_tickCount++;
    
    GalacticCoreEngine::OnTick();
    
    float currentCoherence = GalacticCoreEngine::CalculateGalacticCoherence();
    float currentStability = GalacticCoreEngine::CalculateGalacticStability();
    
    s_coherenceBaseline = (s_coherenceBaseline * 0.99f) + (currentCoherence * 0.01f);
    s_stabilityBaseline = (s_stabilityBaseline * 0.99f) + (currentStability * 0.01f);
}

bool GalacticLoop::IsAlive() {
    return s_initialized;
}

void GalacticLoop::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
    GalacticCoreEngine::Shutdown();
}

nlohmann::json GalacticLoop::GetLoopState() {
    nlohmann::json state;
    state["initialized"] = s_initialized;
    state["tickCount"] = s_tickCount;
    state["coherenceBaseline"] = s_coherenceBaseline;
    state["stabilityBaseline"] = s_stabilityBaseline;
    return state;
}

nlohmann::json GalacticLoop::GetLoopMetrics() {
    nlohmann::json metrics;
    metrics["tickCount"] = s_tickCount;
    metrics["coherenceBaseline"] = s_coherenceBaseline;
    metrics["stabilityBaseline"] = s_stabilityBaseline;
    metrics["galacticMetrics"] = GalacticCoreEngine::GetGalacticMetrics();
    return metrics;
}

} // namespace Galaxy
