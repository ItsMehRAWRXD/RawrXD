#include "cosmic/CosmicWebLoop.hpp"
#include "cosmic/CosmicWebEngine.hpp"

namespace Cosmic {

bool CosmicWebLoop::s_initialized = false;
int64_t CosmicWebLoop::s_tickCount = 0;
float CosmicWebLoop::s_webCoherence = 1.0f;
float CosmicWebLoop::s_webStability = 1.0f;

void CosmicWebLoop::Init() {
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
    s_webCoherence = 1.0f;
    s_webStability = 1.0f;
    
    CosmicWebEngine::Init();
}

void CosmicWebLoop::OnTick() {
    if (!s_initialized) return;
    s_tickCount++;
    
    CosmicWebEngine::OnTick();
    
    float currentCoherence = CosmicWebEngine::CalculateCosmicCoherence();
    float currentStability = CosmicWebEngine::CalculateCosmicStability();
    
    s_webCoherence = (s_webCoherence * 0.99f) + (currentCoherence * 0.01f);
    s_webStability = (s_webStability * 0.99f) + (currentStability * 0.01f);
}

bool CosmicWebLoop::IsAlive() {
    return s_initialized;
}

void CosmicWebLoop::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
    CosmicWebEngine::Shutdown();
}

nlohmann::json CosmicWebLoop::GetLoopState() {
    nlohmann::json state;
    state["initialized"] = s_initialized;
    state["tickCount"] = s_tickCount;
    state["webCoherence"] = s_webCoherence;
    state["webStability"] = s_webStability;
    return state;
}

nlohmann::json CosmicWebLoop::GetLoopMetrics() {
    nlohmann::json metrics;
    metrics["tickCount"] = s_tickCount;
    metrics["webCoherence"] = s_webCoherence;
    metrics["webStability"] = s_webStability;
    metrics["cosmicMetrics"] = CosmicWebEngine::GetCosmicMetrics();
    return metrics;
}

} // namespace Cosmic
