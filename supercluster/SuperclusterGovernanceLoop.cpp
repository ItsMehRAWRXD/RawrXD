#include "supercluster/SuperclusterGovernanceLoop.hpp"
#include "supercluster/SuperclusterGovernanceEngine.hpp"

namespace Supercluster {

bool SuperclusterGovernanceLoop::s_initialized = false;
int64_t SuperclusterGovernanceLoop::s_tickCount = 0;
float SuperclusterGovernanceLoop::s_governanceCoherence = 1.0f;
float SuperclusterGovernanceLoop::s_interRegionalStability = 1.0f;

void SuperclusterGovernanceLoop::Init() {
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
    s_governanceCoherence = 1.0f;
    s_interRegionalStability = 1.0f;
    
    SuperclusterGovernanceEngine::Init();
}

void SuperclusterGovernanceLoop::OnTick() {
    if (!s_initialized) return;
    s_tickCount++;
    
    SuperclusterGovernanceEngine::OnTick();
    
    float currentCoherence = SuperclusterGovernanceEngine::CalculateGovernanceCoherence();
    float currentStability = SuperclusterGovernanceEngine::CalculateInterRegionalStability();
    
    s_governanceCoherence = (s_governanceCoherence * 0.99f) + (currentCoherence * 0.01f);
    s_interRegionalStability = (s_interRegionalStability * 0.99f) + (currentStability * 0.01f);
}

bool SuperclusterGovernanceLoop::IsAlive() {
    return s_initialized;
}

void SuperclusterGovernanceLoop::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
    SuperclusterGovernanceEngine::Shutdown();
}

nlohmann::json SuperclusterGovernanceLoop::GetLoopState() {
    nlohmann::json state;
    state["initialized"] = s_initialized;
    state["tickCount"] = s_tickCount;
    state["governanceCoherence"] = s_governanceCoherence;
    state["interRegionalStability"] = s_interRegionalStability;
    return state;
}

nlohmann::json SuperclusterGovernanceLoop::GetLoopMetrics() {
    nlohmann::json metrics;
    metrics["tickCount"] = s_tickCount;
    metrics["governanceCoherence"] = s_governanceCoherence;
    metrics["interRegionalStability"] = s_interRegionalStability;
    metrics["governanceMetrics"] = SuperclusterGovernanceEngine::GetGovernanceMetrics();
    return metrics;
}

} // namespace Supercluster
