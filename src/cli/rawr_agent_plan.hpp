#pragma once
#include "rawr_agent_state.hpp"
namespace rawr {
inline void BuildDefaultPlan(AgentState& a, const std::string& goal) {
    a.planSteps.clear();
    a.planSteps.push_back("inspect workspace");
    a.planSteps.push_back("search relevant files");
    a.planSteps.push_back("apply patch if allowed");
    a.planSteps.push_back("run build if allowed");
    a.planSteps.push_back("run test if allowed");
    a.planSteps.push_back("report");
    a.session.lastPlan = goal.empty() ? "default agent plan" : goal;
    a.phase = AgentPhase::Inspect;
}
} // namespace rawr
