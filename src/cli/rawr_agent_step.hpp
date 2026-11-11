#pragma once
#include "rawr_agent_state.hpp"
#include "rawr_agent_observer.hpp"
namespace rawr {
inline bool AdvanceStep(AgentState& a) {
    if (a.blocked || a.done) return false;
    ++a.stepIndex;
    if (a.stepIndex >= (int)a.planSteps.size()) {
        a.phase = AgentPhase::Done;
        a.done = true;
        return false;
    }
    Observe(a, a.planSteps[a.stepIndex].c_str());
    return true;
}
} // namespace rawr
