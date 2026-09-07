#pragma once
#include "rawr_session_state.hpp"
#include "rawr_agent_errors.hpp"
#include <string>
#include <vector>
namespace rawr {
enum class AgentPhase : int {
    Plan = 0, Inspect, Patch, Build, Test, Revise, Report, Done, Blocked
};
struct AgentState {
    SessionState session;
    AgentPhase phase = AgentPhase::Plan;
    AgentError lastError = AgentError::Ok;
    std::vector<std::string> planSteps;
    int stepIndex = 0;
    bool done = false;
    bool blocked = false;
    std::string blocker;
};
} // namespace rawr
