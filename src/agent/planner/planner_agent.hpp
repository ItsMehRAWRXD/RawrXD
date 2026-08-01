#pragma once

#include <string>
#include <vector>
#include "../core/agent_controller.hpp"

namespace rawrxd {
namespace agent {

struct PlanStep {
    std::string action;
    std::string target;
    std::string description;
    std::vector<std::string> dependencies;
};

struct AgentPlan {
    bool valid;
    std::string description;
    std::string reasoning;
    std::vector<PlanStep> steps;
};

class PlannerAgent {
public:
    PlannerAgent();
    ~PlannerAgent();

    bool initialize();
    AgentPlan generatePlan(const TaskRequest& request);
};

} // namespace agent
} // namespace rawrxd
