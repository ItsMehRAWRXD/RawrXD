#include "../../include/rawrxd/closure/AgentOrchestrator.hpp"

namespace rawrxd::closure {

AgentRunResult AgentOrchestrator::run(std::string_view objective, uint32_t max_steps) {
    std::string observation;
    for (uint32_t step = 0; step < max_steps; ++step) {
        auto action = reasoner_.next(objective, observation, step);
        if (action.done)
            return {action.success, false, step + 1, action.report};
        if (!action.tool)
            return {false, false, step + 1, "no tool and not done"};
        auto result = tools_.invoke(*action.tool);
        observation = result.output;
    }
    return {false, true, max_steps, "max steps reached"};
}

} // namespace rawrxd::closure
