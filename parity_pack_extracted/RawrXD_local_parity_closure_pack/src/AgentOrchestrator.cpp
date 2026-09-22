#include "rawrxd/closure/AgentOrchestrator.hpp"
#include <unordered_map>

namespace rawrxd::closure {

AgentRunResult AgentOrchestrator::run(std::string_view objective, uint32_t max_steps) {
    AgentRunResult result;
    std::string observation = "BEGIN";
    std::unordered_map<uint64_t, uint32_t> repeated;

    for (uint32_t step = 0; step < max_steps; ++step) {
        result.steps = step + 1;
        AgentAction a = reasoner_.next(objective, observation, step);
        if (a.done) {
            result.ok = a.success;
            result.report = std::move(a.report);
            return result;
        }
        if (!a.tool) {
            result.report = "reasoner returned neither terminal result nor tool action";
            return result;
        }

        const std::string signature =
            a.tool->name + "\n" + a.tool->argument + "\n" +
            (a.tool->path ? a.tool->path->generic_string() : "");
        const uint64_t h = fnv1a64(signature);
        if (++repeated[h] >= 3) {
            result.loop_detected = true;
            result.report = "identical tool action repeated three times";
            return result;
        }

        ToolResult tr = tools_.invoke(std::move(*a.tool));
        observation = tr.ok ? "TOOL_PASS\n" : "TOOL_FAIL\n";
        observation += tr.output;
    }
    result.report = "maximum agent steps reached";
    return result;
}

} // namespace rawrxd::closure
