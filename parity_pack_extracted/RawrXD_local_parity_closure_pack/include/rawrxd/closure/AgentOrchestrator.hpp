#pragma once
#include "ToolGateway.hpp"
#include <deque>

namespace rawrxd::closure {

struct AgentAction {
    bool done{};
    bool success{};
    std::string report;
    std::optional<ToolRequest> tool;
};

class IReasoner {
public:
    virtual ~IReasoner() = default;
    virtual AgentAction next(std::string_view objective,
                             std::string_view observation,
                             uint32_t step) = 0;
};

struct AgentRunResult {
    bool ok{};
    bool loop_detected{};
    uint32_t steps{};
    std::string report;
};

class AgentOrchestrator {
public:
    AgentOrchestrator(IReasoner& reasoner, ToolGateway& tools)
        : reasoner_(reasoner), tools_(tools) {}

    AgentRunResult run(std::string_view objective, uint32_t max_steps = 32);

private:
    IReasoner& reasoner_;
    ToolGateway& tools_;
};

} // namespace rawrxd::closure
