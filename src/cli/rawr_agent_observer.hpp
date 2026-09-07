#pragma once
#include "rawr_output_router.hpp"
#include "rawr_agent_state.hpp"
namespace rawr {
inline void Observe(const AgentState& a, const char* msg) {
    Diag("[agent phase=%d step=%d] %s\n", (int)a.phase, a.stepIndex,
         msg ? msg : "");
}
} // namespace rawr
