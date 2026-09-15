#pragma once
// =============================================================================
// AgentToolAuthority.hpp — CAS Single-Authority Pointer & Snapshot
// =============================================================================
// Provides a compare-and-swap (CAS) pointer to the *one* AgentToolRegistry
// singleton. All surfaces must acquire the authority pointer before dispatch.
//
// Gate: RAWRXD_AGENT_TOOL_AUTHORITY_001
//   - All 5 surfaces (CLI, GUI, Headless, Swarm, AgenticLoop) must reach
//     AgentToolRegistry through this authority.
//   - Any bypass increments the bypass_* counter and fails GatePass().
// =============================================================================

#include "ToolRegistry.h"
#include <atomic>

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Snapshot — captured metrics for audit & gate verification
// ---------------------------------------------------------------------------
struct AgentToolAuthoritySnapshot {
    uint64_t reach_cli{0};
    uint64_t reach_gui{0};
    uint64_t reach_headless{0};
    uint64_t reach_swarm{0};
    uint64_t reach_agentic_loop{0};

    uint64_t bypass_cli{0};
    uint64_t bypass_gui{0};
    uint64_t bypass_headless{0};
    uint64_t bypass_swarm{0};
    uint64_t bypass_agentic_loop{0};

    uint64_t total_dispatches{0};
    uint64_t unknown_tool_dispatches{0};
    uint64_t validation_failures{0};

    bool GatePass() const {
        return bypass_cli == 0 && bypass_gui == 0 && bypass_headless == 0
            && bypass_swarm == 0 && bypass_agentic_loop == 0
            && reach_cli >= 1 && reach_gui >= 1 && reach_headless >= 1
            && reach_swarm >= 1 && reach_agentic_loop >= 1;
    }

    static AgentToolAuthoritySnapshot FromMetrics(const AgentToolAuthorityMetrics& m) {
        return {
            m.reach_cli.load(),         m.reach_gui.load(),         m.reach_headless.load(),
            m.reach_swarm.load(),       m.reach_agentic_loop.load(),
            m.bypass_cli.load(),        m.bypass_gui.load(),        m.bypass_headless.load(),
            m.bypass_swarm.load(),      m.bypass_agentic_loop.load(),
            m.total_dispatches.load(),  m.unknown_tool_dispatches.load(),
            m.validation_failures.load()
        };
    }
};

// ---------------------------------------------------------------------------
// AgentToolAuthority — CAS pointer to the single registry
// ---------------------------------------------------------------------------
class AgentToolAuthority {
public:
    // Compare-and-swap: only succeeds if current == expected (nullptr by default)
    static bool Register(AgentToolRegistry* expected, AgentToolRegistry* desired);

    // Dereference — returns nullptr if no authority registered (fail-closed)
    static AgentToolRegistry* Get();

    // Convenience: checked dispatch — returns error if authority missing
    static AgentToolResult Dispatch(const AgentToolRequest& req);

    // Snapshot for audit gates
    static AgentToolAuthoritySnapshot CaptureSnapshot();

    // Helper: increment a bypass counter (call from legacy / unwired sites)
    static void IncrementBypass(AgentToolSurface surface);

    // Reset the CAS pointer (test / bootstrap only)
    static void ResetForTests();

private:
    static std::atomic<AgentToolRegistry*> s_instance;
};

} // namespace Agent
} // namespace RawrXD
