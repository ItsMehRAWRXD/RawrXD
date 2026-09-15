// =============================================================================
// AgentToolAuthority.cpp — CAS Single-Authority Pointer Implementation
// =============================================================================
// Gate: RAWRXD_AGENT_TOOL_AUTHORITY_001
//
// Provides the single compare-and-swap (CAS) pointer to the one and only
// AgentToolRegistry. All 5 surfaces (CLI, GUI, Headless, Swarm, AgenticLoop)
// MUST acquire the authority pointer before dispatching any tool.
//
// Any caller that bypasses AgentToolAuthority::Dispatch() and calls
// AgentToolRegistry::Dispatch() directly (or worse, implements its own
// tool execution) must call IncrementBypass() so the gate can detect it.
//
// No exceptions. Fail-closed: if no authority is registered, Dispatch()
// returns an error result.
// =============================================================================

#include "AgentToolAuthority.hpp"

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Static CAS pointer — the single source of truth for tool dispatch
// ---------------------------------------------------------------------------
std::atomic<AgentToolRegistry*> AgentToolAuthority::s_instance{nullptr};

// ---------------------------------------------------------------------------
// Register — compare-and-swap the authority pointer
// ---------------------------------------------------------------------------
bool AgentToolAuthority::Register(AgentToolRegistry* expected, AgentToolRegistry* desired) {
    if (expected == nullptr) {
        // Default bootstrap: only succeeds if no authority is currently set
        AgentToolRegistry* nullExpected = nullptr;
        return s_instance.compare_exchange_strong(
            nullExpected, desired,
            std::memory_order_release, std::memory_order_acquire);
    }
    return s_instance.compare_exchange_strong(
        expected, desired,
        std::memory_order_release, std::memory_order_acquire);
}

// ---------------------------------------------------------------------------
// Get — dereference the authority pointer (fail-closed: nullptr if unset)
// ---------------------------------------------------------------------------
AgentToolRegistry* AgentToolAuthority::Get() {
    return s_instance.load(std::memory_order_acquire);
}

// ---------------------------------------------------------------------------
// Dispatch — checked dispatch through the authority
//
// All 5 surfaces must call this instead of AgentToolRegistry::Dispatch()
// directly. This ensures:
//   1. The authority pointer is valid (fail-closed if not)
//   2. Reach counters are incremented for the calling surface
//   3. The normalized AgentToolRequest contract is enforced
// ---------------------------------------------------------------------------
AgentToolResult AgentToolAuthority::Dispatch(const AgentToolRequest& req) {
    AgentToolRegistry* registry = s_instance.load(std::memory_order_acquire);
    if (registry == nullptr) {
        // Fail-closed: no authority registered
        AgentToolResult result;
        result.success = false;
        result.output = "[AgentToolAuthority] No authority registered — dispatch rejected";
        result.exit_code = -1;
        result.kind = req.kind;
        result.tool_name = req.tool_name;
        return result;
    }

    // Delegate to the normalized dispatch (increments reach counters internally)
    return registry->Dispatch(req);
}

// ---------------------------------------------------------------------------
// CaptureSnapshot — for audit gates and selftest verification
// ---------------------------------------------------------------------------
AgentToolAuthoritySnapshot AgentToolAuthority::CaptureSnapshot() {
    AgentToolRegistry* registry = s_instance.load(std::memory_order_acquire);
    if (registry == nullptr) {
        // Return empty snapshot if no authority registered
        return AgentToolAuthoritySnapshot{};
    }
    return AgentToolAuthoritySnapshot::FromMetrics(registry->GetAuthorityMetrics());
}

// ---------------------------------------------------------------------------
// IncrementBypass — call from legacy / unwired sites
//
// This is the "honesty counter": any code path that performs a tool action
// (read_file, write_file, execute_command, ssa_lift, hotpatch, etc.) WITHOUT
// going through AgentToolAuthority::Dispatch() must call this so the gate
// can detect the bypass and fail GatePass().
// ---------------------------------------------------------------------------
void AgentToolAuthority::IncrementBypass(AgentToolSurface surface) {
    AgentToolRegistry* registry = s_instance.load(std::memory_order_acquire);
    if (registry == nullptr) {
        return; // Cannot record bypass if no authority exists
    }

    auto& m = const_cast<AgentToolAuthorityMetrics&>(registry->GetAuthorityMetrics());
    switch (surface) {
        case AgentToolSurface::CLI:           ++m.bypass_cli; break;
        case AgentToolSurface::GUI:           ++m.bypass_gui; break;
        case AgentToolSurface::Headless:      ++m.bypass_headless; break;
        case AgentToolSurface::Swarm:         ++m.bypass_swarm; break;
        case AgentToolSurface::AgenticLoop:  ++m.bypass_agentic_loop; break;
        default: break;
    }
}

// ---------------------------------------------------------------------------
// ResetForTests — test / bootstrap only
// ---------------------------------------------------------------------------
void AgentToolAuthority::ResetForTests() {
    s_instance.store(nullptr, std::memory_order_release);
}

} // namespace Agent
} // namespace RawrXD