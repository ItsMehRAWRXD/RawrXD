#pragma once
#include <cstdint>
#include "AgentToolRegistry.hpp"

namespace RawrXD::Agentic {

// Binds the process-wide authority pointer to an EXISTING AgentToolRegistry.
// This does not construct, own, or replace a registry.
void BindAgentToolAuthority(AgentToolRegistry& registry);

bool IsAgentToolAuthorityBound() noexcept;
AgentToolRegistry* TryAgentToolAuthority() noexcept;
AgentToolRegistry& AgentToolAuthority();

/// Product-execution accessor: throws std::runtime_error if authority is unbound.
/// Use this for all autonomous/product tool paths; never silently fall back.
AgentToolRegistry& RequireAgentToolAuthority();

/// Global counters for authority invocation and bypass detection (relaxed ordering).
extern std::atomic<uint64_t> g_agentToolInvocations;    // incremented at AgentToolRegistry::invoke() boundary
extern std::atomic<uint64_t> g_directAgentToolBypasses;

} // namespace RawrXD::Agentic
