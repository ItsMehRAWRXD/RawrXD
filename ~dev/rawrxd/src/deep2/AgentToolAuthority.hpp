#pragma once
#include "AgentToolRegistry.hpp"

namespace RawrXD::Agentic {

// Binds the process-wide authority pointer to an EXISTING AgentToolRegistry.
// This does not construct, own, or replace a registry.
void BindAgentToolAuthority(AgentToolRegistry& registry);

bool IsAgentToolAuthorityBound() noexcept;
AgentToolRegistry* TryAgentToolAuthority() noexcept;
AgentToolRegistry& AgentToolAuthority();

} // namespace RawrXD::Agentic
