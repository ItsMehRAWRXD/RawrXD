#pragma once
#include "AgentToolRegistry.hpp"

namespace RawrXD::Agentic {

// Registers adapters only. Execution stays inside RawrXD::Agent::ToolRegistry.
void RegisterLegacyRawrXDToolProviders(AgentToolRegistry& authority);

} // namespace RawrXD::Agentic
