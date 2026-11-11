#pragma once
// ============================================================================
// rawr_agent_dispatch.hpp — RAWR_AGENT_DISPATCH_001
// Binds the read-only tool set to the existing AgentToolRegistry authority.
// Tools: workspace.list, file.read, code.search, symbol.find,
//        symbol.references, git.status, git.diff, build.target, test.run,
//        plus audit.* ledger tools (audit.add_candidate, audit.review,
//        audit.coverage, audit.files_reviewed).
// No write tools. No shell. Audit ledger is the only mutable state and it
// is runtime-owned.
// ============================================================================
#include <string>
#include <vector>

#include "rawr_audit_state.hpp"

namespace RawrXD::Agentic {
class AgentToolRegistry;
}

namespace rawrxd {
namespace agent {

// Registers the read-only audit tool set on the given authority. The ledger
// pointer must outlive the registry use (owned by the agent loop).
void registerAuditToolProviders(RawrXD::Agentic::AgentToolRegistry& authority,
                               AuditLedger* ledger);

// The canonical tool list exposed to the model (serialized into the system
// prompt of every agent session).
std::string agentToolCatalogJson();

} // namespace agent
} // namespace rawrxd