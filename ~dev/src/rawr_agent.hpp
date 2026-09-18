#pragma once
// ============================================================================
// rawr_agent.hpp — RAWR_AGENT_LOOP_001 / RAWR_AUDIT_COVERAGE_001
// One unified agent loop on top of the shared Deep2 runner. The model drives
// tool calls; the runtime owns the ledger, step bounds, and completion.
// ============================================================================
#include <cstdint>
#include <string>

#include "rawr_audit_state.hpp"

namespace rawrxd {
namespace runstream {
struct RunStreamReceipt;
class RawrDeep2Runner;
}

namespace agent {

struct AgentResult {
    int         exitCode        = 1;
    uint32_t    steps           = 0;
    uint32_t    toolCalls       = 0;
    uint32_t    toolFailures    = 0;
    uint64_t    generatedTokens = 0;
    bool        coverageComplete = false;
    bool        reachedFinal    = false;
    bool        sawToolResult   = false;   // a generation ran with real tool output in context
    std::string firstTool;                // first successfully dispatched tool name
    std::string finalText;
    std::string status          = "FAIL";
};

struct AgentOptions {
    uint32_t    maxSteps    = 64;
    uint32_t    maxTokensPerStep = 512;
    std::string systemPrompt;   // empty -> audit default
};

// Known tool names for lenient reply parsing (filled by dispatch registration).
void setKnownToolNames(const std::vector<std::string>& names);

// RAWR_AGENT_PROTOCOL_SELFTEST_001 hook: deterministic parse of a raw model
// reply using the EXACT production parser + canonical matching. Exposed so
// the self-test is a behavioral lock on real code, not a duplicate.
struct ProtocolParseResultForTest {
    bool        isTool  = false;
    bool        isFinal = false;
    std::string tool;
    std::string args;
};
ProtocolParseResultForTest parseModelReplyForTest(const std::string& raw);

// Runs one agent session. The runner must already be loaded (shared engine
// with `rawr run`). Workspace root scopes the ledger and tools.
// requireCoverage=false certifies the LOOP only (tool dispatch + result in
// context) without demanding full repository coverage — the RAWR_AGENT_LOOP_001
// certification gate.
AgentResult run_agent_session(runstream::RawrDeep2Runner& runner,
                              const std::string& userRequest,
                              const std::filesystem::path& workspaceRoot,
                              const AgentOptions& options,
                              bool auditMode,
                              bool requireCoverage = true);

} // namespace agent
} // namespace rawrxd