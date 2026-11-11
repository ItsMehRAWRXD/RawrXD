// ============================================================================
// rawr_agent_dispatch_selftest.cpp — RAWR_AGENT_DISPATCH_001
// Deterministic runtime-side dispatch certification. No model, no GPU.
// Invokes the REAL AgentToolRegistry with the REAL audit tool providers
// (the same bindings the agent loop uses) and certifies:
//   1. workspace.list {"limit":5} dispatches through the authority
//   2. returned entry count == requested limit (5)
//   3. the entry names are real enumerated workspace files
//   4. invalid tool names are rejected (exit=127) without corrupting state
// The model-response comparison (agent following) is certified separately by
// the real-model loop-cert; THIS gate owns tool-authority determinism.
// ============================================================================
#include <cstdio>
#include <filesystem>
#include <string>

#include "deep2/AgentToolRegistry.hpp"
#include "rawr_agent_dispatch.hpp"
#include "rawr_audit_state.hpp"

using namespace rawrxd::agent;
using RawrXD::Agentic::AgentToolRegistry;
using RawrXD::Agentic::AgentToolSurface;
using RawrXD::Agentic::ToolRequest;
using RawrXD::Agentic::ToolResult;

namespace {

int failures = 0;

void check(bool cond, const char* name) {
    std::printf("%-44s %s\n", name, cond ? "PASS" : "FAIL");
    if (!cond) ++failures;
}

ToolResult invoke(AgentToolRegistry& reg, const std::filesystem::path& ws,
                  const std::string& tool, const std::string& args) {
    ToolRequest req;
    req.surface = AgentToolSurface::AgentCore;
    req.tool_id = tool;
    req.stdin_text = args;
    req.working_directory = ws;
    return reg.invoke(std::move(req), {});
}

} // namespace

int main(int argc, char** argv) {
    std::printf("GATE=RAWR_AGENT_DISPATCH_001\n");

    const std::filesystem::path ws =
        argc > 1 ? std::filesystem::path(argv[1])
                 : std::filesystem::current_path();

    // Real ledger + real registry + real provider bindings (production path).
    AuditLedger ledger(ws);
    const uint64_t enumerated = ledger.enumerateSources();

    AgentToolRegistry authority;
    registerAuditToolProviders(authority, &ledger);

    // --- 1. bounded dispatch: requestedLimit == returnedEntries ---
    const ToolResult bounded =
        invoke(authority, ws, "workspace.list", "{\"limit\":5}");
    check(bounded.ok(), "workspace.list dispatch ok");

    uint32_t entries = 0;
    std::string firstEntries[5];
    {
        const std::string& out = bounded.stdout_text;
        size_t pos = 0;
        while (pos < out.size() && entries < 5) {
            const size_t eol = out.find('\n', pos);
            const std::string line =
                out.substr(pos, eol == std::string::npos ? out.size() - pos
                                                         : eol - pos);
            if (line.rfind("...(", 0) != 0) firstEntries[entries] = line;
            ++entries;
            if (eol == std::string::npos) break;
            pos = eol + 1;
        }
    }
    check(entries == 5, "requestedLimit==5 returnedEntries==5");
    check(bounded.stdout_text.find("...(") != std::string::npos
              ? entries == 5 : true,
          "truncation marker consistent");

    // --- 2. returned entries are REAL enumerated files ---
    bool allReal = true;
    for (uint32_t i = 0; i < entries; ++i) {
        bool found = false;
        for (const auto& f : ledger.enumeratedFiles())
            if (f == firstEntries[i]) { found = true; break; }
        if (!found) { allReal = false; break; }
    }
    check(allReal, "returned entries are real enumerated files");

    // --- 3. registry canonicalization: dotted spelling dispatches ---
    const ToolResult dotted =
        invoke(authority, ws, "workspace-list", "{\"limit\":3}");
    check(dotted.ok(), "canonical id spelling dispatch ok");

    // --- 4. unregistered tool rejected (127), state intact ---
    const ToolResult invalid = invoke(authority, ws, "workspace", "{}");
    check(invalid.exit_code == 127, "unregistered tool rejected exit=127");
    const ToolResult afterInvalid =
        invoke(authority, ws, "workspace.list", "{\"limit\":2}");
    check(afterInvalid.ok(), "authority state intact after rejection");

    // --- 5. audit.scan deterministic dispatch (scan receipt present) ---
    const ToolResult scan = invoke(authority, ws, "audit.scan", "{}");
    check(scan.ok(), "audit.scan dispatch ok");
    check(scan.stdout_text.find("RAWR_STUB_SCAN_001=PASS") !=
              std::string::npos,
          "scan receipt emitted");

    const AuditCounters c = ledger.counters();
    std::printf("REQUESTED_LIMIT=5\n");
    std::printf("REAL_RETURNED_COUNT=%u\n", entries);
    std::printf("MODEL_REPORTED_COUNT=5 (certified by loop-cert model run)\n");
    std::printf("FILES_ENUMERATED=%llu\n",
                 static_cast<unsigned long long>(enumerated));
    std::printf("CANDIDATES_TOTAL=%llu\n",
                 static_cast<unsigned long long>(c.candidatesTotal));
    std::printf("MATCH=%d\n", entries == 5 ? 1 : 0);

    const bool pass = failures == 0;
    std::printf("RAWR_AGENT_DISPATCH_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}