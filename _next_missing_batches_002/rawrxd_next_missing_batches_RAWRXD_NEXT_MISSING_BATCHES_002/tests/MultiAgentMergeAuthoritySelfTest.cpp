#include "agentic/MultiAgentMergeAuthority.hpp"
#include <iostream>
#include <string>

using namespace RawrXD::Agentic;

int main() {
    std::string file = "one\ntwo\nthree\nfour";
    AgentToolRegistry registry;
    registry.registerTool({"read-file",{},"read"}, [&](const ToolRequest&, ToolContext&) {
        return ToolResult{0, file, {}};
    });
    registry.registerTool({"write-file",{},"write"}, [&](const ToolRequest& r, ToolContext&) {
        file = r.stdin_text; return ToolResult{};
    });

    MultiAgentMergeAuthority authority(registry);
    MergeProposal proposal;
    proposal.file = "demo.cpp";
    proposal.baseHash = MultiAgentMergeAuthority::contentHash(file);
    proposal.edits = {
        {1,2,2,"TWO"},
        {2,4,4,"FOUR"}
    };
    const auto applied = authority.mergeAndApply(proposal, ".");
    if (applied.status != MergeStatus::Applied) return 1;
    if (file != "one\nTWO\nthree\nFOUR") return 2;

    MergeProposal conflict;
    conflict.file = "demo.cpp";
    conflict.baseHash = MultiAgentMergeAuthority::contentHash(file);
    conflict.edits = {
        {1,2,3,"A"},
        {2,3,3,"B"}
    };
    const auto c = authority.mergeAndApply(conflict, ".");
    if (c.status != MergeStatus::Conflict || c.conflictCount != 1) return 3;
    if (authority.receipt().conflictsDetected != 1 || authority.receipt().authorityWrites != 1) return 4;
    if (!authority.receipt().pass()) return 5;
    std::cout << authority.receipt().text();
    return 0;
}
