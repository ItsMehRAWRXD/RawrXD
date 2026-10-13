// sovereign_smoke.cpp — regression gate for the Sovereign Agent Core tool layer.
// From the source drop's smoke test: one real search, one cached replay of the
// same request. Fails unless the first call really executed, the second was
// served from the host cache without a second execution, and the first
// succeeded. No model is involved; this is host-side truth only.
#include "agentic/sovereign_agent.hpp"

#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: sovereign_smoke <workspace_root>\n";
        return 2;
    }
    rawrxd::HostTools tools(argv[1]);
    auto a = tools.invoke({"search_text", ".", "AgentRunner"});
    auto b = tools.invoke({"search_text", ".", "AgentRunner"});
    std::cout << a.output << rawrxd::evidence_summary(rawrxd::AgentState{0, {}, {a, b}, 0});
    return a.ok && a.executed && b.cached && !b.executed ? 0 : 1;
}
