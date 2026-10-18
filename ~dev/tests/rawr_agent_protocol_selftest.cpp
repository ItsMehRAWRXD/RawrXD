// ============================================================================
// rawr_agent_protocol_selftest.cpp — RAWR_AGENT_PROTOCOL_SELFTEST_001
// Deterministic regression guard for the model-reply tool-call parser +
// registry-canonical name matching. No model, no GPU — pure parse cases
// against the EXACT production parser (parseModelReplyForTest).
//
// Root cause being guarded: registry IDs are canonicalized ('workspace.list'
// -> 'workspace-list'); the model emits the dotted catalog spelling. Every
// equivalent spelling must resolve to the same registered tool.
// ============================================================================
#include <cctype>
#include <cstdio>
#include <string>
#include <vector>

#include "rawr_agent.hpp"

using namespace rawrxd::agent;

namespace {

int failures = 0;
int parseFailures = 0;
int canonFailures = 0;

// Registry membership through the same canonicalization the registry uses.
bool isKnownCanonical(const std::string& name,
                      const std::vector<std::string>& registered) {
    auto canon = [](const std::string& s) {
        std::string out;
        for (char c : s) {
            const unsigned char u = static_cast<unsigned char>(c);
            if (u == '.' || u == '-' || u == '_' || u == '/' || u == '\\')
                continue;
            out.push_back(static_cast<char>(std::tolower(u)));
        }
        return out;
    };
    const std::string key = canon(name);
    for (const auto& n : registered)
        if (canon(n) == key) return true;
    return false;
}

void expectTool(const std::string& raw,
                const std::vector<std::string>& tools) {
    const ProtocolParseResultForTest p = parseModelReplyForTest(raw);
    if (!p.isTool) {
        std::printf("FAIL(parse)          : %s\n", raw.c_str());
        ++parseFailures;
        ++failures;
        return;
    }
    if (!isKnownCanonical(p.tool, tools)) {
        std::printf("FAIL(canonicalize)   : '%s' from '%s'\n", p.tool.c_str(),
                    raw.c_str());
        ++canonFailures;
        ++failures;
        return;
    }
    std::printf("PASS: %-52s -> %-16s args=%s\n", raw.c_str(), p.tool.c_str(),
                p.args.c_str());
}

} // namespace

int main() {
    std::printf("GATE=RAWR_AGENT_PROTOCOL_SELFTEST_001\n");

    // Same tool surface the agent loop registers (registry-canonical IDs).
    const std::vector<std::string> tools = {
        "workspace-list", "file-read",   "code-search", "symbol-find",
        "symbol-references", "git-status", "git-diff",  "build-target",
        "test-run",          "audit-add-candidate", "audit-review",
        "audit-files-reviewed", "audit-coverage",
    };
    setKnownToolNames(tools);

    int cases = 0;
    auto check = [&](const std::string& raw) {
        ++cases;
        expectTool(raw, tools);
    };

    // The six canonicalization cases from the spec — every spelling of the
    // same tool must resolve identically.
    check("workspace.list {\"limit\":100}");
    check("workspace-list {\"limit\":100}");
    check("<tool>workspace.list</tool>\n<args>{\"limit\":100}</args>");
    check("```workspace.list {\"limit\":100}```");
    check("audit.coverage {}");
    check("audit-coverage {}");

    std::printf("CASES=%d\n", cases);
    std::printf("PARSE_FAILURES=%d\n", parseFailures);
    std::printf("CANONICALIZATION_FAILURES=%d\n", canonFailures);
    const bool pass = failures == 0;
    std::printf("RAWR_AGENT_PROTOCOL_SELFTEST_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}