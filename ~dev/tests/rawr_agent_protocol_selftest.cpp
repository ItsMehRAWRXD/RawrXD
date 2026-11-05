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
    check("```json\nworkspace.list {\"limit\":100}\n```");
    check("audit.coverage {}");
    check("audit-coverage {}");

    // B9: Fifteen parser cases using the same portable parser contract.
    auto reject = [&](const std::string& raw) {
        ++cases;
        const auto p = parseModelReplyForTest(raw);
        if (p.isTool || p.isFinal) {
            std::printf("FAIL(expected rejection): %s\n", raw.c_str());
            ++parseFailures; ++failures;
        }
    };
    auto finalReply = [&](const std::string& raw) {
        ++cases;
        const auto p = parseModelReplyForTest(raw);
        if (!p.isFinal || p.isTool) {
            std::printf("FAIL(expected final): %s\n", raw.c_str());
            ++parseFailures; ++failures;
        }
    };
    check("<tool>file.read</tool><args>{\"path\":\"a.cpp\"}</args>"); // 01
    check("<tool>audit.coverage</tool><args>{}</args>"); // 02
    check("file.read {\"path\":\"a.cpp\"}"); // 03
    check("code.search {\"query\":\"TODO\"}"); // 04
    check("<tool>workspace.list</tool><args></args>"); // 05
    reject("<tool>file.read"); // 06
    reject("<tool>file.read</tool><args>{}</args><tool>file.read</tool><args>{}</args>"); // 07
    reject("<tool>file.read</tool><args>{}</args><args>{}</args>"); // 08
    reject("<tool>file.read</tool><args>{}</args></args>"); // 09
    reject("<args>{}</args>"); // 10
    reject("<tool>file.read</tool><args>not-json</args>"); // 11
    reject("<args>{}</args><tool>file.read</tool>"); // 12
    reject("<tool>file.read</tool><args>{}</args></tool>"); // 13
    finalReply("Task complete."); // 14
    finalReply("Plain response with literal `backticks`."); // 15

    // Batch 11: reject tool-call framing contamination (15 cases).
    reject("preface<tool>file.read</tool><args>{}</args>"); // 01
    reject("<tool>file.read</tool><args>{}</args>suffix"); // 02
    reject("<tool>file.read</tool>noise<args>{}</args>"); // 03
    reject(" \n<tool>file.read</tool><args>{}</args>suffix"); // 04
    reject("<tool>file.read</tool><args>{}</args><|im_end|>"); // 05
    reject("<tool>file.read</tool><args>{}</args><tool>"); // 06
    reject("<tool>file.read</tool><args>{}</args>DONE"); // 07
    reject("<tool>file.read</tool> extra <args>{}</args>"); // 08
    reject("assistant:\n<tool>file.read</tool><args>{}</args>"); // 09
    reject("<tool>file.read</tool><args>{}</args>\nTask complete."); // 10
    reject("<tool>file.read</tool>\nprose\n<args>{}</args>"); // 11
    reject("<tool>file.read</tool><args>{}</args>\n<args>"); // 12
    reject("<tool>file.read</tool><args>{}</args>\n</tool>"); // 13
    reject("<tool>file.read</tool><args>{}</args>\n<tool>other"); // 14
    check(" \n<tool>file.read</tool>\n<args>{}</args>\n "); // 15

    // Batch 12: malformed bare tool-call boundary matrix (15 cases).
    reject("file.read {\"path\":\"a.cpp\"} trailing"); // 01
    reject("file.read {\"path\":\"a.cpp\"}\nextra"); // 02
    reject("file.read {\"path\":\"a.cpp\"}\nfile.read {}"); // 03
    reject("file.read {\"path\":\"a.cpp\"} {}"); // 04
    reject("file.read {\"path\":\"a.cpp\"} <tool>"); // 05
    reject("file.read {\"path\":\"a.cpp\"} prose"); // 06
    reject("file.read {\"path\":\"a.cpp\"}\nDONE"); // 07
    reject("file.read {\"path\":\"a.cpp\"}\n<|im_end|>"); // 08
    reject("file.read {\"path\":\"a.cpp\"}   extra"); // 09
    reject("file.read {\"path\":\"a.cpp\"}\n\n"); // 10
    reject("file.read {\"path\":\"a.cpp\"} \n"); // 11
    reject("file.read {\"path\":\"a.cpp\"}#comment"); // 12
    reject("file.read {\"path\":\"a.cpp\"} [complete]"); // 13
    check("file.read {\"path\":\"a.cpp\"}"); // 14
    check("audit.coverage {}"); // 15

    std::printf("CASES=%d\n", cases);
    std::printf("PARSE_FAILURES=%d\n", parseFailures);
    std::printf("CANONICALIZATION_FAILURES=%d\n", canonFailures);
    const bool pass = failures == 0;
    std::printf("RAWR_AGENT_PROTOCOL_SELFTEST_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}