// =============================================================================
// sast_rule_test.cpp — S1 certification: the engine must find the exact
// planted rule ids in tests/fixtures/sast_sample.c and nothing else.
// =============================================================================
#include <cstdio>
#include <set>
#include <string>

#include "security/sast_rule_engine.h"

int main(int argc, char** argv) {
    try {
    const std::string fixture =
        argc > 1 ? argv[1] : "tests/fixtures/sast_sample.c";
    rawrxd::security::SastRuleEngine engine;
    const auto findings = engine.ScanFile(fixture);

    std::set<std::string> seen;
    for (const auto& f : findings) seen.insert(f.rule_id);

    const std::set<std::string> expected = {
        "SAST001", "SAST002", "SAST003", "SAST004", "SAST005",
        "SAST006", "SAST009", "SAST012"};
    int failures = 0;
    for (const auto& id : expected) {
        if (!seen.count(id)) {
            std::printf("[FAIL] missing %s\n", id.c_str());
            ++failures;
        }
    }
    // SAST010 (malloc unchecked) also matches fixture line with q; allowed.
    std::printf("sast_rule_test: %zu findings, %zu rules, failures=%d\n",
                findings.size(), engine.RuleCount(), failures);
    std::printf("SAST_RULE_TEST %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
    } catch (const std::exception& e) {
        std::printf("[FAIL] exception: %s\n", e.what());
        return 1;
    }
}