// =============================================================================
// dependency_rule_test.cpp — S3 certification: advisories fire correctly.
// =============================================================================
#include <cstdio>
#include <set>
#include <string>

#include "security/dependency_audit.h"

int main(int argc, char** argv) {
    try {
        const std::string dir = argc > 1 ? argv[1] : "tests/fixtures";
        rawrxd::security::DependencyAuditor auditor;
        const auto deps = auditor.ScanTree(dir);
        const auto adv = auditor.Audit(deps);
        std::set<std::string> flagged;
        for (const auto& a : adv) flagged.insert(a.dependency);

        int failures = 0;
        const std::set<std::string> expected = {
            "lodash", "minimist", "requests", "py"};
        for (const auto& id : expected) {
            if (!flagged.count(id)) {
                std::printf("[FAIL] missing advisory %s\n", id.c_str());
                ++failures;
            }
        }
        if (flagged.count("left-pad") || flagged.count("flask")) {
            std::printf("[FAIL] false positive on clean dependency\n");
            ++failures;
        }
        // Version comparison sanity.
        if (rawrxd::security::CompareVersions("4.17.21", "4.17.20") <= 0 ||
            rawrxd::security::CompareVersions("2.31.0", "2.25.1") <= 0 ||
            rawrxd::security::CompareVersions("1.2.6", "1.2.5") <= 0) {
            std::printf("[FAIL] version comparison wrong\n");
            ++failures;
        }
        std::printf("dependency_rule_test: %zu deps, %zu advisories, failures=%d\n",
                    deps.size(), adv.size(), failures);
        std::printf("DEPENDENCY_RULE_TEST %s\n", failures == 0 ? "PASS" : "FAIL");
        return failures == 0 ? 0 : 1;
    } catch (const std::exception& e) {
        std::printf("[FAIL] exception: %s\n", e.what());
        return 1;
    }
}