// =============================================================================
// secrets_rule_test.cpp — S2 certification: planted secrets must be found.
// =============================================================================
#include <cstdio>
#include <set>
#include <string>

#include "security/secrets_scanner.h"

int main(int argc, char** argv) {
    try {
        const std::string fixture =
            argc > 1 ? argv[1] : "tests/fixtures/secrets_sample.txt";
        rawrxd::security::SecretsScanner scanner;
        const auto findings = scanner.ScanPath(fixture);
        std::set<std::string> seen;
        for (const auto& f : findings) seen.insert(f.rule_id);
        const std::set<std::string> expected = {
            "AWS_ACCESS_KEY", "GITHUB_TOKEN", "SLACK_TOKEN",
            "GOOGLE_API_KEY", "JWT", "CREDENTIAL_ASSIGN", "PRIVATE_KEY"};
        int failures = 0;
        for (const auto& id : expected) {
            if (!seen.count(id)) {
                std::printf("[FAIL] missing %s\n", id.c_str());
                ++failures;
            }
        }
        // Redaction must hide the middle of every match.
        for (const auto& f : findings) {
            if (f.match.find("...") == std::string::npos &&
                f.match.size() > 8) {
                std::printf("[FAIL] unredacted match for %s\n", f.rule_id.c_str());
                ++failures;
            }
        }
        std::printf("secrets_rule_test: %zu findings, failures=%d\n",
                    findings.size(), failures);
        std::printf("SECRETS_RULE_TEST %s\n", failures == 0 ? "PASS" : "FAIL");
        return failures == 0 ? 0 : 1;
    } catch (const std::exception& e) {
        std::printf("[FAIL] exception: %s\n", e.what());
        return 1;
    }
}