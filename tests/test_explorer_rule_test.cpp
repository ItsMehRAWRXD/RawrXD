// =============================================================================
// test_explorer_rule_test.cpp — I5/T3 certification: discovery + verdicts.
// =============================================================================
#include <cstdio>
#include <string>

#include "test_explorer/test_explorer.h"

int main(int argc, char** argv) {
    try {
        const std::string dir = argc > 1 ? argv[1] : "tests/fixtures";
        rawrxd::testing::TestExplorer explorer;
        const auto tests = explorer.Discover(dir);
        int failures = 0;
        if (tests.size() < 2) {
            std::printf("[FAIL] expected >=2 discovered tests, got %zu\n",
                        tests.size());
            ++failures;
        }
        bool sawOk = false, sawBad = false;
        for (const auto& t : tests) {
            if (t.name == "test_ok.cmd") sawOk = true;
            if (t.name == "test_bad.cmd") sawBad = true;
        }
        if (!sawOk || !sawBad) {
            std::printf("[FAIL] discovery missed fixtures (ok=%d bad=%d)\n",
                        sawOk, sawBad);
            ++failures;
        }
        // Run both: exit codes must be 0 and 1 respectively.
        for (const auto& t : tests) {
            if (t.name != "test_ok.cmd" && t.name != "test_bad.cmd") continue;
            const auto r = explorer.Run(t);
            const int expect = (t.name == "test_ok.cmd") ? 0 : 1;
            if (r.exit_code != expect) {
                std::printf("[FAIL] %s exit=%d expected=%d\n", t.name.c_str(),
                            r.exit_code, expect);
                ++failures;
            }
        }
        std::printf("test_explorer_rule_test: %zu tests, failures=%d\n",
                    tests.size(), failures);
        std::printf("TEST_EXPLORER_RULE_TEST %s\n",
                    failures == 0 ? "PASS" : "FAIL");
        return failures == 0 ? 0 : 1;
    } catch (const std::exception& e) {
        std::printf("[FAIL] exception: %s\n", e.what());
        return 1;
    }
}