// =============================================================================
// dast_test.cpp — S5 certification: ZAP JSON import normalizes findings.
// =============================================================================
#include <cstdio>
#include <string>

#include "security/dast_bridge.h"

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1]
                                      : "tests/fixtures/dast_zap.json";
    rawrxd::security::DastBridge bridge;
    std::vector<rawrxd::security::DastFinding> findings;
    int failures = 0;
    if (!bridge.Import(path, findings) || findings.size() != 2) {
        std::printf("[FAIL] import (n=%zu)\n", findings.size());
        ++failures;
    }
    if (findings.size() == 2) {
        if (findings[0].severity != "high" ||
            findings[0].rule_id != "40012" ||
            findings[0].url.find("/search") == std::string::npos) {
            std::printf("[FAIL] finding0 normalized wrong\n");
            ++failures;
        }
        if (findings[1].severity != "low") {
            std::printf("[FAIL] finding1 severity\n");
            ++failures;
        }
    }
    // Unsupported input must fail closed.
    std::vector<rawrxd::security::DastFinding> none;
    if (bridge.Import("tests/fixtures/package.json", none)) {
        std::printf("[FAIL] unsupported input accepted\n");
        ++failures;
    }
    std::printf("dast_test: failures=%d\n", failures);
    std::printf("DAST_TEST %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}