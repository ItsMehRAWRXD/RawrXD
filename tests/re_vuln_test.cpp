// =============================================================================
// re_vuln_test.cpp — R3 certification: dangerous APIs detected, benign not.
// =============================================================================
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "reverse_engineering/re_vuln_rules.h"

int main() {
    int failures = 0;
    const std::string tmp = getenv("TEMP") ? getenv("TEMP") : ".";
    const std::string p = tmp + "/re_vuln_test.bin";
    {
        std::ofstream out(p, std::ios::binary);
        const char payload[] =
            "IMPORT: strcpy\0system\0VirtualAlloc\0"
            "benign: systematic\0ecosystem\0";
        out.write(payload, sizeof(payload));
    }
    rawrxd::re::ReVulnScanner scanner;
    const auto findings = scanner.Scan(p);
    auto has = [&](const char* api) {
        for (const auto& f : findings)
            if (f.api == api) return true;
        return false;
    };
    if (!has("strcpy") || !has("system") || !has("VirtualAlloc")) {
        std::printf("[FAIL] dangerous APIs missed\n");
        ++failures;
    }
    // Token boundary: 'systematic' must not trigger the system rule via the
    // same offset (the scanner reports the real 'system' import only).
    if (findings.size() != 3) {
        std::printf("[FAIL] expected 3 findings, got %zu\n", findings.size());
        ++failures;
    }
    std::printf("re_vuln_test: failures=%d\n", failures);
    std::printf("RE_VULN_TEST %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}