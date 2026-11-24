// =============================================================================
// re_vuln_scan.cpp — R3 CLI: scan a binary for dangerous APIs.
// =============================================================================
#include <cstdio>
#include <string>

#include "reverse_engineering/re_vuln_rules.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: re_vuln_scan <binary>\n");
        return 2;
    }
    rawrxd::re::ReVulnScanner scanner;
    const auto findings = scanner.Scan(argv[1]);
    std::fputs(rawrxd::re::ReVulnScanner::ToJson(findings).c_str(), stdout);
    std::fprintf(stderr, "re_vuln_scan: %zu finding(s)\n", findings.size());
    return findings.empty() ? 0 : 1;
}