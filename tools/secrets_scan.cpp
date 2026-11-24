// =============================================================================
// secrets_scan.cpp — S2 CLI: scan a file or directory for secrets.
// Exit 0 = clean, 1 = findings, 2 = usage error.
// =============================================================================
#include <cstdio>
#include <string>

#include "security/secrets_scanner.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: secrets_scan <file-or-dir>\n");
        return 2;
    }
    rawrxd::security::SecretsScanner scanner;
    const auto findings = scanner.ScanPath(argv[1]);
    std::fputs(rawrxd::security::SecretsScanner::ToJson(findings).c_str(),
               stdout);
    std::fprintf(stderr, "secrets: %zu findings\n", findings.size());
    return findings.empty() ? 0 : 1;
}