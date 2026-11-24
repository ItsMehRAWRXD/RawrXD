// =============================================================================
// dast_import.cpp — S5 CLI: import a DAST report, emit JSON findings.
// =============================================================================
#include <cstdio>
#include <string>

#include "security/dast_bridge.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: dast_import <zap.json|burp.xml>\n");
        return 2;
    }
    rawrxd::security::DastBridge bridge;
    std::vector<rawrxd::security::DastFinding> findings;
    if (!bridge.Import(argv[1], findings)) {
        std::fprintf(stderr, "dast_import: unsupported or unreadable report\n");
        return 2;
    }
    std::fputs(rawrxd::security::DastBridge::ToJson(findings).c_str(), stdout);
    std::fprintf(stderr, "dast_import: %zu finding(s)\n", findings.size());
    return 0;
}