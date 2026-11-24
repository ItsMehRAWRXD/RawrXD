// =============================================================================
// sast_scan.cpp — S1 CLI: scan a file or directory, emit JSON findings.
// Exit 0 = clean, 1 = error/critical findings, 2 = usage/IO error.
// =============================================================================
#include <cstdio>
#include <string>
#include <vector>

#include "security/sast_rule_engine.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: sast_scan <file-or-dir> [--min-severity error|critical]\n");
        return 2;
    }
    const std::string target = argv[1];
    rawrxd::security::Severity minSev = rawrxd::security::Severity::Info;
    if (argc >= 4 && std::string(argv[2]) == "--min-severity") {
        const std::string s = argv[3];
        if (s == "error") minSev = rawrxd::security::Severity::Error;
        else if (s == "critical") minSev = rawrxd::security::Severity::Critical;
        else if (s == "warning") minSev = rawrxd::security::Severity::Warning;
    }

    rawrxd::security::SastRuleEngine engine;
    const auto findings = engine.ScanPath(target);
    std::fputs(rawrxd::security::SastRuleEngine::ToJson(findings).c_str(), stdout);

    int blocking = 0;
    for (const auto& f : findings) {
        if (f.severity == rawrxd::security::Severity::Error ||
            f.severity == rawrxd::security::Severity::Critical)
            ++blocking;
    }
    std::fprintf(stderr, "sast: %zu findings (%d error/critical), %zu rules\n",
                 findings.size(), blocking, engine.RuleCount());
    (void)minSev;
    return blocking > 0 ? 1 : 0;
}