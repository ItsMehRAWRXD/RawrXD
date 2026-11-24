// =============================================================================
// dependency_audit.cpp CLI — S3: audit a manifest or tree for dependencies.
// =============================================================================
#include <cstdio>
#include <string>

#include "security/dependency_audit.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: dependency_audit <manifest-or-dir>\n");
        return 2;
    }
    rawrxd::security::DependencyAuditor auditor;
    const auto deps = auditor.ScanTree(argv[1]);
    const auto advisories = auditor.Audit(deps);
    std::fputs(rawrxd::security::DependencyAuditor::ToJson(deps, advisories)
                   .c_str(), stdout);
    std::fprintf(stderr, "dependency_audit: %zu deps, %zu advisories\n",
                 deps.size(), advisories.size());
    return advisories.empty() ? 0 : 1;
}