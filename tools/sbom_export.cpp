// =============================================================================
// sbom_export.cpp CLI — S4: generate a CycloneDX SBOM from a manifest/tree.
// usage: sbom_export <manifest-or-dir> [name] [version] > sbom.json
// =============================================================================
#include <cstdio>
#include <string>

#include "security/dependency_audit.h"
#include "security/sbom_export.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: sbom_export <manifest-or-dir> [name] [version]\n");
        return 2;
    }
    rawrxd::security::DependencyAuditor auditor;
    const auto deps = auditor.ScanTree(argv[1]);
    const std::string name = argc > 2 ? argv[2] : "rawrxd-workspace";
    const std::string version = argc > 3 ? argv[3] : "0.0.0";
    const std::string sbom = rawrxd::security::SbomExporter::ToCycloneDx(
        deps, name, version);
    std::fputs(sbom.c_str(), stdout);
    std::fprintf(stderr, "sbom: %zu components\n", deps.size());
    return 0;
}