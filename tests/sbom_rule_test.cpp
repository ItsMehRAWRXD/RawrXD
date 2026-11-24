// =============================================================================
// sbom_rule_test.cpp — S4 certification: valid CycloneDX with real components.
// =============================================================================
#include <cstdio>
#include <string>

#include "security/dependency_audit.h"
#include "security/sbom_export.h"

int main(int argc, char** argv) {
    try {
        const std::string dir = argc > 1 ? argv[1] : "tests/fixtures";
        rawrxd::security::DependencyAuditor auditor;
        const auto deps = auditor.ScanTree(dir);
        const std::string sbom = rawrxd::security::SbomExporter::ToCycloneDx(
            deps, "fixture-app", "1.0.0");
        int failures = 0;
        auto need = [&](const std::string& needle) {
            if (sbom.find(needle) == std::string::npos) {
                std::printf("[FAIL] sbom missing %s\n", needle.c_str());
                ++failures;
            }
        };
        need("\"bomFormat\": \"CycloneDX\"");
        need("\"specVersion\": \"1.4\"");
        need("urn:uuid:");
        need("\"name\": \"lodash\"");
        need("\"name\": \"requests\"");
        need("pkg:npm/lodash@4.17.20");
        if (deps.size() < 6) {
            std::printf("[FAIL] expected >=6 deps, got %zu\n", deps.size());
            ++failures;
        }
        // Deterministic serial: same input -> same document.
        const std::string again = rawrxd::security::SbomExporter::ToCycloneDx(
            deps, "fixture-app", "1.0.0");
        if (again != sbom) {
            std::printf("[FAIL] sbom not deterministic\n");
            ++failures;
        }
        std::printf("sbom_rule_test: %zu components, failures=%d\n",
                    deps.size(), failures);
        std::printf("SBOM_RULE_TEST %s\n", failures == 0 ? "PASS" : "FAIL");
        return failures == 0 ? 0 : 1;
    } catch (const std::exception& e) {
        std::printf("[FAIL] exception: %s\n", e.what());
        return 1;
    }
}