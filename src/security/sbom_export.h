// =============================================================================
// sbom_export.h — S4 SBOM export (TOP50 S4), dependency-free.
// =============================================================================
// Generates a CycloneDX 1.4 JSON SBOM from the S3 dependency inventory.
// No new dependencies; consumed by tools/sbom_export.cpp and CI.
// =============================================================================
#pragma once
#include <string>
#include <vector>

#include "security/dependency_audit.h"

namespace rawrxd::security {

class SbomExporter {
public:
    // Build a CycloneDX document from an inventory. serialNumber is derived
    // deterministically from the inventory content (no RNG dependency).
    static std::string ToCycloneDx(const std::vector<Dependency>& deps,
                                   const std::string& component_name,
                                   const std::string& component_version);
};

}  // namespace rawrxd::security