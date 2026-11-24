// =============================================================================
// dependency_audit.h — S3 SCA / dependency audit (TOP50 S3).
// =============================================================================
// Parses package.json, requirements.txt, vcpkg.json and CMakeLists manifests
// into a dependency inventory and matches a built-in advisory table (offline;
// no NVD/OSV network dependency). Findings feed the Problems panel (I3).
// =============================================================================
#pragma once
#include <string>
#include <vector>

namespace rawrxd::security {

struct Dependency {
    std::string name;
    std::string version;     // "" when unpinned
    std::string ecosystem;   // npm | pypi | vcpkg | cmake
    std::string manifest;
};

struct Advisory {
    std::string dependency;
    std::string ecosystem;
    std::string fixed_version;   // first non-vulnerable version
    std::string severity;        // critical | high | moderate
    std::string summary;
};

class DependencyAuditor {
public:
    // Parse one manifest file (format detected by name/content).
    std::vector<Dependency> ParseManifest(const std::string& path) const;

    // Recursively collect manifests under a directory (bounded depth).
    std::vector<Dependency> ScanTree(const std::string& root) const;

    // Match inventory against the built-in advisory table.
    std::vector<Advisory> Audit(const std::vector<Dependency>& deps) const;

    static std::string ToJson(const std::vector<Dependency>& deps,
                              const std::vector<Advisory>& advisories);

    static const std::vector<Advisory>& AdvisoryTable();
};

// Compare dotted numeric versions: -1, 0, 1.
int CompareVersions(const std::string& a, const std::string& b);

}  // namespace rawrxd::security