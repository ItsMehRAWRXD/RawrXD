// =============================================================================
// re_vuln_rules.h — R3 RE vulnerability rules (TOP50 R3), dependency-free.
// =============================================================================
// Scans a binary's raw bytes for dangerous imported/used API names (SAST-style
// rules applied to compiled artifacts) and reports them with CWE references.
// =============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd::re {

struct VulnFinding {
    std::string api;
    std::string cwe;
    std::string message;
    uint64_t offset = 0;   // file offset of the first occurrence
};

class ReVulnScanner {
public:
    std::vector<VulnFinding> Scan(const std::string& path,
                                  int max_findings = 500) const;

    static std::string ToJson(const std::vector<VulnFinding>& findings);
};

}  // namespace rawrxd::re