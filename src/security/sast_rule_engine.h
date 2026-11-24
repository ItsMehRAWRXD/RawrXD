// =============================================================================
// sast_rule_engine.h — S1 SAST rule engine (C/C++), dependency-free.
// =============================================================================
// Real static analysis over source text: a declarative rule table
// (sast_rules/*.inc) of pattern + state rules produces Findings with
// file/line/column/severity/CWE. Consumers: Problems panel (I3), LSP
// diagnostics bridge (I2), CLI (tools/sast_scan.cpp).
// =============================================================================
#pragma once
#include <regex>
#include <string>
#include <vector>

namespace rawrxd::security {

enum class Severity { Info, Warning, Error, Critical };

struct Finding {
    std::string rule_id;
    std::string rule_name;
    std::string file;
    int line = 0;
    int column = 0;
    Severity severity = Severity::Warning;
    std::string message;
    std::string cwe;          // e.g. "CWE-120"
    std::string snippet;      // offending source line (trimmed)
};

struct ScanOptions {
    int max_file_bytes = 2 * 1024 * 1024;
    int max_findings = 5000;
    bool recursive = true;
};

class SastRuleEngine {
public:
    SastRuleEngine();

    // Scan one file. Returns findings sorted by (file, line, column).
    std::vector<Finding> ScanFile(const std::string& path,
                                  const ScanOptions& opts = {}) const;

    // Scan a file or directory tree (recursive per opts).
    std::vector<Finding> ScanPath(const std::string& path,
                                  const ScanOptions& opts = {}) const;

    // Machine-readable JSON array of findings (manual escaping, no deps).
    static std::string ToJson(const std::vector<Finding>& findings);

    size_t RuleCount() const;

private:
    struct Rule {
        std::string id;
        std::string name;
        std::string cwe;
        Severity severity = Severity::Warning;
        std::regex pattern;
        std::string message;
        bool needs_state = false;
    };
    std::vector<Rule> rules_;
};

// Human-readable severity name ("error", "warning", ...).
const char* SeverityName(Severity s);

}  // namespace rawrxd::security