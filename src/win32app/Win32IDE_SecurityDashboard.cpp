// =============================================================================
// Win32IDE_SecurityDashboard.cpp — S6 security dashboard (TOP50 S6).
// =============================================================================
// One action runs all three security engines (S1 SAST, S2 secrets, S3 SCA)
// over the workspace, pushes every finding into the unified Problems panel,
// writes a JSON snapshot (counts + per-source) for trend tracking under
// .rawrxd/audit/, and prints a summary to the Output "Security" channel.
// =============================================================================
#include "Win32IDE.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include "agentic/tool_security.hpp"
#include "core/problems_aggregator.hpp"
#include "security/dependency_audit.h"
#include "security/sast_rule_engine.h"
#include "security/secrets_scanner.h"

// IDM_SECURITY_DASHBOARD (12050) is handled in Win32IDE_lifecycle.cpp.

void Win32IDE::showSecurityDashboard() {
    const std::string root = m_gitRepoPath.empty() ? std::string(".")
                                                   : m_gitRepoPath;
    if (root.empty() || m_currentFile.empty()) {
        appendToOutput("[Security] Dashboard needs an open workspace.\n",
                       "Security", OutputSeverity::Warning);
        return;
    }

    rawrxd::security::SastRuleEngine sast;
    rawrxd::security::SecretsScanner secrets;
    rawrxd::security::DependencyAuditor deps;

    const auto sastFindings = sast.ScanPath(root);
    const auto secretFindings = secrets.ScanPath(root);
    const auto inventory = deps.ScanTree(root);
    const auto advisories = deps.Audit(inventory);

    auto& agg = RawrXD::ProblemsAggregator::instance();
    agg.clear("SAST");
    agg.clear("Secrets");
    agg.clear("SCA");
    for (const auto& f : sastFindings) {
        const int sev = (f.severity == rawrxd::security::Severity::Error ||
                         f.severity == rawrxd::security::Severity::Critical)
                            ? 1 : 2;
        agg.add("SAST", f.file, f.line, f.column, sev, f.rule_id, f.message,
                f.rule_id);
    }
    for (const auto& f : secretFindings) {
        const int sev = (f.rule_id == "PRIVATE_KEY" ||
                         f.rule_id == "AWS_ACCESS_KEY") ? 1 : 2;
        agg.add("Secrets", f.file, f.line, f.column, sev, f.rule_id,
                f.message + " (redacted: " + f.match + ")", f.rule_id);
    }
    for (const auto& a : advisories) {
        const int sev = (a.severity == "critical") ? 1 : 2;
        agg.add("SCA", "", 0, 0, sev, a.dependency, a.summary, a.dependency);
    }
    refreshProblemsView();

    std::ostringstream summary;
    summary << "[Security] Dashboard: SAST=" << sastFindings.size()
            << " Secrets=" << secretFindings.size()
            << " SCA=" << advisories.size()
            << " (deps=" << inventory.size() << ")\n";
    appendToOutput(summary.str(), "Security", OutputSeverity::Info);

    // Trend snapshot (append-only history for counts over time).
    std::string snap = root + "/.rawrxd/audit/security_dashboard.jsonl";
    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(snap).parent_path(), ec);
    std::ofstream out(snap, std::ios::app);
    if (out) {
        out << "{\"ts\":\"" << rawrxd::agentic::security::NowIso8601Utc() << "\""
            << ",\"sast\":" << sastFindings.size()
            << ",\"secrets\":" << secretFindings.size()
            << ",\"sca\":" << advisories.size()
            << ",\"deps\":" << inventory.size() << "}\n";
    }
}