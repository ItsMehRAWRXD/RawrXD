// =============================================================================
// Win32IDE_SastBridge.cpp — I2/I3 SAST + secrets diagnostics bridge.
// =============================================================================
// I2: SAST findings render as inline editor annotations (AnnotationOverlay).
// I3: every source (LSP already, SAST + Secrets here) pushes into the unified
// ProblemsAggregator so the Problems panel is one list.
// =============================================================================
#include "Win32IDE.h"

#include <cstdio>
#include <string>

#include "core/problems_aggregator.hpp"
#include "security/sast_rule_engine.h"
#include "security/secrets_scanner.h"

// IDM_SECURITY_SCAN_SAST (12040) and IDM_SECURITY_SCAN_SECRETS (12041) are
// handled in Win32IDE_lifecycle.cpp.

void Win32IDE::scanCurrentFileSAST() {
    if (m_currentFile.empty()) {
        appendToOutput("[SAST] Open a file first (SAST scans the current file).\n");
        return;
    }
    rawrxd::security::SastRuleEngine engine;
    const auto findings = engine.ScanFile(m_currentFile);
    clearAllAnnotations("sast");
    {
        auto& agg = RawrXD::ProblemsAggregator::instance();
        agg.clear("SAST");
        for (const auto& f : findings) {
            AnnotationSeverity sev = AnnotationSeverity::Warning;
            int aggSev = 2;
            if (f.severity == rawrxd::security::Severity::Error ||
                f.severity == rawrxd::security::Severity::Critical) {
                sev = AnnotationSeverity::Error;
                aggSev = 1;
            } else if (f.severity == rawrxd::security::Severity::Info) {
                sev = AnnotationSeverity::Info;
                aggSev = 3;
            }
            addAnnotation(f.line, sev,
                          f.message + " [" + f.rule_id + " " + f.cwe + "]",
                          "sast");
            agg.add("SAST", m_currentFile, f.line, f.column, aggSev,
                    f.rule_id, f.message, f.rule_id);
        }
    }
    refreshProblemsView();
    if (findings.empty()) {
        appendToOutput("[SAST] No findings in " + m_currentFile + " (" +
                       std::to_string(engine.RuleCount()) + " rules).\n");
        return;
    }
    appendToOutput("[SAST] " + std::to_string(findings.size()) +
                   " finding(s) in " + m_currentFile + ":\n");
    for (const auto& f : findings) {
        appendToOutput("  line " + std::to_string(f.line) + " " + f.rule_id +
                       " " + f.message + "\n");
    }
    showAnnotationOverlay();
}

void Win32IDE::scanCurrentFileSecrets() {
    if (m_currentFile.empty()) {
        appendToOutput("[SECRETS] Open a file first.\n");
        return;
    }
    rawrxd::security::SecretsScanner scanner;
    const auto findings = scanner.ScanPath(m_currentFile);
    {
        auto& agg = RawrXD::ProblemsAggregator::instance();
        agg.clear("Secrets");
        for (const auto& f : findings) {
            const int aggSev = (f.rule_id == "PRIVATE_KEY" ||
                                f.rule_id == "AWS_ACCESS_KEY") ? 1 : 2;
            agg.add("Secrets", f.file, f.line, f.column, aggSev, f.rule_id,
                    f.message + " (redacted: " + f.match + ")", f.rule_id);
        }
    }
    refreshProblemsView();
    appendToOutput("[SECRETS] " + std::to_string(findings.size()) +
                   " finding(s) in " + m_currentFile + " (pushed to Problems).\n");
}