// =============================================================================
// Win32IDE_SastBridge.cpp — I2 SAST inline diagnostics bridge (TOP50 I2).
// =============================================================================
// Runs the S1 SAST engine (src/security/sast_rule_engine) over the current
// file and renders each finding as an inline editor annotation (squiggle via
// the existing AnnotationOverlay path) plus an Output summary. LSP
// diagnostics already flow through onDiagnosticsReceived; this closes the
// SAST half of I2.
// =============================================================================
#include "Win32IDE.h"

#include <cstdio>
#include <string>

#include "security/sast_rule_engine.h"

// IDM_SECURITY_SCAN_SAST (12040) is handled in Win32IDE_lifecycle.cpp.

void Win32IDE::scanCurrentFileSAST() {
    if (m_currentFile.empty()) {
        appendToOutput("[SAST] Open a file first (SAST scans the current file).\n");
        return;
    }
    rawrxd::security::SastRuleEngine engine;
    const auto findings = engine.ScanFile(m_currentFile);
    if (findings.empty()) {
        appendToOutput("[SAST] No findings in " + m_currentFile + " (" +
                       std::to_string(engine.RuleCount()) + " rules).\n");
        return;
    }
    clearAllAnnotations("sast");
    for (const auto& f : findings) {
        AnnotationSeverity sev = AnnotationSeverity::Warning;
        if (f.severity == rawrxd::security::Severity::Error ||
            f.severity == rawrxd::security::Severity::Critical)
            sev = AnnotationSeverity::Error;
        else if (f.severity == rawrxd::security::Severity::Info)
            sev = AnnotationSeverity::Info;
        addAnnotation(f.line, sev,
                      f.message + " [" + f.rule_id + " " + f.cwe + "]",
                      "sast");
    }
    appendToOutput("[SAST] " + std::to_string(findings.size()) +
                   " finding(s) in " + m_currentFile + ":\n");
    for (const auto& f : findings) {
        appendToOutput("  line " + std::to_string(f.line) + " " + f.rule_id +
                       " " + f.message + "\n");
    }
    showAnnotationOverlay();
}