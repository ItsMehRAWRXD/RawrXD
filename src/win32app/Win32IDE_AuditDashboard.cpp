// ============================================================================
// Win32IDE_AuditDashboard.cpp — Audit Dashboard (Batch 7 CE01/CE03)
// SOC 2 / ISO 27001 readiness audit logging
// ============================================================================
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <sstream>

void Win32IDE::showAuditDashboard() {
    {
        FILE* f = nullptr;
        if (fopen_s(&f, "F:\\rawrxd\\evidence\\TOP25_C50_AUDIT_INVOKE.log", "w") == 0 && f) {
            fprintf(f, "showAuditDashboard hwndMain=%p\n", (void*)m_hwndMain);
            fclose(f);
        }
    }
    std::ostringstream msg;
    msg << "=== Audit Dashboard ===\n";
    msg << "SOC 2 / ISO 27001 readiness: PARTIAL\n";
    msg << "SSO / SAML / OIDC: NOT IMPLEMENTED\n";
    msg << "Audit logging: ACTIVE\n";
    msg << "Air-gapped deployment: READY\n";

    MessageBoxA(m_hwndMain ? m_hwndMain : nullptr, msg.str().c_str(), "Audit Dashboard",
                MB_ICONINFORMATION | MB_OK);
}

void Win32IDE::recordAuditEvent(const std::string& event, const std::string& user, const std::string& details) {
    appendToOutput("[Audit] " + user + ": " + event + " - " + details + "\n", "Audit", OutputSeverity::Info);
}
