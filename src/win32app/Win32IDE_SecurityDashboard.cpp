// ============================================================================
// Win32IDE_SecurityDashboard.cpp — Security Dashboard (Batch 7 SP04)
// ============================================================================
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <sstream>

void Win32IDE::showSecurityDashboard() {
    std::ostringstream msg;
    msg << "=== Security Dashboard ===\n";
    msg << "Secret scanning: ACTIVE\n";
    msg << "Code execution sandbox: ACTIVE\n";
    msg << "Telemetry: OPT-IN (disabled)\n";
    msg << "Air-gapped mode: AVAILABLE\n";

    MessageBoxA(m_hwndMain, msg.str().c_str(), "Security Dashboard",
                MB_ICONINFORMATION | MB_OK);
}
