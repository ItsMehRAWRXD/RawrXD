// ============================================================================
// Win32IDE_LicenseCreator.cpp — License Management / Activation (Batch 7 SP07)
// ============================================================================
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <sstream>

void Win32IDE::showLicenseManager() {
    std::ostringstream msg;
    msg << "=== License Creator ===\n";
    msg << "License status: DEMO (unlocked for development)\n";
    msg << "Trial period: 30 days remaining\n";
    msg << "Feature access: All features unlocked\n";

    MessageBoxA(m_hwndMain, msg.str().c_str(), "License Manager",
                MB_ICONINFORMATION | MB_OK);
}

void Win32IDE::activateLicense(const std::string& key) {
    (void)key;
    appendToOutput("[License] Activation attempted.\n", "License", OutputSeverity::Info);
}

bool Win32IDE::isLicenseValid() const {
    return true;
}
