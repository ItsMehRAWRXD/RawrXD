// ============================================================================
// [SOURCE] win32app\Win32IDE_SecurityDashboard.cpp
// FILE: D:\rawrxd\src\win32app\Win32IDE_SecurityDashboard.cpp
// ============================================================================

// Win32IDE_SecurityDashboard.cpp — Top-50 P1: aggregate SAST, SCA, Secrets, DAST counts
// [CONSOLIDATED] #include "Win32IDE.h"
// [CONSOLIDATED] #include "../core/problems_aggregator.hpp"
// [SYSINCLUDE] #include <string>
// [SYSINCLUDE] #include <sstream>

void Win32IDE::showSecurityDashboard() {
    auto& agg = RawrXD::ProblemsAggregator::instance();
    size_t secrets = 0, sast = 0, sca = 0, dast = 0, build = 0;
    auto all = agg.getProblems("", "");
    for (const auto& p : all) {
        if (p.source == "Secrets") secrets++;
        else if (p.source == "SAST") sast++;
        else if (p.source == "SCA") sca++;
        else if (p.source == "DAST") dast++;
        else if (p.source == "Build") build++;
    }
    std::ostringstream ss;
    ss << "Security: Secrets " << secrets << " | SAST " << sast << " | SCA " << sca << " | DAST " << dast << " | Build " << build;
    std::string msg = ss.str();
    appendToOutput("[Security] " + msg + "\n", "Output", OutputSeverity::Info);
    if (m_hwndStatusBar && IsWindow(m_hwndStatusBar)) {
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, (LPARAM)msg.c_str());
    }
}
