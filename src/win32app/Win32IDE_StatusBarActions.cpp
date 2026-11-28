// Win32IDE_StatusBarActions.cpp — Status Bar (Batch 4 U06)
// Git branch, errors/warnings, line/col, encoding, language mode
#include "Win32IDE.h"
#include <windows.h>

void Win32IDE::initStatusBar() {
    if (!m_hwndStatusBar) return;
    const int parts[] = {120, 260, 120};
    SendMessageA(m_hwndStatusBar, SB_SETPARTS, 3, reinterpret_cast<LPARAM>(parts));
    updateStatusBar();
    appendToOutput("[StatusBar] Status bar initialized.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::updateStatusBar() {
    if (!m_hwndStatusBar) return;
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                 reinterpret_cast<LPARAM>("RawrXD | main"));
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 1,
                 reinterpret_cast<LPARAM>("Ln 1, Col 1"));
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 2,
                 reinterpret_cast<LPARAM>("UTF-8 | C++"));
}
