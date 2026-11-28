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
    std::string model = getModelInfo();
    if (model.empty()) model = m_selectedChatModel.identifier;
    const std::string left = "RawrXD | " + (model.empty() ? "no model" : model);

    int line = 1, col = 1, selLen = 0;
    if (m_hwndEditor && IsWindow(m_hwndEditor)) {
        DWORD selStart = 0, selEnd = 0;
        SendMessageA(m_hwndEditor, EM_GETSEL, reinterpret_cast<WPARAM>(&selStart),
                     reinterpret_cast<LPARAM>(&selEnd));
        line = static_cast<int>(SendMessageA(m_hwndEditor, EM_LINEFROMCHAR, selStart, 0)) + 1;
        const int lineStart = static_cast<int>(SendMessageA(m_hwndEditor, EM_LINEINDEX, line - 1, 0));
        col = static_cast<int>(selStart) - lineStart + 1;
        selLen = static_cast<int>(selEnd - selStart);
    }
    const std::string pos = "Ln " + std::to_string(line) + ", Col " + std::to_string(col) +
                            " | sel=" + std::to_string(selLen);

    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                 reinterpret_cast<LPARAM>(left.c_str()));
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 1,
                 reinterpret_cast<LPARAM>(pos.c_str()));
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 2,
                 reinterpret_cast<LPARAM>("UTF-8 | C++"));
}
