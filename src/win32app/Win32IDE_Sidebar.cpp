// Win32IDE_Sidebar.cpp — File Explorer with Git Decorators (Batch 4 P02)
// Stub: file tree view with git status indicators
#include "Win32IDE.h"
#include <windows.h>

void Win32IDE::createFileExplorer() {
    if (m_hwndSidebar) return;
    m_hwndSidebar = CreateWindowW(L"STATIC", L"File Explorer",
                                  WS_CHILD | WS_VISIBLE | SS_CENTER,
                                  0, 0, 300, 400, m_hwndMain,
                                  nullptr, m_hInstance, nullptr);
    appendToOutput("[Sidebar] File explorer created.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::refreshFileExplorer() {
    if (!m_hwndSidebar) return;
    appendToOutput("[Sidebar] Refreshing file tree.\n", "Output", OutputSeverity::Info);
}
