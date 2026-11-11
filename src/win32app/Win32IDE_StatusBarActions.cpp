// Win32IDE_StatusBarActions.cpp — Status Bar (Batch 4 U06)
// Git branch, errors/warnings, line/col, encoding, language mode
#include "Win32IDE.h"
#include <windows.h>

void Win32IDE::initStatusBar() {
    appendToOutput("[StatusBar] Status bar created.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::updateStatusBar() {
    // Stub - updates status bar with current state
}
