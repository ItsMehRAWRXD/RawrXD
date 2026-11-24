// =============================================================================
// Win32IDE_WatchUI.cpp — D3 watch expression UI (TOP50 D3).
// =============================================================================
// Adds the missing UI surface for the existing watch engine:
//   - promptAddWatchExpression (command 12080): focuses the Debug Console and
//     seeds the `watch ` prefix; the console command path (debuggerStepCommand)
//     handles `watch <expr>` / `unwatch <expr>`.
//   - removeSelectedWatch (command 12081): removes the selected watch row.
// =============================================================================
#include "Win32IDE.h"

#include <commctrl.h>
#include <cstdio>
#include <string>

void Win32IDE::promptAddWatchExpression() {
    showDebugConsole();
    appendToOutput("[Watch] Type: watch <expression>   (unwatch <expr> to "
                   "remove)\n", "Debug", OutputSeverity::Info);
}

// showDebugConsole (declared in Win32IDE.h; the old definition lived in the
// orphaned Win32IDE_Core.cpp): reveal the Debug Console panel tab.
void Win32IDE::showDebugConsole() {
    ensurePanelTabBodies();
    ensurePanelVisible();
    switchPanelTab(PanelTab::DebugConsole);
}

void Win32IDE::removeSelectedWatch() {
    if (!m_hwndDebuggerWatch || !IsWindow(m_hwndDebuggerWatch)) return;
    const int sel = (int)SendMessageA(m_hwndDebuggerWatch, LVM_GETNEXTITEM,
                                      -1, LVNI_SELECTED);
    if (sel < 0) {
        appendToOutput("[Watch] No watch selected.\n", "Debug",
                       OutputSeverity::Info);
        return;
    }
    char buf[512] = {0};
    LVITEMA lvi = {0};
    lvi.mask = LVIF_TEXT;
    lvi.iSubItem = 0;
    lvi.pszText = buf;
    lvi.cchTextMax = sizeof(buf);
    SendMessageA(m_hwndDebuggerWatch, LVM_GETITEMTEXTA, sel, (LPARAM)&lvi);
    if (buf[0]) removeWatchExpression(buf);
}