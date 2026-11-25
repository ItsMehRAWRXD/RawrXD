// =============================================================================
// Win32IDE_LspCommands.cpp — I1 go-to-definition wiring (TOP50 I1).
// =============================================================================
// F12 in the editor -> textDocument/definition via the running LSP server ->
// open the target file and reveal the line. Uses the existing LSP client
// (lspGotoDefinition), cursor helper (getEditorCursorFileLineCol) and
// navigation (navigateToFileLine); no parallel symbol path.
// =============================================================================
#include "Win32IDE.h"

#include <cstdio>
#include <string>

// F12 key subclass for the editor window. The editor is a child RichEdit, so
// keystrokes never reach the main WndProc; subclass it once at creation.
static LRESULT CALLBACK LspEditorKeyProc(HWND hwnd, UINT uMsg, WPARAM wParam,
                                         LPARAM lParam, UINT_PTR idSubclass,
                                         DWORD_PTR dwRefData) {
    (void)idSubclass; (void)dwRefData;
    // P0: the editor can be destroyed while a subclass message is in flight;
    // IsWindow filters the dead-HWND call into DefSubclassProc (the
    // confirmed LspEditorKeyProc+0x5c access violation).
    if (!IsWindow(hwnd))
        return DefSubclassProc(hwnd, uMsg, wParam, lParam);
    if (uMsg == WM_KEYDOWN && wParam == VK_F12) {
        auto* self = reinterpret_cast<Win32IDE*>(
            GetPropW(hwnd, L"RawrXD_IDE_PTR"));
        if (self) {
            // Reentrancy guard: F12 autorepeat must not re-enter the LSP
            // request path while a previous definition request is in flight.
            static thread_local bool s_inDefinition = false;
            if (!s_inDefinition) {
                s_inDefinition = true;
                self->lspGotoDefinitionAtCursor();
                s_inDefinition = false;
                return 0;
            }
        }
    }
    return DefSubclassProc(hwnd, uMsg, wParam, lParam);
}

void Win32IDE::installLspEditorSubclass() {
    if (!m_hwndEditor || !IsWindow(m_hwndEditor)) return;
    if (!GetPropW(m_hwndEditor, L"RawrXD_IDE_PTR")) {
        SetPropW(m_hwndEditor, L"RawrXD_IDE_PTR", this);
    }
    if (!SetWindowSubclass(m_hwndEditor, LspEditorKeyProc, 1, 0)) {
        OutputDebugStringA("WARN: installLspEditorSubclass failed\n");
    }
}

void Win32IDE::lspGotoDefinitionAtCursor() {
    std::string file;
    uint32_t line1 = 0, col = 0;
    if (!getEditorCursorFileLineCol(file, line1, col)) {
        appendToOutput("[LSP] Go to Definition: open a file and place the "
                       "cursor on a symbol (F12).\n");
        return;
    }
    std::string uri = "file:///";
    for (char c : file) uri += (c == '\\') ? '/' : c;

    const auto locations = lspGotoDefinition(uri, (int)(line1 - 1), (int)col);
    if (locations.empty()) {
        appendToOutput("[LSP] No definition found at cursor (server may not "
                       "be running for this language).\n");
        return;
    }
    const auto& loc = locations.front();
    const std::string target = uriToFilePath(loc.uri);
    navigateToFileLine(target, loc.range.start.line + 1);
    appendToOutput("[LSP] -> " + target + ":" +
                   std::to_string(loc.range.start.line + 1) + "\n");
}