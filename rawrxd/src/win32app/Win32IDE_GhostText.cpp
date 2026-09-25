// Win32IDE_GhostText.cpp — inline AI ghost text completions
#include <windows.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <chrono>

namespace RawrXD::IDE {

HFONT IDECore_MonoFont();

struct GhostTextState {
    HWND        editorHwnd  = nullptr;
    std::string suggestion;
    bool        visible     = false;
    int         anchorLine  = -1;
    int         anchorCol   = -1;
    std::atomic<bool> pending{false};
    std::function<std::string(const std::string&)> completionProvider;
};

static GhostTextState g_ghost;

void GhostText_Init(HWND editorHwnd)
{
    g_ghost.editorHwnd = editorHwnd;
}

void GhostText_SetProvider(std::function<std::string(const std::string&)> provider)
{
    g_ghost.completionProvider = std::move(provider);
}

// Called by editor on each keystroke with current line prefix
void GhostText_RequestCompletion(const std::string& linePrefix, int line, int col)
{
    if (g_ghost.pending.load()) return;
    g_ghost.pending.store(true);
    g_ghost.anchorLine = line;
    g_ghost.anchorCol  = col;

    std::thread([linePrefix, line, col]() {
        // 300ms debounce
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        if (!g_ghost.pending.load()) return;

        std::string suggestion;
        if (g_ghost.completionProvider) {
            suggestion = g_ghost.completionProvider(linePrefix);
        } else {
            // Built-in heuristic completions
            if (linePrefix.find("for") != std::string::npos && linePrefix.back() == '(')
                suggestion = "int i = 0; i < n; ++i)";
            else if (linePrefix.find("if") != std::string::npos && linePrefix.back() == '(')
                suggestion = "condition) {";
            else if (linePrefix.find("std::") != std::string::npos)
                suggestion = "string";
            else if (!linePrefix.empty() && linePrefix.back() == '.')
                suggestion = "size()";
        }

        g_ghost.suggestion  = suggestion;
        g_ghost.visible     = !suggestion.empty();
        g_ghost.pending.store(false);

        if (g_ghost.editorHwnd && g_ghost.visible)
            InvalidateRect(g_ghost.editorHwnd, nullptr, FALSE);
    }).detach();
}

// Accept the current suggestion — returns the text to insert
std::string GhostText_Accept()
{
    if (!g_ghost.visible) return "";
    std::string s = g_ghost.suggestion;
    g_ghost.suggestion.clear();
    g_ghost.visible = false;
    if (g_ghost.editorHwnd) InvalidateRect(g_ghost.editorHwnd, nullptr, FALSE);
    return s;
}

void GhostText_Dismiss()
{
    g_ghost.suggestion.clear();
    g_ghost.visible = false;
    g_ghost.pending.store(false);
    if (g_ghost.editorHwnd) InvalidateRect(g_ghost.editorHwnd, nullptr, FALSE);
}

bool GhostText_IsVisible() { return g_ghost.visible; }
const std::string& GhostText_GetSuggestion() { return g_ghost.suggestion; }

// Called from editor paint to overlay ghost text at cursor position
void GhostText_Paint(HDC hdc, int cursorX, int cursorY, int charH)
{
    if (!g_ghost.visible || g_ghost.suggestion.empty()) return;
    HFONT font = IDECore_MonoFont();
    HFONT old  = (HFONT)SelectObject(hdc, font);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(100, 100, 100));
    RECT r = {cursorX, cursorY, cursorX + 800, cursorY + charH};
    DrawTextA(hdc, g_ghost.suggestion.c_str(), (int)g_ghost.suggestion.size(),
              &r, DT_LEFT | DT_SINGLELINE | DT_NOCLIP);
    SelectObject(hdc, old);
}

} // namespace RawrXD::IDE
