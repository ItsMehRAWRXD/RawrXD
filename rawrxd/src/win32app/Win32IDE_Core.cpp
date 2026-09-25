// Win32IDE_Core.cpp — IDE core state, panel registry, layout engine
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <algorithm>
#include <cstdio>

namespace RawrXD::IDE {

// ── Panel IDs ────────────────────────────────────────────────────────────────
enum class PanelID {
    Editor = 0,
    Sidebar,
    Chat,
    Agent,
    Terminal,
    Git,
    Search,
    Problems,
    Output,
    Count
};

// ── Panel descriptor ─────────────────────────────────────────────────────────
struct Panel {
    PanelID     id;
    HWND        hwnd    = nullptr;
    bool        visible = true;
    int         x = 0, y = 0, w = 0, h = 0;
    std::string title;
};

// ── Core state ───────────────────────────────────────────────────────────────
static HWND  g_mainWnd   = nullptr;
static HFONT g_monoFont  = nullptr;
static HFONT g_uiFont    = nullptr;
static bool  g_darkMode  = true;

static std::vector<Panel> g_panels;
static std::unordered_map<int, std::function<void()>> g_commandHandlers;

// ── Colours ──────────────────────────────────────────────────────────────────
static COLORREF g_colBg       = RGB(30,  30,  30);
static COLORREF g_colPanel    = RGB(37,  37,  38);
static COLORREF g_colBorder   = RGB(60,  60,  60);
static COLORREF g_colText     = RGB(212, 212, 212);
static COLORREF g_colAccent   = RGB(0,   122, 204);

void IDECore_Init(HWND mainWnd)
{
    g_mainWnd = mainWnd;

    // Monospace font for editor/terminal
    g_monoFont = CreateFontA(
        16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN,
        "Consolas");
    if (!g_monoFont)
        g_monoFont = (HFONT)GetStockObject(ANSI_FIXED_FONT);

    // UI font
    g_uiFont = CreateFontA(
        14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS,
        "Segoe UI");
    if (!g_uiFont)
        g_uiFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
}

void IDECore_Shutdown()
{
    if (g_monoFont) { DeleteObject(g_monoFont); g_monoFont = nullptr; }
    if (g_uiFont)   { DeleteObject(g_uiFont);   g_uiFont   = nullptr; }
}

HWND  IDECore_MainWnd()  { return g_mainWnd; }
HFONT IDECore_MonoFont() { return g_monoFont; }
HFONT IDECore_UIFont()   { return g_uiFont; }
COLORREF IDECore_ColBg()     { return g_colBg; }
COLORREF IDECore_ColPanel()  { return g_colPanel; }
COLORREF IDECore_ColBorder() { return g_colBorder; }
COLORREF IDECore_ColText()   { return g_colText; }
COLORREF IDECore_ColAccent() { return g_colAccent; }

void IDECore_RegisterPanel(int idRaw, HWND hwnd, const std::string& title)
{
    PanelID id = static_cast<PanelID>(idRaw);
    for (auto& p : g_panels) {
        if (p.id == id) { p.hwnd = hwnd; p.title = title; return; }
    }
    Panel p;
    p.id    = id;
    p.hwnd  = hwnd;
    p.title = title;
    g_panels.push_back(p);
}

void IDECore_ShowPanel(PanelID id, bool show)
{
    for (auto& p : g_panels) {
        if (p.id == id) {
            p.visible = show;
            if (p.hwnd) ShowWindow(p.hwnd, show ? SW_SHOW : SW_HIDE);
            return;
        }
    }
}

HWND IDECore_GetPanel(PanelID id)
{
    for (auto& p : g_panels)
        if (p.id == id) return p.hwnd;
    return nullptr;
}

// ── Layout: tile panels inside client rect ───────────────────────────────────
// Layout:  [Sidebar(200)] | [Editor(flex)] | [Chat/Agent(320)]
//          [Terminal/Git/Search(200 bottom)]
void IDECore_Layout(int clientW, int clientH)
{
    const int sidebarW  = 200;
    const int rightW    = 340;
    const int bottomH   = 220;
    const int topH      = clientH - bottomH;

    // Sidebar
    HWND hSidebar = IDECore_GetPanel(PanelID::Sidebar);
    if (hSidebar)
        SetWindowPos(hSidebar, nullptr, 0, 0, sidebarW, topH, SWP_NOZORDER | SWP_NOACTIVATE);

    // Editor
    HWND hEditor = IDECore_GetPanel(PanelID::Editor);
    int editorX = sidebarW;
    int editorW = clientW - sidebarW - rightW;
    if (editorW < 100) editorW = 100;
    if (hEditor)
        SetWindowPos(hEditor, nullptr, editorX, 0, editorW, topH, SWP_NOZORDER | SWP_NOACTIVATE);

    // Chat panel (right)
    HWND hChat = IDECore_GetPanel(PanelID::Chat);
    if (hChat)
        SetWindowPos(hChat, nullptr, editorX + editorW, 0, rightW, topH, SWP_NOZORDER | SWP_NOACTIVATE);

    // Terminal (bottom left)
    HWND hTerm = IDECore_GetPanel(PanelID::Terminal);
    if (hTerm)
        SetWindowPos(hTerm, nullptr, 0, topH, clientW / 2, bottomH, SWP_NOZORDER | SWP_NOACTIVATE);

    // Git (bottom right)
    HWND hGit = IDECore_GetPanel(PanelID::Git);
    if (hGit)
        SetWindowPos(hGit, nullptr, clientW / 2, topH, clientW / 2, bottomH, SWP_NOZORDER | SWP_NOACTIVATE);
}

void IDECore_RegisterCommand(int cmdId, std::function<void()> handler)
{
    g_commandHandlers[cmdId] = std::move(handler);
}

bool IDECore_DispatchCommand(int cmdId)
{
    auto it = g_commandHandlers.find(cmdId);
    if (it != g_commandHandlers.end()) {
        it->second();
        return true;
    }
    return false;
}

} // namespace RawrXD::IDE
