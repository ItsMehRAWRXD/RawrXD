// Win32IDE_ShellLayout.cpp — shell layout: creates all panels and handles resize
#include <windows.h>
#include <string>

namespace RawrXD::IDE {

// Forward declarations
void IDECore_Init(HWND);
void IDECore_Layout(int, int);
void IDECore_RegisterPanel(int, HWND, const std::string&);
HWND EditorEngine_Create(HWND, int, int, int, int, HINSTANCE);
void EditorEngine_Register(HINSTANCE);
HWND TabManager_Create(HWND, int, int, int, int, HINSTANCE);
void TabManager_Register(HINSTANCE);
HWND ChatPanel_Create(HWND, int, int, int, int, HINSTANCE);
void ChatPanel_Register(HINSTANCE);
HWND AgentPanel_Create(HWND, int, int, int, int, HINSTANCE);
void AgentPanel_Register(HINSTANCE);
HWND TerminalSplit_Create(HWND, int, int, int, int, HINSTANCE);
void TerminalSplit_Register(HINSTANCE);
HWND GitPanel_Create(HWND, int, int, int, int, HINSTANCE);
void GitPanel_Register(HINSTANCE);
HWND SearchPanel_Create(HWND, int, int, int, int, HINSTANCE);
void SearchPanel_Register(HINSTANCE);
extern "C" HWND Sidebar_Create(HWND, int, int, int, int, HINSTANCE);
extern "C" void Sidebar_Register(HINSTANCE);

HWND StatusBar_Create(HWND, int, int, int, int, HINSTANCE);
void StatusBar_Register(HINSTANCE);
void StatusBar_Resize(int, int);

static HWND g_hSidebar  = nullptr;
static HWND g_hTabBar   = nullptr;
static HWND g_hEditor   = nullptr;
static HWND g_hChat     = nullptr;
static HWND g_hAgent    = nullptr;
static HWND g_hTerminal = nullptr;
static HWND g_hGit      = nullptr;
static HWND g_hSearch   = nullptr;
static HWND g_hStatus   = nullptr;

static bool g_showChat    = true;
static bool g_showAgent   = false;
static bool g_showTerminal= true;
static bool g_showGit     = false;
static bool g_showSearch  = false;

void ShellLayout_RegisterAll(HINSTANCE hInst)
{
    TabManager_Register(hInst);
    EditorEngine_Register(hInst);
    ChatPanel_Register(hInst);
    AgentPanel_Register(hInst);
    TerminalSplit_Register(hInst);
    GitPanel_Register(hInst);
    SearchPanel_Register(hInst);
    Sidebar_Register(hInst);
    StatusBar_Register(hInst);
}

void ShellLayout_CreateAll(HWND parent, HINSTANCE hInst)
{
    IDECore_Init(parent);

    RECT rc; GetClientRect(parent, &rc);
    int W = rc.right, H = rc.bottom;

    g_hSidebar  = Sidebar_Create(parent,  0, 0, 200, H, hInst);
    g_hTabBar   = TabManager_Create(parent, 200, 0, W - 540, 28, hInst);
    g_hEditor   = EditorEngine_Create(parent, 200, 28, W - 540, H - 220 - 28, hInst);
    g_hChat     = ChatPanel_Create(parent, W - 340, 0, 340, H, hInst);
    g_hAgent    = AgentPanel_Create(parent, W - 340, 0, 340, H, hInst);
    g_hTerminal = TerminalSplit_Create(parent, 200, H - 220, (W - 540) / 2, 220, hInst);
    g_hGit      = GitPanel_Create(parent, 200 + (W - 540) / 2, H - 220, (W - 540) / 2, 220, hInst);
    g_hSearch   = SearchPanel_Create(parent, 200, H - 220, W - 540, 220, hInst);
    g_hStatus   = StatusBar_Create(parent, 0, H - 24, W, 24, hInst);

    // Register with core
    IDECore_RegisterPanel(1 /*Sidebar*/,  g_hSidebar,  "Explorer");    IDECore_RegisterPanel(0 /*TabBar*/,    g_hTabBar,   "Tabs");    IDECore_RegisterPanel(0 /*Editor*/,   g_hEditor,   "Editor");
    IDECore_RegisterPanel(2 /*Chat*/,     g_hChat,     "Chat");
    IDECore_RegisterPanel(3 /*Agent*/,    g_hAgent,    "Agent");
    IDECore_RegisterPanel(4 /*Terminal*/, g_hTerminal, "Terminal");
    IDECore_RegisterPanel(5 /*Git*/,      g_hGit,      "Git");
    IDECore_RegisterPanel(6 /*Search*/,   g_hSearch,   "Search");

    // Initial visibility
    ShowWindow(g_hAgent,  SW_HIDE);
    ShowWindow(g_hSearch, SW_HIDE);
    ShowWindow(g_hGit,    SW_HIDE);
}

void ShellLayout_Resize(int W, int H)
{
    const int sideW  = 200;
    const int rightW = 340;
    const int botH   = 220;
    const int topH   = H - botH;
    const int midW   = W - sideW - rightW;

    if (g_hSidebar)  SetWindowPos(g_hSidebar,  nullptr, 0,              0,    sideW,       topH, SWP_NOZORDER|SWP_NOACTIVATE);
    if (g_hTabBar)   SetWindowPos(g_hTabBar,   nullptr, sideW,          0,    midW,        28,   SWP_NOZORDER|SWP_NOACTIVATE);
    if (g_hEditor)   SetWindowPos(g_hEditor,   nullptr, sideW,          28,   midW,        topH-28, SWP_NOZORDER|SWP_NOACTIVATE);
    if (g_hChat)     SetWindowPos(g_hChat,     nullptr, sideW + midW,   0,    rightW,      H,    SWP_NOZORDER|SWP_NOACTIVATE);
    if (g_hAgent)    SetWindowPos(g_hAgent,    nullptr, sideW + midW,   0,    rightW,      H,    SWP_NOZORDER|SWP_NOACTIVATE);
    if (g_hTerminal) SetWindowPos(g_hTerminal, nullptr, sideW,          topH, midW / 2,    botH, SWP_NOZORDER|SWP_NOACTIVATE);
    if (g_hGit)      SetWindowPos(g_hGit,      nullptr, sideW+midW/2,   topH, midW - midW/2, botH, SWP_NOZORDER|SWP_NOACTIVATE);
    if (g_hSearch)   SetWindowPos(g_hSearch,   nullptr, sideW,          topH, midW,        botH, SWP_NOZORDER|SWP_NOACTIVATE);
    if (g_hStatus)   StatusBar_Resize(W, H);
}

void ShellLayout_ToggleChat()
{
    g_showChat = !g_showChat;
    if (g_hChat) ShowWindow(g_hChat, g_showChat ? SW_SHOW : SW_HIDE);
}

void ShellLayout_ToggleAgent()
{
    g_showAgent = !g_showAgent;
    if (g_hAgent) ShowWindow(g_hAgent, g_showAgent ? SW_SHOW : SW_HIDE);
    if (g_showAgent && g_hChat) ShowWindow(g_hChat, SW_HIDE);
}

void ShellLayout_ToggleTerminal()
{
    g_showTerminal = !g_showTerminal;
    if (g_hTerminal) ShowWindow(g_hTerminal, g_showTerminal ? SW_SHOW : SW_HIDE);
}

void ShellLayout_ToggleSearch()
{
    g_showSearch = !g_showSearch;
    if (g_hSearch) ShowWindow(g_hSearch, g_showSearch ? SW_SHOW : SW_HIDE);
    if (g_showSearch) {
        if (g_hTerminal) ShowWindow(g_hTerminal, SW_HIDE);
        if (g_hGit)      ShowWindow(g_hGit,      SW_HIDE);
    }
}

void ShellLayout_ToggleGit()
{
    g_showGit = !g_showGit;
    if (g_hGit) ShowWindow(g_hGit, g_showGit ? SW_SHOW : SW_HIDE);
}

HWND ShellLayout_GetEditor()   { return g_hEditor; }
HWND ShellLayout_GetChat()     { return g_hChat; }
HWND ShellLayout_GetAgent()    { return g_hAgent; }
HWND ShellLayout_GetTerminal() { return g_hTerminal; }
HWND ShellLayout_GetSidebar()  { return g_hSidebar; }
HWND ShellLayout_GetStatusBar(){ return g_hStatus; }

} // namespace RawrXD::IDE
