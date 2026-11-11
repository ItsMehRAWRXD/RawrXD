// ============================================================================
// main.cpp - RawrXD IDE Entry Point
// ============================================================================
// Complete integration of all production components:
// - GGUFLoader_Fixed
// - Agentic Tools
// - DebuggerCore
// - GitIntegration
// - ANSITerminalRenderer
// - LSPClient
// - GhostTextEngine
// - ScintillaEditor
// ============================================================================

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <string>
#include <memory>
#include <iostream>

#include "../ide/IDECore.h"
#include "../ide/SettingsManager.hpp"
#include "gguf_loader.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")

// Version info
#define RAWRXD_VERSION_MAJOR 1
#define RAWRXD_VERSION_MINOR 0
#define RAWRXD_VERSION_PATCH 0
#define RAWRXD_VERSION_STRING "1.0.0"

// Window constants
static constexpr wchar_t MAIN_WINDOW_CLASS[] = L"RawrXD_IDE_MainWindow_v1.0";
static constexpr wchar_t MAIN_WINDOW_TITLE[] = L"RawrXD Sovereign AI IDE v1.0.0";

// Global IDE instance
static std::unique_ptr<RawrXD::IDE::IDECore> g_ideCore;
static HINSTANCE g_hInstance = nullptr;
static HWND g_hwndMain = nullptr;

// Forward declarations
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
bool InitializeApplication(HINSTANCE hInstance);
void ShutdownApplication();
bool CreateMainWindow(HINSTANCE hInstance, int nCmdShow);
void InitializeMenus(HWND hwnd);
void InitializeToolbar(HWND hwnd);
void InitializeStatusBar(HWND hwnd);
void UpdateLayout();
void ShowFirstRunDialog();

// Menu IDs
enum MenuIDs {
    // File
    IDM_FILE_NEW = 100,
    IDM_FILE_OPEN,
    IDM_FILE_SAVE,
    IDM_FILE_SAVEAS,
    IDM_FILE_EXIT,
    
    // Edit
    IDM_EDIT_UNDO,
    IDM_EDIT_REDO,
    IDM_EDIT_CUT,
    IDM_EDIT_COPY,
    IDM_EDIT_PASTE,
    IDM_EDIT_FIND,
    IDM_EDIT_REPLACE,
    IDM_EDIT_SELECTALL,
    
    // View
    IDM_VIEW_LINENUMBERS,
    IDM_VIEW_WORDWRAP,
    IDM_VIEW_WHITESPACE,
    IDM_VIEW_THEME_DARK,
    IDM_VIEW_THEME_LIGHT,
    IDM_VIEW_FULLSCREEN,
    
    // AI
    IDM_AI_COMPLETE,
    IDM_AI_EXPLAIN,
    IDM_AI_FIX,
    IDM_AI_GENERATE,
    IDM_AI_STOP,
    IDM_AI_LOADMODEL,
    IDM_AI_SETTINGS,
    
    // Build
    IDM_BUILD_BUILD,
    IDM_BUILD_RUN,
    IDM_BUILD_DEBUG,
    IDM_BUILD_CLEAN,
    IDM_BUILD_CONFIGURE,
    
    // Git
    IDM_GIT_COMMIT,
    IDM_GIT_PUSH,
    IDM_GIT_PULL,
    IDM_GIT_FETCH,
    IDM_GIT_DIFF,
    IDM_GIT_BLAME,
    IDM_GIT_LOG,
    IDM_GIT_BRANCH,
    IDM_GIT_STASH,
    
    // Debug
    IDM_DEBUG_START,
    IDM_DEBUG_STOP,
    IDM_DEBUG_BREAK,
    IDM_DEBUG_STEP_OVER,
    IDM_DEBUG_STEP_INTO,
    IDM_DEBUG_STEP_OUT,
    IDM_DEBUG_TOGGLE_BREAKPOINT,
    
    // Tools
    IDM_TOOLS_TERMINAL,
    IDM_TOOLS_AGENTIC,
    IDM_TOOLS_OPTIONS,
    
    // Help
    IDM_HELP_DOCS,
    IDM_HELP_ABOUT
};

// ============================================================================
// Application Entry Point
// ============================================================================

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                    LPWSTR lpCmdLine, int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    
    // Initialize console for debugging (in debug builds)
    #ifdef _DEBUG
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    std::cout << "RawrXD IDE v" << RAWRXD_VERSION_STRING << " [Debug Mode]" << std::endl;
    #endif
    
    // Initialize COM
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        MessageBoxW(nullptr, L"Failed to initialize COM", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    // Initialize application
    if (!InitializeApplication(hInstance)) {
        MessageBoxW(nullptr, L"Failed to initialize application", L"Error", 
                     MB_OK | MB_ICONERROR);
        CoUninitialize();
        return 1;
    }
    
    // Create main window
    if (!CreateMainWindow(hInstance, nCmdShow)) {
        MessageBoxW(nullptr, L"Failed to create main window", L"Error", 
                     MB_OK | MB_ICONERROR);
        ShutdownApplication();
        CoUninitialize();
        return 1;
    }
    
    // Show first-run dialog if needed
    ShowFirstRunDialog();
    
    // Main message loop
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    
    // Cleanup
    ShutdownApplication();
    CoUninitialize();
    
    return static_cast<int>(msg.wParam);
}

// ============================================================================
// Application Initialization
// ============================================================================

bool InitializeApplication(HINSTANCE hInstance) {
    g_hInstance = hInstance;
    
    // Initialize common controls
    INITCOMMONCONTROLSEX iccex{};
    iccex.dwSize = sizeof(iccex);
    iccex.dwICC = ICC_BAR_CLASSES | ICC_TREEVIEW_CLASSES | ICC_TAB_CLASSES;
    if (!InitCommonControlsEx(&iccex)) {
        OutputDebugStringW(L"Failed to initialize common controls\n");
        return false;
    }
    
    // Create IDE core
    g_ideCore = std::make_unique<RawrXD::IDE::IDECore>();
    if (!g_ideCore) {
        OutputDebugStringW(L"Failed to create IDE core\n");
        return false;
    }
    
    // Load settings
    RawrXD::IDE::RawrXD_IDE ideSettings{};
    if (!RawrXD::IDE::LoadSettings(&ideSettings)) {
        OutputDebugStringW(L"No previous settings found, using defaults\n");
    }
    
    // Initialize IDE core with settings
    RawrXD::IDE::IDEConfig config;
    config.windowWidth = ideSettings.windowWidth;
    config.windowHeight = ideSettings.windowHeight;
    config.windowX = ideSettings.windowX;
    config.windowY = ideSettings.windowY;
    config.maximized = ideSettings.maximized;
    config.darkTheme = (ideSettings.theme == "dark");
    config.fontSize = ideSettings.fontSize;
    config.enableGhostText = ideSettings.enableGhostText;
    config.enableLSP = ideSettings.enableLSP;
    
    if (!g_ideCore->Initialize(config)) {
        OutputDebugStringW(L"Failed to initialize IDE core\n");
        return false;
    }
    
    OutputDebugStringW(L"Application initialized successfully\n");
    return true;
}

void ShutdownApplication() {
    if (g_ideCore) {
        g_ideCore->Shutdown();
        g_ideCore.reset();
    }
    
    OutputDebugStringW(L"Application shutdown complete\n");
}

// ============================================================================
// Main Window Creation
// ============================================================================

bool CreateMainWindow(HINSTANCE hInstance, int nCmdShow) {
    // Register window class
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName = nullptr;
    wc.lpszClassName = MAIN_WINDOW_CLASS;
    wc.hIconSm = LoadIconW(nullptr, IDI_APPLICATION);
    
    if (!RegisterClassExW(&wc)) {
        OutputDebugStringW(L"Failed to register window class\n");
        return false;
    }
    
    // Load settings for window position
    RawrXD::IDE::RawrXD_IDE ideSettings{};
    RawrXD::IDE::LoadSettings(&ideSettings);
    
    // Create main window
    g_hwndMain = CreateWindowExW(
        WS_EX_OVERLAPPEDWINDOW,
        MAIN_WINDOW_CLASS,
        MAIN_WINDOW_TITLE,
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_VISIBLE,
        ideSettings.windowX, ideSettings.windowY,
        ideSettings.windowWidth, ideSettings.windowHeight,
        nullptr, nullptr, hInstance, nullptr
    );
    
    if (!g_hwndMain) {
        OutputDebugStringW(L"Failed to create main window\n");
        return false;
    }
    
    // Initialize menus
    InitializeMenus(g_hwndMain);
    
    // Initialize toolbar
    InitializeToolbar(g_hwndMain);
    
    // Initialize status bar
    InitializeStatusBar(g_hwndMain);
    
    // Show window
    ShowWindow(g_hwndMain, ideSettings.maximized ? SW_SHOWMAXIMIZED : nCmdShow);
    UpdateWindow(g_hwndMain);
    
    return true;
}

// ============================================================================
// Menu Initialization
// ============================================================================

void InitializeMenus(HWND hwnd) {
    HMENU hMenu = CreateMenu();
    
    // File menu
    HMENU hFileMenu = CreatePopupMenu();
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_NEW, L"&New\tCtrl+N");
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_OPEN, L"&Open...\tCtrl+O");
    AppendMenuW(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_SAVE, L"&Save\tCtrl+S");
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_SAVEAS, L"Save &As...\tCtrl+Shift+S");
    AppendMenuW(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_EXIT, L"E&xit\tAlt+F4");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"&File");
    
    // Edit menu
    HMENU hEditMenu = CreatePopupMenu();
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_UNDO, L"&Undo\tCtrl+Z");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_REDO, L"&Redo\tCtrl+Y");
    AppendMenuW(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_CUT, L"Cu&t\tCtrl+X");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_COPY, L"&Copy\tCtrl+C");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_PASTE, L"&Paste\tCtrl+V");
    AppendMenuW(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_FIND, L"&Find...\tCtrl+F");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_REPLACE, L"&Replace...\tCtrl+H");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hEditMenu, L"&Edit");
    
    // View menu
    HMENU hViewMenu = CreatePopupMenu();
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_LINENUMBERS, L"Line &Numbers");
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_WORDWRAP, L"&Word Wrap");
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_WHITESPACE, L"&Whitespace");
    AppendMenuW(hViewMenu, MF_SEPARATOR, 0, nullptr);
    HMENU hThemeMenu = CreatePopupMenu();
    AppendMenuW(hThemeMenu, MF_STRING, IDM_VIEW_THEME_DARK, L"&Dark");
    AppendMenuW(hThemeMenu, MF_STRING, IDM_VIEW_THEME_LIGHT, L"&Light");
    AppendMenuW(hViewMenu, MF_POPUP, (UINT_PTR)hThemeMenu, L"&Theme");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hViewMenu, L"&View");
    
    // AI menu
    HMENU hAIMenu = CreatePopupMenu();
    AppendMenuW(hAIMenu, MF_STRING, IDM_AI_COMPLETE, L"&Complete\tCtrl+Space");
    AppendMenuW(hAIMenu, MF_STRING, IDM_AI_EXPLAIN, L"&Explain\tCtrl+Shift+E");
    AppendMenuW(hAIMenu, MF_STRING, IDM_AI_FIX, L"&Fix\tCtrl+Shift+F");
    AppendMenuW(hAIMenu, MF_STRING, IDM_AI_GENERATE, L"&Generate...");
    AppendMenuW(hAIMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hAIMenu, MF_STRING, IDM_AI_STOP, L"&Stop Generation\tEscape");
    AppendMenuW(hAIMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hAIMenu, MF_STRING, IDM_AI_LOADMODEL, L"&Load Model...");
    AppendMenuW(hAIMenu, MF_STRING, IDM_AI_SETTINGS, L"AI &Settings...");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hAIMenu, L"&AI");
    
    // Build menu
    HMENU hBuildMenu = CreatePopupMenu();
    AppendMenuW(hBuildMenu, MF_STRING, IDM_BUILD_BUILD, L"&Build\tF7");
    AppendMenuW(hBuildMenu, MF_STRING, IDM_BUILD_RUN, L"&Run\tF5");
    AppendMenuW(hBuildMenu, MF_STRING, IDM_BUILD_DEBUG, L"&Debug\tF9");
    AppendMenuW(hBuildMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hBuildMenu, MF_STRING, IDM_BUILD_CLEAN, L"&Clean");
    AppendMenuW(hBuildMenu, MF_STRING, IDM_BUILD_CONFIGURE, L"&Configure...");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hBuildMenu, L"&Build");
    
    // Git menu
    HMENU hGitMenu = CreatePopupMenu();
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_COMMIT, L"&Commit...\tCtrl+K");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_PUSH, L"&Push\tCtrl+Shift+K");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_PULL, L"&Pull\tCtrl+Shift+L");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_FETCH, L"&Fetch");
    AppendMenuW(hGitMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_DIFF, L"&Diff");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_BLAME, L"&Blame");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_LOG, L"&Log");
    AppendMenuW(hGitMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_BRANCH, L"&Branch...");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_STASH, L"&Stash...");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hGitMenu, L"&Git");
    
    // Debug menu
    HMENU hDebugMenu = CreatePopupMenu();
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_START, L"&Start Debugging\tF9");
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_STOP, L"&Stop Debugging\tShift+F5");
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_BREAK, L"&Break\tCtrl+Break");
    AppendMenuW(hDebugMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_STEP_OVER, L"Step &Over\tF10");
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_STEP_INTO, L"Step &Into\tF11");
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_STEP_OUT, L"Step O&ut\tShift+F11");
    AppendMenuW(hDebugMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_TOGGLE_BREAKPOINT, 
                L"Toggle &Breakpoint\tF8");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hDebugMenu, L"&Debug");
    
    // Tools menu
    HMENU hToolsMenu = CreatePopupMenu();
    AppendMenuW(hToolsMenu, MF_STRING, IDM_TOOLS_TERMINAL, L"&Terminal\tCtrl+`");
    AppendMenuW(hToolsMenu, MF_STRING, IDM_TOOLS_AGENTIC, L"&Agentic Tools...");
    AppendMenuW(hToolsMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hToolsMenu, MF_STRING, IDM_TOOLS_OPTIONS, L"&Options...");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hToolsMenu, L"&Tools");
    
    // Help menu
    HMENU hHelpMenu = CreatePopupMenu();
    AppendMenuW(hHelpMenu, MF_STRING, IDM_HELP_DOCS, L"&Documentation\tF1");
    AppendMenuW(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, L"&About RawrXD");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, L"&Help");
    
    SetMenu(hwnd, hMenu);
}

void InitializeToolbar(HWND hwnd) {
    // Create toolbar
    HWND hToolbar = CreateWindowExW(0, TOOLBARCLASSNAMEW, nullptr,
        WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS,
        0, 0, 0, 0, hwnd, nullptr, g_hInstance, nullptr);
    
    if (!hToolbar) return;
    
    // Send TB_BUTTONSTRUCTSIZE message
    SendMessageW(hToolbar, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    
    // Add buttons
    TBBUTTON buttons[] = {
        { STD_FILENEW, IDM_FILE_NEW, TBSTATE_ENABLED, TBSTYLE_BUTTON, {0}, 0, (INT_PTR)L"New" },
        { STD_FILEOPEN, IDM_FILE_OPEN, TBSTATE_ENABLED, TBSTYLE_BUTTON, {0}, 0, (INT_PTR)L"Open" },
        { STD_FILESAVE, IDM_FILE_SAVE, TBSTATE_ENABLED, TBSTYLE_BUTTON, {0}, 0, (INT_PTR)L"Save" },
        { 0, 0, TBSTATE_ENABLED, TBSTYLE_SEP, {0}, 0, 0 },
        { STD_CUT, IDM_EDIT_CUT, TBSTATE_ENABLED, TBSTYLE_BUTTON, {0}, 0, (INT_PTR)L"Cut" },
        { STD_COPY, IDM_EDIT_COPY, TBSTATE_ENABLED, TBSTYLE_BUTTON, {0}, 0, (INT_PTR)L"Copy" },
        { STD_PASTE, IDM_EDIT_PASTE, TBSTATE_ENABLED, TBSTYLE_BUTTON, {0}, 0, (INT_PTR)L"Paste" },
        { 0, 0, TBSTATE_ENABLED, TBSTYLE_SEP, {0}, 0, 0 },
        { STD_UNDO, IDM_EDIT_UNDO, TBSTATE_ENABLED, TBSTYLE_BUTTON, {0}, 0, (INT_PTR)L"Undo" },
        { STD_REDOW, IDM_EDIT_REDO, TBSTATE_ENABLED, TBSTYLE_BUTTON, {0}, 0, (INT_PTR)L"Redo" },
    };
    
    SendMessageW(hToolbar, TB_ADDBUTTONS, ARRAYSIZE(buttons), (LPARAM)buttons);
    SendMessageW(hToolbar, TB_AUTOSIZE, 0, 0);
}

void InitializeStatusBar(HWND hwnd) {
    // Create status bar
    HWND hStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hwnd, nullptr, g_hInstance, nullptr);
    
    if (!hStatusBar) return;
    
    // Set parts
    int parts[] = { 100, 200, 350, 500, 650, -1 };
    SendMessageW(hStatusBar, SB_SETPARTS, ARRAYSIZE(parts), (LPARAM)parts);
    
    // Set initial text
    SendMessageW(hStatusBar, SB_SETTEXTW, 0, (LPARAM)L"Ln 1, Col 1");
    SendMessageW(hStatusBar, SB_SETTEXTW, 1, (LPARAM)L"UTF-8");
    SendMessageW(hStatusBar, SB_SETTEXTW, 2, (LPARAM)L"No model");
    SendMessageW(hStatusBar, SB_SETTEXTW, 3, (LPARAM)L"Ready");
}

// ============================================================================
// Window Procedure
// ============================================================================

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            return 0;
            
        case WM_SIZE:
            UpdateLayout();
            return 0;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                // File menu
                case IDM_FILE_NEW:
                    if (g_ideCore) g_ideCore->OnFileNew();
                    break;
                case IDM_FILE_OPEN:
                    if (g_ideCore) g_ideCore->OnFileOpen();
                    break;
                case IDM_FILE_SAVE:
                    if (g_ideCore) g_ideCore->OnFileSave();
                    break;
                case IDM_FILE_SAVEAS:
                    if (g_ideCore) g_ideCore->OnFileSaveAs();
                    break;
                case IDM_FILE_EXIT:
                    DestroyWindow(hwnd);
                    break;
                    
                // Edit menu
                case IDM_EDIT_UNDO:
                    if (g_ideCore) g_ideCore->OnEditUndo();
                    break;
                case IDM_EDIT_REDO:
                    if (g_ideCore) g_ideCore->OnEditRedo();
                    break;
                case IDM_EDIT_CUT:
                    if (g_ideCore) g_ideCore->OnEditCut();
                    break;
                case IDM_EDIT_COPY:
                    if (g_ideCore) g_ideCore->OnEditCopy();
                    break;
                case IDM_EDIT_PASTE:
                    if (g_ideCore) g_ideCore->OnEditPaste();
                    break;
                case IDM_EDIT_FIND:
                    if (g_ideCore) g_ideCore->OnEditFind();
                    break;
                case IDM_EDIT_REPLACE:
                    if (g_ideCore) g_ideCore->OnEditReplace();
                    break;
                    
                // View menu
                case IDM_VIEW_LINENUMBERS:
                    if (g_ideCore) g_ideCore->OnViewToggleLineNumbers();
                    break;
                case IDM_VIEW_WORDWRAP:
                    if (g_ideCore) g_ideCore->OnViewToggleWordWrap();
                    break;
                case IDM_VIEW_THEME_DARK:
                    if (g_ideCore) {
                        RawrXD::IDE::IDEConfig config = g_ideCore->GetConfig();
                        config.darkTheme = true;
                        g_ideCore->UpdateConfig(config);
                    }
                    break;
                case IDM_VIEW_THEME_LIGHT:
                    if (g_ideCore) {
                        RawrXD::IDE::IDEConfig config = g_ideCore->GetConfig();
                        config.darkTheme = false;
                        g_ideCore->UpdateConfig(config);
                    }
                    break;
                    
                // AI menu
                case IDM_AI_COMPLETE:
                    if (g_ideCore) g_ideCore->OnAIComplete();
                    break;
                case IDM_AI_EXPLAIN:
                    if (g_ideCore) g_ideCore->OnAIExplain();
                    break;
                case IDM_AI_FIX:
                    if (g_ideCore) g_ideCore->OnAIFix();
                    break;
                case IDM_AI_STOP:
                    if (g_ideCore) g_ideCore->OnAIStop();
                    break;
                    
                // Build menu
                case IDM_BUILD_BUILD:
                    if (g_ideCore) g_ideCore->OnBuildBuild();
                    break;
                case IDM_BUILD_RUN:
                    if (g_ideCore) g_ideCore->OnBuildRun();
                    break;
                case IDM_BUILD_CLEAN:
                    if (g_ideCore) g_ideCore->OnBuildClean();
                    break;
                    
                // Git menu
                case IDM_GIT_COMMIT:
                    if (g_ideCore) g_ideCore->OnGitCommit();
                    break;
                case IDM_GIT_PUSH:
                    if (g_ideCore) g_ideCore->OnGitPush();
                    break;
                case IDM_GIT_PULL:
                    if (g_ideCore) g_ideCore->OnGitPull();
                    break;
                case IDM_GIT_DIFF:
                    if (g_ideCore) g_ideCore->ShowGitDiff(g_ideCore->GetCurrentFile());
                    break;
                case IDM_GIT_BLAME:
                    if (g_ideCore) g_ideCore->ShowGitBlame(g_ideCore->GetCurrentFile());
                    break;
                case IDM_GIT_LOG:
                    if (g_ideCore) g_ideCore->ShowGitLog();
                    break;
                    
                // Help menu
                case IDM_HELP_ABOUT:
                    if (g_ideCore) g_ideCore->OnHelpAbout();
                    break;
            }
            return 0;
            
        case WM_KEYDOWN:
            // Handle ghost text keys
            if (g_ideCore && g_ideCore->IsGhostTextVisible()) {
                g_ideCore->OnGhostTextKeyDown(wParam);
            }
            return 0;
            
        case WM_CLOSE:
            // Save settings before closing
            if (g_ideCore) {
                g_ideCore->SaveSettings();
            }
            DestroyWindow(hwnd);
            return 0;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
            
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

// ============================================================================
// Layout Management
// ============================================================================

void UpdateLayout() {
    if (!g_hwndMain || !g_ideCore) return;
    
    // Get client area
    RECT rcClient;
    GetClientRect(g_hwndMain, &rcClient);
    
    // Layout child windows
    g_ideCore->LayoutWindows();
}

// ============================================================================
// First Run Dialog
// ============================================================================

void ShowFirstRunDialog() {
    // Check if this is first run
    wchar_t appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath))) {
        std::wstring configPath = std::wstring(appDataPath) + L"\\RawrXD\\first_run.flag";
        
        if (GetFileAttributesW(configPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            // First run - show welcome dialog
            int result = MessageBoxW(g_hwndMain,
                L"Welcome to RawrXD Sovereign AI IDE v1.0.0!\n\n"
                L"This is a fully local, offline-capable development environment\n"
                L"with AI-powered coding assistance.\n\n"
                L"Would you like to:\n"
                L"1. Download a sample model (TinyLlama 1.1B)\n"
                L"2. Configure your workspace\n"
                L"3. View the quick start guide\n\n"
                L"Click Yes to get started, No to skip.",
                L"Welcome to RawrXD",
                MB_YESNO | MB_ICONINFORMATION);
            
            if (result == IDYES) {
                // Open settings dialog
                if (g_ideCore) {
                    // TODO: Show first-run wizard
                }
            }
            
            // Create flag file
            CreateDirectoryW((std::wstring(appDataPath) + L"\\RawrXD").c_str(), nullptr);
            HANDLE hFile = CreateFileW(configPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
            }
        }
    }
}

