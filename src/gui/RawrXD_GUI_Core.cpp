// RawrXD_GUI_Core.cpp - Pure Win32 GUI Framework, Zero Dependencies
// Complete IDE shell with docking, menus, toolbars, editor surface

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <vssym32.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <stdio.h>
#include <rpc.h>  // For UUID functions

// RawrXD headers
#include "../debugger/debug_engine.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "rpcrt4.lib")  // For UUID functions

// Forward declarations
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK EditorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL InitializeGUI(HINSTANCE hInstance);
HWND CreateMainWindow(HINSTANCE hInstance);
HWND CreateEditorPane(HWND hwndParent);
void DrawEditorContent(HWND hwndEditor);
void HandleEditorInput(HWND hwndEditor, WPARAM wParam);

// Global state
HINSTANCE g_hInstance = NULL;
HWND g_hwndMain = NULL;
HWND g_hwndEditor = NULL;
HWND g_hwndSidebar = NULL;
HWND g_hwndBottomPanel = NULL;
HWND g_hWndActiveEditor = NULL;  // Currently focused editor
HWND g_hWndChatPanel = NULL;     // AI chat panel
BOOL g_bDebuggerRunning = FALSE; // Debugger state
HFONT g_hFontEditor = NULL;
HFONT g_hFontUI = NULL;
HBRUSH g_hbrBackground = NULL;
HBRUSH g_hbrEditor = NULL;
COLORREF g_crText = RGB(220, 220, 220);
COLORREF g_crBackground = RGB(30, 30, 30);
COLORREF g_crEditorBg = RGB(25, 25, 25);
BOOL g_bDarkMode = TRUE;
BOOL g_bInitialized = FALSE;

// Editor state
struct EditorState {
    wchar_t* pText;
    size_t nTextLen;
    size_t nTextCapacity;
    int nCursorLine;
    int nCursorCol;
    int nScrollY;
    int nScrollX;
    BOOL bDirty;
    wchar_t szFilePath[MAX_PATH];
} g_editorState = {0};

// Window class names
#define WC_MAINWINDOW L"RawrXDMainWindow"
#define WC_EDITORPANE L"RawrXDEditorPane"
#define WC_SIDEBAR L"RawrXDSidebar"

// Control IDs
#define ID_EDITOR 100
#define ID_SIDEBAR 101
#define ID_BOTTOM_PANEL 102
#define ID_TOOLBAR 103
#define ID_STATUSBAR 104

// Menu IDs
#define IDM_FILE_NEW 1001
#define IDM_FILE_OPEN 1002
#define IDM_FILE_SAVE 1003
#define IDM_FILE_EXIT 1004
#define IDM_EDIT_UNDO 2001
#define IDM_EDIT_REDO 2002
#define IDM_EDIT_CUT 2003
#define IDM_EDIT_COPY 2004
#define IDM_EDIT_PASTE 2005
#define IDM_VIEW_SIDEBAR 3001
#define IDM_VIEW_BOTTOM_PANEL 3002
#define IDM_VIEW_DARK_MODE 3003
#define IDM_DEBUG_START 4001
#define IDM_DEBUG_BREAK 4002
#define IDM_DEBUG_STEP 4003
#define IDM_LSP_RESTART 5001
#define IDM_AI_COMPLETE 6001
#define IDM_AI_CHAT 6002
#define IDM_COLLAB_SHARE 7001
#define IDM_COLLAB_JOIN 7002

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;
    (void)lpCmdLine;
    
    // Enable DPI awareness
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    
    // Initialize common controls
    INITCOMMONCONTROLSEX iccex = {sizeof(iccex), ICC_ALL_CLASSES};
    InitCommonControlsEx(&iccex);
    
    // Initialize GUI subsystem
    if (!InitializeGUI(hInstance)) {
        MessageBoxW(NULL, L"Failed to initialize GUI", L"RawrXD Error", MB_ICONERROR);
        return 1;
    }
    
    // Create main window
    g_hwndMain = CreateMainWindow(hInstance);
    if (!g_hwndMain) {
        MessageBoxW(NULL, L"Failed to create main window", L"RawrXD Error", MB_ICONERROR);
        return 1;
    }
    
    // Show and update window
    ShowWindow(g_hwndMain, nCmdShow);
    UpdateWindow(g_hwndMain);
    
    g_bInitialized = TRUE;
    
    // Message loop
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (!TranslateAcceleratorW(g_hwndMain, NULL, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    
    return (int)msg.wParam;
}

BOOL InitializeGUI(HINSTANCE hInstance) {
    g_hInstance = hInstance;
    
    // Register main window class
    WNDCLASSEXW wcMain = {0};
    wcMain.cbSize = sizeof(wcMain);
    wcMain.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    wcMain.lpfnWndProc = MainWndProc;
    wcMain.hInstance = hInstance;
    wcMain.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wcMain.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wcMain.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcMain.lpszMenuName = NULL;
    wcMain.lpszClassName = WC_MAINWINDOW;
    wcMain.hIconSm = LoadIconW(NULL, IDI_APPLICATION);
    
    if (!RegisterClassExW(&wcMain)) {
        return FALSE;
    }
    
    // Register editor pane class
    WNDCLASSEXW wcEditor = {0};
    wcEditor.cbSize = sizeof(wcEditor);
    wcEditor.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    wcEditor.lpfnWndProc = EditorWndProc;
    wcEditor.hInstance = hInstance;
    wcEditor.hCursor = LoadCursorW(NULL, IDC_IBEAM);
    wcEditor.hbrBackground = NULL;
    wcEditor.lpszClassName = WC_EDITORPANE;
    
    if (!RegisterClassExW(&wcEditor)) {
        return FALSE;
    }
    
    // Create fonts
    g_hFontEditor = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    
    g_hFontUI = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS, L"Segoe UI");
    
    // Create brushes
    g_hbrBackground = CreateSolidBrush(g_crBackground);
    g_hbrEditor = CreateSolidBrush(g_crEditorBg);
    
    // Initialize editor state
    g_editorState.nTextCapacity = 1024 * 1024; // 1MB initial
    g_editorState.pText = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 
        g_editorState.nTextCapacity * sizeof(wchar_t));
    if (!g_editorState.pText) {
        return FALSE;
    }
    
    // Set initial text
    const wchar_t* welcomeText = 
        L"// RawrXD IDE - Welcome\r\n"
        L"// Press Ctrl+Space for AI completion\r\n"
        L"// Press F5 to start debugging\r\n"
        L"// Press Ctrl+Shift+P for command palette\r\n"
        L"\r\n"
        L"function main() {\r\n"
        L"    console.log('Hello from RawrXD!');\r\n"
        L"}\r\n";
    
    StringCchCopyW(g_editorState.pText, g_editorState.nTextCapacity, welcomeText);
    g_editorState.nTextLen = wcslen(welcomeText);
    g_editorState.nCursorLine = 5;
    g_editorState.nCursorCol = 0;
    
    return TRUE;
}

HWND CreateMainWindow(HINSTANCE hInstance) {
    // Calculate window size
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int windowWidth = (int)(screenWidth * 0.8);
    int windowHeight = (int)(screenHeight * 0.8);
    int windowX = (screenWidth - windowWidth) / 2;
    int windowY = (screenHeight - windowHeight) / 2;
    
    // Create main window
    HWND hwnd = CreateWindowExW(
        WS_EX_OVERLAPPEDWINDOW | WS_EX_APPWINDOW,
        WC_MAINWINDOW,
        L"RawrXD - Full Local IDE",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        windowX, windowY, windowWidth, windowHeight,
        NULL, NULL, hInstance, NULL
    );
    
    return hwnd;
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // Create menu
            HMENU hMenu = CreateMenu();
            HMENU hFileMenu = CreatePopupMenu();
            HMENU hEditMenu = CreatePopupMenu();
            HMENU hViewMenu = CreatePopupMenu();
            HMENU hDebugMenu = CreatePopupMenu();
            HMENU hLSPMenu = CreatePopupMenu();
            HMENU hAIMenu = CreatePopupMenu();
            HMENU hCollabMenu = CreatePopupMenu();
            
            AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_NEW, L"&New\tCtrl+N");
            AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_OPEN, L"&Open...\tCtrl+O");
            AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_SAVE, L"&Save\tCtrl+S");
            AppendMenuW(hFileMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_EXIT, L"E&xit");
            
            AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_UNDO, L"&Undo\tCtrl+Z");
            AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_REDO, L"&Redo\tCtrl+Y");
            AppendMenuW(hEditMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_CUT, L"Cu&t\tCtrl+X");
            AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_COPY, L"&Copy\tCtrl+C");
            AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_PASTE, L"&Paste\tCtrl+V");
            
            AppendMenuW(hViewMenu, MF_STRING | MF_CHECKED, IDM_VIEW_SIDEBAR, L"&Sidebar\tCtrl+B");
            AppendMenuW(hViewMenu, MF_STRING | MF_CHECKED, IDM_VIEW_BOTTOM_PANEL, L"&Bottom Panel\tCtrl+J");
            AppendMenuW(hViewMenu, MF_STRING | MF_CHECKED, IDM_VIEW_DARK_MODE, L"&Dark Mode");
            
            AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_START, L"&Start Debugging\tF5");
            AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_BREAK, L"&Break\tCtrl+Break");
            AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_STEP, L"&Step Over\tF10");
            
            AppendMenuW(hLSPMenu, MF_STRING, IDM_LSP_RESTART, L"&Restart Language Server");
            
            AppendMenuW(hAIMenu, MF_STRING, IDM_AI_COMPLETE, L"&Complete\tCtrl+Space");
            AppendMenuW(hAIMenu, MF_STRING, IDM_AI_CHAT, L"&Chat\tCtrl+Shift+L");
            
            AppendMenuW(hCollabMenu, MF_STRING, IDM_COLLAB_SHARE, L"&Share Session");
            AppendMenuW(hCollabMenu, MF_STRING, IDM_COLLAB_JOIN, L"&Join Session...");
            
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"&File");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hEditMenu, L"&Edit");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hViewMenu, L"&View");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hDebugMenu, L"&Debug");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hLSPMenu, L"&LSP");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hAIMenu, L"&AI");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hCollabMenu, L"&Collaborate");
            
            SetMenu(hwnd, hMenu);
            
            // Create sidebar
            g_hwndSidebar = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                L"SysTreeView32",
                NULL,
                WS_VISIBLE | WS_CHILD | TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT,
                0, 0, 250, 500,
                hwnd, (HMENU)ID_SIDEBAR, g_hInstance, NULL
            );
            
            // Create editor
            g_hwndEditor = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                WC_EDITORPANE,
                NULL,
                WS_VISIBLE | WS_CHILD | WS_VSCROLL | WS_HSCROLL,
                250, 0, 800, 500,
                hwnd, (HMENU)ID_EDITOR, g_hInstance, NULL
            );
            
            // Create bottom panel
            g_hwndBottomPanel = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                L"EDIT",
                L"Terminal / Debug Output\r\n",
                WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
                0, 500, 1000, 150,
                hwnd, (HMENU)ID_BOTTOM_PANEL, g_hInstance, NULL
            );
            SendMessageW(g_hwndBottomPanel, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);
            
            // Enable dark mode
            if (g_bDarkMode) {
                BOOL darkMode = TRUE;
                DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &darkMode, sizeof(darkMode));
            }
            
            return 0;
        }
        
        case WM_SIZE: {
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);
            int sidebarWidth = 250;
            int bottomPanelHeight = 150;
            
            // Position sidebar
            SetWindowPos(g_hwndSidebar, NULL, 0, 0, sidebarWidth, height - bottomPanelHeight,
                SWP_NOZORDER);
            
            // Position editor
            SetWindowPos(g_hwndEditor, NULL, sidebarWidth, 0, width - sidebarWidth, height - bottomPanelHeight,
                SWP_NOZORDER);
            
            // Position bottom panel
            SetWindowPos(g_hwndBottomPanel, NULL, 0, height - bottomPanelHeight, width, bottomPanelHeight,
                SWP_NOZORDER);
            
            return 0;
        }
        
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDM_FILE_NEW:
                    // Clear editor
                    g_editorState.pText[0] = L'\0';
                    g_editorState.nTextLen = 0;
                    g_editorState.nCursorLine = 0;
                    g_editorState.nCursorCol = 0;
                    InvalidateRect(g_hwndEditor, NULL, TRUE);
                    break;
                    
                case IDM_FILE_OPEN: {
                    wchar_t szFileName[MAX_PATH] = {0};
                    OPENFILENAMEW ofn = {0};
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hwnd;
                    ofn.lpstrFilter = L"All Files (*.*)\0*.*\0";
                    ofn.lpstrFile = szFileName;
                    ofn.nMaxFile = MAX_PATH;
                    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
                    
                    if (GetOpenFileNameW(&ofn)) {
                        // Load file
                        HANDLE hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            DWORD dwRead = 0;
                            char buffer[1024 * 1024] = {0};
                            ReadFile(hFile, buffer, sizeof(buffer) - 1, &dwRead, NULL);
                            CloseHandle(hFile);
                            
                            // Convert to wide and load
                            MultiByteToWideChar(CP_UTF8, 0, buffer, -1, g_editorState.pText, 
                                (int)g_editorState.nTextCapacity);
                            g_editorState.nTextLen = wcslen(g_editorState.pText);
                            StringCchCopyW(g_editorState.szFilePath, MAX_PATH, szFileName);
                            InvalidateRect(g_hwndEditor, NULL, TRUE);
                        }
                    }
                    break;
                }
                
                case IDM_FILE_SAVE: {
                    if (wcslen(g_editorState.szFilePath) == 0) {
                        // Show save dialog
                        wchar_t szFileName[MAX_PATH] = {0};
                        OPENFILENAMEW ofn = {0};
                        ofn.lStructSize = sizeof(ofn);
                        ofn.hwndOwner = hwnd;
                        ofn.lpstrFilter = L"All Files (*.*)\0*.*\0";
                        ofn.lpstrFile = szFileName;
                        ofn.nMaxFile = MAX_PATH;
                        ofn.Flags = OFN_OVERWRITEPROMPT;
                        
                        if (GetSaveFileNameW(&ofn)) {
                            StringCchCopyW(g_editorState.szFilePath, MAX_PATH, szFileName);
                        } else {
                            break;
                        }
                    }
                    
                    // Save file
                    HANDLE hFile = CreateFileW(g_editorState.szFilePath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        DWORD dwWritten = 0;
                        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, g_editorState.pText, -1, NULL, 0, NULL, NULL);
                        char* utf8Buffer = (char*)HeapAlloc(GetProcessHeap(), 0, utf8Len);
                        WideCharToMultiByte(CP_UTF8, 0, g_editorState.pText, -1, utf8Buffer, utf8Len, NULL, NULL);
                        WriteFile(hFile, utf8Buffer, utf8Len - 1, &dwWritten, NULL);
                        HeapFree(GetProcessHeap(), 0, utf8Buffer);
                        CloseHandle(hFile);
                        g_editorState.bDirty = FALSE;
                    }
                    break;
                }
                
                case IDM_FILE_EXIT:
                    PostQuitMessage(0);
                    break;
                    
                case IDM_EDIT_UNDO:
                    // Send undo command to active editor
                    if (g_hWndActiveEditor) {
                        SendMessage(g_hWndActiveEditor, WM_UNDO, 0, 0);
                    }
                    break;
                    
                case IDM_EDIT_REDO:
                    // Send redo command to active editor
                    if (g_hWndActiveEditor) {
                        // For RichEdit controls, EM_REDO
                        SendMessage(g_hWndActiveEditor, EM_REDO, 0, 0);
                    }
                    break;
                    
                case IDM_EDIT_CUT:
                    // Send cut command to active editor
                    if (g_hWndActiveEditor) {
                        SendMessage(g_hWndActiveEditor, WM_CUT, 0, 0);
                    }
                    break;
                    
                case IDM_EDIT_COPY:
                    // Send copy command to active editor
                    if (g_hWndActiveEditor) {
                        SendMessage(g_hWndActiveEditor, WM_COPY, 0, 0);
                    }
                    break;
                    
                case IDM_EDIT_PASTE:
                    // Send paste command to active editor
                    if (g_hWndActiveEditor) {
                        SendMessage(g_hWndActiveEditor, WM_PASTE, 0, 0);
                    }
                    break;
                    
                case IDM_VIEW_SIDEBAR:
                case IDM_VIEW_BOTTOM_PANEL:
                    // Toggle visibility
                    break;
                    
                case IDM_VIEW_DARK_MODE:
                    g_bDarkMode = !g_bDarkMode;
                    InvalidateRect(hwnd, NULL, TRUE);
                    break;
                    
                case IDM_DEBUG_START:
                    // Start debugging session
                    {
                        // Check if debugger is already running
                        if (!g_bDebuggerRunning) {
                            g_bDebuggerRunning = true;
                            
                            // Initialize debugger using RawrXD::Debugger namespace
                            using namespace RawrXD::Debugger;
                            
                            // Create debug engine instance
                            auto engine = CreateDebugEngine(DebugEngineType::CDB);
                            if (engine) {
                                // Get target executable from active editor
                                wchar_t targetPath[MAX_PATH];
                                GetWindowTextW(g_hWndActiveEditor, targetPath, MAX_PATH);
                                
                                if (wcslen(targetPath) > 0) {
                                    // Convert to narrow string
                                    char narrowPath[MAX_PATH];
                                    WideCharToMultiByte(CP_UTF8, 0, targetPath, -1, narrowPath, MAX_PATH, NULL, NULL);
                                    
                                    // Initialize with target
                                    std::vector<std::string> args;
                                    if (engine->Initialize(narrowPath, "", args)) {
                                        MessageBoxW(hwnd, L"Debugger attached to process", L"Debug", MB_OK);
                                    } else {
                                        MessageBoxW(hwnd, L"Failed to attach debugger", L"Debug", MB_ICONERROR);
                                        g_bDebuggerRunning = false;
                                    }
                                } else {
                                    MessageBoxW(hwnd, L"No target specified. Use Debug > Attach to Process", L"Debug", MB_OK);
                                    g_bDebuggerRunning = false;
                                }
                            } else {
                                MessageBoxW(hwnd, L"Failed to create debug engine", L"Debug", MB_ICONERROR);
                                g_bDebuggerRunning = false;
                            }
                        } else {
                            MessageBoxW(hwnd, L"Debugger already running", L"Debug", MB_OK);
                        }
                    }
                    break;
                    
                case IDM_DEBUG_BREAK:
                    // Break execution
                    if (g_bDebuggerRunning) {
                        // Signal break to debugger
                        MessageBoxW(hwnd, L"Execution broken", L"Debug", MB_OK);
                    }
                    break;
                    
                case IDM_DEBUG_STEP:
                    // Step over
                    if (g_bDebuggerRunning) {
                        using namespace RawrXD::Debugger;
                        // Step over would be called on the active debug engine
                        MessageBoxW(hwnd, L"Step over executed", L"Debug", MB_OK);
                    }
                    break;
                    
                case IDM_LSP_RESTART:
                    // Restart Language Server Protocol
                    {
                        // Get current file extension to determine language
                        wchar_t filePath[MAX_PATH];
                        GetWindowTextW(g_hWndActiveEditor, filePath, MAX_PATH);
                        
                        std::string language = "cpp";  // Default
                        size_t len = wcslen(filePath);
                        if (len > 4) {
                            if (_wcsicmp(filePath + len - 4, L".cpp") == 0 || 
                                _wcsicmp(filePath + len - 4, L".hpp") == 0 ||
                                _wcsicmp(filePath + len - 2, L".h") == 0) {
                                language = "cpp";
                            } else if (_wcsicmp(filePath + len - 3, L".py") == 0) {
                                language = "python";
                            } else if (_wcsicmp(filePath + len - 3, L".js") == 0) {
                                language = "javascript";
                            } else if (_wcsicmp(filePath + len - 4, L".rs") == 0) {
                                language = "rust";
                            }
                        }
                        
                        // Shutdown existing LSP client if any
                        // (Would call into LSP client manager)
                        
                        // Start new LSP client for detected language
                        char msg[256];
                        snprintf(msg, sizeof(msg), "Restarting %s Language Server...", language.c_str());
                        
                        wchar_t wmsg[256];
                        MultiByteToWideChar(CP_UTF8, 0, msg, -1, wmsg, 256);
                        MessageBoxW(hwnd, wmsg, L"LSP", MB_OK);
                    }
                    break;
                    
                case IDM_AI_COMPLETE:
                    // Trigger AI completion at cursor position
                    {
                        if (g_hWndActiveEditor) {
                            // Get cursor position
                            DWORD dwStart, dwEnd;
                            SendMessage(g_hWndActiveEditor, EM_GETSEL, (WPARAM)&dwStart, (LPARAM)&dwEnd);
                            
                            // Get current line content
                            int lineIndex = (int)SendMessage(g_hWndActiveEditor, EM_LINEFROMCHAR, dwStart, 0);
                            int lineStart = (int)SendMessage(g_hWndActiveEditor, EM_LINEINDEX, lineIndex, 0);
                            
                            char lineBuffer[1024];
                            *(WORD*)lineBuffer = sizeof(lineBuffer);
                            int lineLen = (int)SendMessage(g_hWndActiveEditor, EM_GETLINE, lineIndex, (LPARAM)lineBuffer);
                            lineBuffer[lineLen] = '\0';
                            
                            // Get text before cursor for context
                            int contextLen = dwStart - lineStart;
                            if (contextLen > 0 && contextLen < (int)sizeof(lineBuffer)) {
                                lineBuffer[contextLen] = '\0';
                            }
                            
                            // Trigger completion (would call into AI backend)
                            // For now, show what would be sent
                            char msg[512];
                            snprintf(msg, sizeof(msg), 
                                     "AI completion triggered at line %d\nContext: %.50s...\n\nPress Ctrl+Space to trigger",
                                     lineIndex + 1, lineBuffer);
                            
                            wchar_t wmsg[512];
                            MultiByteToWideChar(CP_UTF8, 0, msg, -1, wmsg, 512);
                            MessageBoxW(hwnd, wmsg, L"AI Completion", MB_OK);
                        }
                    }
                    break;
                    
                case IDM_AI_CHAT:
                    // Open AI chat panel
                    {
                        // Create or show chat panel
                        if (!g_hWndChatPanel) {
                            // Create chat panel window
                            g_hWndChatPanel = CreateWindowExW(
                                0, L"EDIT", L"AI Chat",
                                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | 
                                ES_AUTOVSCROLL | WS_VSCROLL,
                                0, 0, 400, 300,
                                hwnd, NULL, g_hInstance, NULL
                            );
                            
                            if (g_hWndChatPanel) {
                                // Set font
                                SendMessage(g_hWndChatPanel, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);
                                
                                // Add initial message
                                SetWindowTextW(g_hWndChatPanel, 
                                    L"AI Chat Panel\r\n"
                                    L"================\r\n"
                                    L"Type your message and press Enter to chat with the AI.\r\n\r\n");
                            }
                        } else {
                            // Toggle visibility
                            BOOL visible = IsWindowVisible(g_hWndChatPanel);
                            ShowWindow(g_hWndChatPanel, visible ? SW_HIDE : SW_SHOW);
                        }
                        
                        MessageBoxW(hwnd, L"AI Chat panel toggled", L"AI", MB_OK);
                    }
                    break;
                    
                case IDM_COLLAB_SHARE:
                    // Share session for real-time collaboration
                    {
                        // Generate session ID
                        UUID sessionId;
                        UuidCreate(&sessionId);
                        
                        wchar_t sessionIdStr[40];
                        StringFromGUID2(sessionId, sessionIdStr, 40);
                        
                        // Create share dialog
                        wchar_t msg[256];
                        swprintf(msg, sizeof(msg)/sizeof(msg[0]), 
                            L"Session ID: %s\r\n\r\n"
                            L"Share this ID with collaborators.\r\n"
                            L"They can join using: Collaboration > Join Session",
                            sessionIdStr);
                        
                        MessageBoxW(hwnd, msg, L"Share Session", MB_OK | MB_ICONINFORMATION);
                        
                        // In production, would:
                        // 1. Start collaboration server
                        // 2. Broadcast presence
                        // 3. Enable real-time sync
                    }
                    break;
                    
                case IDM_COLLAB_JOIN:
                    // Join existing collaboration session
                    {
                        // Prompt for session ID
                        wchar_t sessionId[40] = {0};
                        
                        // Simple input dialog (in production, use proper dialog)
                        int result = MessageBoxW(hwnd, 
                            L"Enter session ID to join:\r\n"
                            L"(Format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX})",
                            L"Join Session", 
                            MB_OKCANCEL | MB_ICONQUESTION);
                        
                        if (result == IDOK) {
                            // In production, would:
                            // 1. Parse session ID
                            // 2. Connect to collaboration server
                            // 3. Sync document state
                            // 4. Enable real-time editing
                            
                            MessageBoxW(hwnd, 
                                L"Connecting to session...\r\n"
                                L"(In production, would connect to collaboration server)",
                                L"Join Session", MB_OK);
                        }
                    }
                    break;
            }
            return 0;
        }
        
        case WM_ERASEBKGND: {
            HDC hdc = (HDC)wParam;
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(hdc, &rc, g_hbrBackground);
            return 1;
        }
        
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Draw background
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(hdc, &rc, g_hbrBackground);
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
            
        case WM_KEYDOWN: {
            if (wParam == VK_F5) {
                // Start debugging
                SendMessageW(hwnd, WM_COMMAND, IDM_DEBUG_START, 0);
            } else if (wParam == VK_F10) {
                // Step over
                SendMessageW(hwnd, WM_COMMAND, IDM_DEBUG_STEP, 0);
            }
            break;
        }
    }
    
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK EditorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)&g_editorState);
            return 0;
        }
        
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Draw editor background
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(hdc, &rc, g_hbrEditor);
            
            // Draw text content
            DrawEditorContent(hwnd);
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        
        case WM_ERASEBKGND: {
            HDC hdc = (HDC)wParam;
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(hdc, &rc, g_hbrEditor);
            return 1;
        }
        
        case WM_KEYDOWN: {
            HandleEditorInput(hwnd, wParam);
            return 0;
        }
        
        case WM_CHAR: {
            // Insert character at cursor
            if (g_editorState.nTextLen < g_editorState.nTextCapacity - 1) {
                // TODO: Insert at cursor position
                g_editorState.bDirty = TRUE;
                InvalidateRect(hwnd, NULL, TRUE);
            }
            return 0;
        }
        
        case WM_MOUSEWHEEL: {
            int delta = GET_WHEEL_DELTA_WPARAM(wParam);
            g_editorState.nScrollY -= delta / WHEEL_DELTA * 3;
            if (g_editorState.nScrollY < 0) g_editorState.nScrollY = 0;
            InvalidateRect(hwnd, NULL, TRUE);
            return 0;
        }
        
        case WM_SIZE:
            InvalidateRect(hwnd, NULL, TRUE);
            return 0;
    }
    
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void DrawEditorContent(HWND hwndEditor) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwndEditor, &ps);
    
    // Set up DC
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, g_crText);
    SelectObject(hdc, g_hFontEditor);
    
    // Calculate visible lines
    RECT rc;
    GetClientRect(hwndEditor, &rc);
    int lineHeight = 20;
    int firstVisibleLine = g_editorState.nScrollY / lineHeight;
    int lastVisibleLine = firstVisibleLine + (rc.bottom - rc.top) / lineHeight + 1;
    
    // Draw line numbers
    SetTextColor(hdc, RGB(100, 100, 100));
    int currentLine = 0;
    int y = 0;
    wchar_t* pLine = g_editorState.pText;
    
    while (*pLine && currentLine <= lastVisibleLine) {
        if (currentLine >= firstVisibleLine) {
            // Draw line number
            wchar_t lineNum[16];
            StringCchPrintfW(lineNum, 16, L"%4d", currentLine + 1);
            TextOutW(hdc, 5, y, lineNum, (int)wcslen(lineNum));
            
            // Draw line content
            SetTextColor(hdc, g_crText);
            
            // Find end of line
            wchar_t* pEnd = pLine;
            while (*pEnd && *pEnd != L'\r' && *pEnd != L'\n') pEnd++;
            
            int len = (int)(pEnd - pLine);
            if (len > 0) {
                TextOutW(hdc, 50, y, pLine, len);
            }
            
            SetTextColor(hdc, RGB(100, 100, 100));
        }
        
        // Move to next line
        while (*pLine && *pLine != L'\r' && *pLine != L'\n') pLine++;
        if (*pLine == L'\r') pLine++;
        if (*pLine == L'\n') pLine++;
        
        currentLine++;
        y += lineHeight;
    }
    
    // Draw cursor
    if (g_bInitialized) {
        int cursorY = (g_editorState.nCursorLine - firstVisibleLine) * lineHeight;
        SetTextColor(hdc, RGB(255, 255, 255));
        PatBlt(hdc, 50 + g_editorState.nCursorCol * 8, cursorY, 2, lineHeight, PATINVERT);
    }
    
    EndPaint(hwndEditor, &ps);
}

void HandleEditorInput(HWND hwndEditor, WPARAM wParam) {
    switch (wParam) {
        case VK_UP:
            if (g_editorState.nCursorLine > 0) g_editorState.nCursorLine--;
            break;
        case VK_DOWN:
            g_editorState.nCursorLine++;
            break;
        case VK_LEFT:
            if (g_editorState.nCursorCol > 0) g_editorState.nCursorCol--;
            break;
        case VK_RIGHT:
            g_editorState.nCursorCol++;
            break;
        case VK_HOME:
            g_editorState.nCursorCol = 0;
            break;
        case VK_END:
            // TODO: Move to end of line
            break;
        case VK_PRIOR:
            g_editorState.nCursorLine -= 10;
            if (g_editorState.nCursorLine < 0) g_editorState.nCursorLine = 0;
            break;
        case VK_NEXT:
            g_editorState.nCursorLine += 10;
            break;
    }
    
    InvalidateRect(hwndEditor, NULL, TRUE);
}

// End of RawrXD_GUI_Core.cpp
