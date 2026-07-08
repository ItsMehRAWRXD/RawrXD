// Win32IDE_Helpers.cpp
// Implementation of helper functions for menu handlers
// This file provides the glue between menu handlers and the main IDE

#include "../win32app/Win32IDE.h"
#include "Win32IDE_Resource.h"
#include <string>

// Force Unicode APIs
#undef GetWindowText
#define GetWindowText GetWindowTextW
#undef SetWindowText
#define SetWindowText SetWindowTextW
#undef GetFileAttributes
#define GetFileAttributes GetFileAttributesW
#undef MessageBox
#define MessageBox MessageBoxW
#undef CreateWindowEx
#define CreateWindowEx CreateWindowExW
#undef CreateFont
#define CreateFont CreateFontW

// External globals from main Win32IDE
extern HWND g_hWndMain;
extern HWND g_hWndEditor;
extern HWND g_hWndStatusBar;
extern HWND g_hWndOutput;
extern HINSTANCE g_hInstance;

// Current project path
static std::wstring g_currentProjectPath;
static std::wstring g_currentProjectName;

// =============================================================================
// DOCUMENT PATH HELPERS
// =============================================================================

std::wstring GetActiveDocumentPath() {
    // Get the path from the window title or internal storage
    // For now, return the current project path if available
    if (!g_currentProjectPath.empty()) {
        return g_currentProjectPath;
    }
    
    // Try to get from editor window text (if it contains a path)
    wchar_t buffer[MAX_PATH];
    if (GetWindowText(g_hWndEditor, buffer, MAX_PATH) > 0) {
        // Check if it looks like a path
        if (wcschr(buffer, L'\\') != nullptr || wcschr(buffer, L'/') != nullptr) {
            return std::wstring(buffer);
        }
    }
    
    return L"";
}

void SetActiveDocumentPath(const wchar_t* path) {
    if (path) {
        g_currentProjectPath = path;
    }
}

std::wstring GetCurrentProjectName() {
    return g_currentProjectName;
}

void SetCurrentProjectName(const wchar_t* name) {
    if (name) {
        g_currentProjectName = name;
    }
}

// =============================================================================
// STATUS BAR HELPERS
// =============================================================================

void SetStatusBarText(const wchar_t* text) {
    if (!g_hWndStatusBar || !text) return;
    
    // Send message to set status bar text (part 0 = main panel)
    SendMessage(g_hWndStatusBar, SB_SETTEXT, 0, (LPARAM)text);
    
    // Force redraw
    InvalidateRect(g_hWndStatusBar, nullptr, FALSE);
}

void SetStatusBarProgress(int percent) {
    if (!g_hWndStatusBar) return;
    
    // If we have a progress bar in the status bar, update it
    // For now, show percentage in text
    wchar_t buffer[64];
    swprintf_s(buffer, L"Progress: %d%%", percent);
    SendMessage(g_hWndStatusBar, SB_SETTEXT, 1, (LPARAM)buffer);
}

void ClearStatusBar() {
    if (!g_hWndStatusBar) return;
    SendMessage(g_hWndStatusBar, SB_SETTEXT, 0, (LPARAM)L"Ready");
}

// =============================================================================
// OUTPUT WINDOW HELPERS
// =============================================================================

void AppendOutputText(const wchar_t* text) {
    if (!g_hWndOutput || !text) return;
    
    // Get current length
    int len = GetWindowTextLength(g_hWndOutput);
    
    // Move cursor to end
    SendMessage(g_hWndOutput, EM_SETSEL, len, len);
    
    // Append text
    SendMessage(g_hWndOutput, EM_REPLACESEL, 0, (LPARAM)text);
    
    // Add newline
    SendMessage(g_hWndOutput, EM_REPLACESEL, 0, (LPARAM)L"\r\n");
    
    // Scroll to bottom
    SendMessage(g_hWndOutput, EM_SCROLL, SB_BOTTOM, 0);
}

void ClearOutputWindow() {
    if (!g_hWndOutput) return;
    SetWindowText(g_hWndOutput, L"");
}

void AppendOutputTextA(const char* text) {
    if (!text) return;
    
    // Convert to wide string
    int len = MultiByteToWideChar(CP_UTF8, 0, text, -1, nullptr, 0);
    if (len > 0) {
        std::wstring wideText(len, 0);
        MultiByteToWideChar(CP_UTF8, 0, text, -1, &wideText[0], len);
        AppendOutputText(wideText.c_str());
    }
}

// =============================================================================
// MENU HELPERS
// =============================================================================

void EnableMenuItemByID(int id, BOOL enable) {
    if (!g_hWndMain) return;
    
    HMENU hMenu = GetMenu(g_hWndMain);
    if (!hMenu) return;
    
    UINT flags = enable ? (MF_BYCOMMAND | MF_ENABLED) : (MF_BYCOMMAND | MF_GRAYED);
    EnableMenuItem(hMenu, id, flags);
    
    // Force menu update
    DrawMenuBar(g_hWndMain);
}

void CheckMenuItemByID(int id, BOOL checked) {
    if (!g_hWndMain) return;
    
    HMENU hMenu = GetMenu(g_hWndMain);
    if (!hMenu) return;
    
    UINT flags = MF_BYCOMMAND | (checked ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuItem(hMenu, id, flags);
}

// =============================================================================
// EDITOR HELPERS
// =============================================================================

std::wstring GetEditorText() {
    if (!g_hWndEditor) return L"";
    
    int len = GetWindowTextLength(g_hWndEditor);
    if (len == 0) return L"";
    
    std::wstring text(len + 1, 0);
    GetWindowText(g_hWndEditor, &text[0], len + 1);
    
    return text;
}

void SetEditorText(const wchar_t* text) {
    if (!g_hWndEditor || !text) return;
    SetWindowText(g_hWndEditor, text);
}

// =============================================================================
// UTILITY HELPERS
// =============================================================================

bool IsProjectOpen() {
    return !g_currentProjectPath.empty();
}

bool IsBuildOutputAvailable() {
    if (!IsProjectOpen()) return false;
    
    // Check if .exe file exists
    std::wstring exePath = g_currentProjectPath;
    size_t dotPos = exePath.find_last_of(L'.');
    if (dotPos != std::wstring::npos) {
        exePath = exePath.substr(0, dotPos) + L".exe";
    } else {
        exePath += L".exe";
    }
    
    DWORD attribs = GetFileAttributes(exePath.c_str());
    return (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY));
}

void ShowErrorMessage(const wchar_t* message) {
    MessageBox(g_hWndMain, message, L"RawrXD IDE - Error", MB_OK | MB_ICONERROR);
}

void ShowInfoMessage(const wchar_t* message) {
    MessageBox(g_hWndMain, message, L"RawrXD IDE", MB_OK | MB_ICONINFORMATION);
}

bool AskYesNoQuestion(const wchar_t* question) {
    return MessageBox(g_hWndMain, question, L"RawrXD IDE", MB_YESNO | MB_ICONQUESTION) == IDYES;
}

// =============================================================================
// WINDOW CREATION HELPERS
// =============================================================================

HWND CreateOutputWindow(HWND hWndParent, HINSTANCE hInstance) {
    HWND hWndOutput = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
        0, 0, 0, 0,
        hWndParent,
        (HMENU)40401,
        hInstance,
        nullptr
    );
    
    if (hWndOutput) {
        // Set a nice font
        HFONT hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
        SendMessage(hWndOutput, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    
    return hWndOutput;
}

HWND CreateProjectPanel(HWND hWndParent, HINSTANCE hInstance) {
    // Create a tree view for project files
    HWND hWndProject = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"SysTreeView32",
        L"",
        WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS,
        0, 0, 0, 0,
        hWndParent,
        (HMENU)40402,
        hInstance,
        nullptr
    );
    
    return hWndProject;
}

// =============================================================================
// INITIALIZATION
// =============================================================================

void InitializeWin32IDEHelpers(HWND hWndMain, HWND hWndEditor, HWND hWndStatusBar, HINSTANCE hInstance) {
    g_hWndMain = hWndMain;
    g_hWndEditor = hWndEditor;
    g_hWndStatusBar = hWndStatusBar;
    g_hInstance = hInstance;
    
    // Create output window
    g_hWndOutput = CreateOutputWindow(hWndMain, hInstance);
    
    // Initial status
    SetStatusBarText(L"Ready");
}
