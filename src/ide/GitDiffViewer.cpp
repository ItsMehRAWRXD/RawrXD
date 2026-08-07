/**
 * @file GitDiffViewer.cpp
 * @brief Git Diff Viewer Implementation
 */

#include "GitDiffViewer.hpp"
#include <richedit.h>
#include <commctrl.h>
#include <sstream>
#include <iomanip>
#include <regex>
#include <algorithm>

// Toolbar and status bar constants
#ifndef TOOLBARCLASSNAMEW
#define TOOLBARCLASSNAMEW L"ToolbarWindow32"
#endif
#ifndef STATUSCLASSNAMEW
#define STATUSCLASSNAMEW L"msctls_statusbar32"
#endif

// Command IDs
#define ID_VIEW_SIDEBYSIDE 1001
#define ID_VIEW_UNIFIED    1002
#define ID_NAV_PREV        1003
#define ID_NAV_NEXT        1004
#define ID_EDIT_FIND       1005
#define ID_EDIT_COPY       1006
#define ID_FILE_EXPORT     1007

namespace RawrXD::IDE {

// Color scheme
const COLORREF GitDiffViewer::s_colorAdded = RGB(0, 128, 0);
const COLORREF GitDiffViewer::s_colorAddedBg = RGB(220, 255, 220);
const COLORREF GitDiffViewer::s_colorRemoved = RGB(200, 0, 0);
const COLORREF GitDiffViewer::s_colorRemovedBg = RGB(255, 220, 220);
const COLORREF GitDiffViewer::s_colorHeader = RGB(128, 128, 128);
const COLORREF GitDiffViewer::s_colorHeaderBg = RGB(240, 240, 240);
const COLORREF GitDiffViewer::s_colorLineNum = RGB(128, 128, 128);
const COLORREF GitDiffViewer::s_colorLineNumBg = RGB(245, 245, 245);

// Dialog template
constexpr wchar_t s_diffDialogTemplate[] =
    L"Git Diff Viewer\0"
    L"DS_MODALFRAME | DS_SETFONT | DS_FIXEDSYS | WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME\0"
    L"8\0"  // Font size
    L"MS Shell Dlg\0"
    L"\0";

GitDiffViewer::GitDiffViewer()
    : m_hwnd(nullptr)
    , m_hwndParent(nullptr)
    , m_hwndOldView(nullptr)
    , m_hwndNewView(nullptr)
    , m_hwndUnifiedView(nullptr)
    , m_hwndToolbar(nullptr)
    , m_hwndStatusBar(nullptr)
    , m_hwndSplitter(nullptr)
    , m_hInstance(nullptr)
    , m_viewMode(ViewMode::SideBySide)
    , m_currentHunk(0)
    , m_searchCaseSensitive(false)
{
}

GitDiffViewer::~GitDiffViewer() {
    Destroy();
}

bool GitDiffViewer::Create(HWND hwndParent, HINSTANCE hInstance) {
    if (m_hwnd) return true;
    
    m_hwndParent = hwndParent;
    m_hInstance = hInstance;
    
    // Register window class
    WNDCLASSEXW wcx = {};
    wcx.cbSize = sizeof(wcx);
    wcx.lpfnWndProc = DefWindowProcW;
    wcx.hInstance = hInstance;
    wcx.lpszClassName = L"RawrXD_GitDiffViewer";
    wcx.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcx.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExW(&wcx);
    
    // Create main window
    m_hwnd = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        L"RawrXD_GitDiffViewer",
        L"Git Diff Viewer",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1200, 800,
        hwndParent,
        nullptr,
        hInstance,
        this
    );
    
    if (!m_hwnd) return false;
    
    // Store pointer to this instance
    SetWindowLongPtr(m_hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    
    // Create child controls
    CreateToolbar();
    CreateViews();
    CreateStatusBar();
    
    // Initial layout
    LayoutControls();
    
    return true;
}

void GitDiffViewer::Destroy() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void GitDiffViewer::CreateToolbar() {
    // Create toolbar with buttons
    m_hwndToolbar = CreateWindowExW(0, TOOLBARCLASSNAMEW, nullptr,
        WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS,
        0, 0, 0, 0, m_hwnd, nullptr, m_hInstance, nullptr);
    
    // Add buttons
    TBBUTTON buttons[] = {
        { 0, ID_VIEW_SIDEBYSIDE, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Side by Side" },
        { 1, ID_VIEW_UNIFIED, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Unified" },
        { 0, 0, TBSTATE_ENABLED, BTNS_SEP, {0}, 0, 0 },
        { 2, ID_NAV_PREV, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Previous Hunk" },
        { 3, ID_NAV_NEXT, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Next Hunk" },
        { 0, 0, TBSTATE_ENABLED, BTNS_SEP, {0}, 0, 0 },
        { 4, ID_EDIT_FIND, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Find" },
        { 5, ID_EDIT_COPY, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Copy" },
        { 0, 0, TBSTATE_ENABLED, BTNS_SEP, {0}, 0, 0 },
        { 6, ID_FILE_EXPORT, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Export" },
    };
    
    SendMessage(m_hwndToolbar, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    SendMessage(m_hwndToolbar, TB_ADDBUTTONS, ARRAYSIZE(buttons), (LPARAM)buttons);
    SendMessage(m_hwndToolbar, TB_AUTOSIZE, 0, 0);
}

void GitDiffViewer::CreateViews() {
    // Load RichEdit
    LoadLibraryW(L"msftedit.dll");
    
    // Create side-by-side views
    DWORD style = WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
                  ES_MULTILINE | ES_READONLY | ES_NOHIDESEL;
    
    m_hwndOldView = CreateWindowExW(WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
        style, 0, 0, 0, 0, m_hwnd, nullptr, m_hInstance, nullptr);
    
    m_hwndNewView = CreateWindowExW(WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
        style, 0, 0, 0, 0, m_hwnd, nullptr, m_hInstance, nullptr);
    
    m_hwndUnifiedView = CreateWindowExW(WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
        style | ES_READONLY, 0, 0, 0, 0, m_hwnd, nullptr, m_hInstance, nullptr);
    
    // Set fonts
    HFONT hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    
    SendMessage(m_hwndOldView, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hwndNewView, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hwndUnifiedView, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // Initially hide unified view
    ShowWindow(m_hwndUnifiedView, SW_HIDE);
}

void GitDiffViewer::CreateStatusBar() {
    m_hwndStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, m_hwnd, nullptr, m_hInstance, nullptr);
    
    // Set parts
    int parts[] = { 200, 400, 600, -1 };
    SendMessage(m_hwndStatusBar, SB_SETPARTS, 4, (LPARAM)parts);
}

void GitDiffViewer::LayoutControls() {
    if (!m_hwnd) return;
    
    RECT rcClient;
    GetClientRect(m_hwnd, &rcClient);
    
    int x = 0;
    int y = 0;
    int width = rcClient.right;
    int height = rcClient.bottom;
    
    // Toolbar
    RECT rcToolbar;
    GetWindowRect(m_hwndToolbar, &rcToolbar);
    int toolbarHeight = rcToolbar.bottom - rcToolbar.top;
    SetWindowPos(m_hwndToolbar, nullptr, x, y, width, toolbarHeight, SWP_NOZORDER);
    y += toolbarHeight;
    height -= toolbarHeight;
    
    // Status bar
    RECT rcStatus;
    GetWindowRect(m_hwndStatusBar, &rcStatus);
    int statusHeight = rcStatus.bottom - rcStatus.top;
    height -= statusHeight;
    
    // Position status bar at bottom
    SetWindowPos(m_hwndStatusBar, nullptr, x, rcClient.bottom - statusHeight, 
                  width, statusHeight, SWP_NOZORDER);
    
    // Views
    if (m_viewMode == ViewMode::SideBySide) {
        ShowWindow(m_hwndUnifiedView, SW_HIDE);
        ShowWindow(m_hwndOldView, SW_SHOW);
        ShowWindow(m_hwndNewView, SW_SHOW);
        
        int halfWidth = width / 2;
        SetWindowPos(m_hwndOldView, nullptr, x, y, halfWidth - 2, height, SWP_NOZORDER);
        SetWindowPos(m_hwndNewView, nullptr, x + halfWidth + 2, y, 
                     halfWidth - 2, height, SWP_NOZORDER);
    } else {
        ShowWindow(m_hwndOldView, SW_HIDE);
        ShowWindow(m_hwndNewView, SW_HIDE);
        ShowWindow(m_hwndUnifiedView, SW_SHOW);
        
        SetWindowPos(m_hwndUnifiedView, nullptr, x, y, width, height, SWP_NOZORDER);
    }
}

void GitDiffViewer::SetDiff(const std::string& diffText) {
    m_currentDiff = ParseDiffText(diffText);
    m_currentHunk = 0;
    
    if (m_viewMode == ViewMode::SideBySide) {
        RenderSideBySide();
    } else {
        RenderUnified();
    }
    
    UpdateStatusBar();
}

void GitDiffViewer::SetDiff(const FileDiff& diff) {
    m_currentDiff = diff;
    m_currentHunk = 0;
    
    if (m_viewMode == ViewMode::SideBySide) {
        RenderSideBySide();
    } else {
        RenderUnified();
    }
    
    UpdateStatusBar();
}

void GitDiffViewer::Clear() {
    SetWindowTextW(m_hwndOldView, L"");
    SetWindowTextW(m_hwndNewView, L"");
    SetWindowTextW(m_hwndUnifiedView, L"");
    m_currentDiff = FileDiff();
    m_currentHunk = 0;
    UpdateStatusBar();
}

void GitDiffViewer::SetViewMode(ViewMode mode) {
    if (m_viewMode == mode) return;
    m_viewMode = mode;
    LayoutControls();
    
    // Re-render
    if (mode == ViewMode::SideBySide) {
        RenderSideBySide();
    } else {
        RenderUnified();
    }
}

void GitDiffViewer::ToggleViewMode() {
    SetViewMode(m_viewMode == ViewMode::SideBySide ? ViewMode::Unified : ViewMode::SideBySide);
}

void GitDiffViewer::RenderSideBySide() {
    if (!m_hwndOldView || !m_hwndNewView) return;
    
    SetWindowTextW(m_hwndOldView, L"");
    SetWindowTextW(m_hwndNewView, L"");
    
    // Build old and new versions
    std::wstring oldText, newText;
    int oldLineNum = 1, newLineNum = 1;
    
    for (const auto& hunk : m_currentDiff.hunks) {
        for (const auto& line : hunk.lines) {
            switch (line.type) {
                case DiffLineType::Context:
                    oldText += std::to_wstring(oldLineNum) + L" " + 
                              std::wstring(line.content.begin(), line.content.end()) + L"\r\n";
                    newText += std::to_wstring(newLineNum) + L" " + 
                               std::wstring(line.content.begin(), line.content.end()) + L"\r\n";
                    oldLineNum++;
                    newLineNum++;
                    break;
                case DiffLineType::Removed:
                    oldText += std::to_wstring(oldLineNum) + L" " + 
                              std::wstring(line.content.begin(), line.content.end()) + L"\r\n";
                    newText += L"\r\n";  // Empty line in new view
                    oldLineNum++;
                    break;
                case DiffLineType::Added:
                    oldText += L"\r\n";  // Empty line in old view
                    newText += std::to_wstring(newLineNum) + L" " + 
                               std::wstring(line.content.begin(), line.content.end()) + L"\r\n";
                    newLineNum++;
                    break;
                default:
                    break;
            }
        }
    }
    
    SetWindowTextW(m_hwndOldView, oldText.c_str());
    SetWindowTextW(m_hwndNewView, newText.c_str());
    
    // Apply colors
    ApplyRichEditColors(m_hwndOldView);
    ApplyRichEditColors(m_hwndNewView);
}

void GitDiffViewer::RenderUnified() {
    if (!m_hwndUnifiedView) return;
    
    std::wstring text;
    
    // Header
    text += L"--- " + std::wstring(m_currentDiff.oldPath.begin(), m_currentDiff.oldPath.end()) + L"\r\n";
    text += L"+++ " + std::wstring(m_currentDiff.newPath.begin(), m_currentDiff.newPath.end()) + L"\r\n";
    
    // Hunks
    for (const auto& hunk : m_currentDiff.hunks) {
        text += L"@@ -" + std::to_wstring(hunk.oldStart) + L"," + 
                std::to_wstring(hunk.oldCount) + L" +" + 
                std::to_wstring(hunk.newStart) + L"," + 
                std::to_wstring(hunk.newCount) + L" @@\r\n";
        
        for (const auto& line : hunk.lines) {
            switch (line.type) {
                case DiffLineType::Context:
                    text += L" " + std::wstring(line.content.begin(), line.content.end()) + L"\r\n";
                    break;
                case DiffLineType::Removed:
                    text += L"-" + std::wstring(line.content.begin(), line.content.end()) + L"\r\n";
                    break;
                case DiffLineType::Added:
                    text += L"+" + std::wstring(line.content.begin(), line.content.end()) + L"\r\n";
                    break;
                default:
                    break;
            }
        }
    }
    
    SetWindowTextW(m_hwndUnifiedView, text.c_str());
    ApplyRichEditColors(m_hwndUnifiedView);
}

void GitDiffViewer::ApplyRichEditColors(HWND hwnd) {
    // Get text
    LRESULT len = SendMessage(hwnd, WM_GETTEXTLENGTH, 0, 0);
    if (len == 0) return;
    
    // Apply colors based on line prefixes
    // This is simplified - full implementation would parse and color each line
    CHARFORMAT2W cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR | CFM_BACKCOLOR;
}

void GitDiffViewer::UpdateStatusBar() {
    if (!m_hwndStatusBar) return;
    
    // File info
    std::wstring fileInfo = L"File: " + 
        std::wstring(m_currentDiff.newPath.begin(), m_currentDiff.newPath.end());
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)fileInfo.c_str());
    
    // Stats
    std::wstring stats = L"+" + std::to_wstring(m_currentDiff.additions) + 
                        L" -" + std::to_wstring(m_currentDiff.deletions);
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)stats.c_str());
    
    // Hunk info
    std::wstring hunkInfo = L"Hunk " + std::to_wstring(m_currentHunk + 1) + 
                            L" of " + std::to_wstring(m_currentDiff.hunks.size());
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 2, (LPARAM)hunkInfo.c_str());
    
    // View mode
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 3, 
        (LPARAM)(m_viewMode == ViewMode::SideBySide ? L"Side by Side" : L"Unified"));
}

FileDiff GitDiffViewer::ParseDiffText(const std::string& text) {
    FileDiff diff;
    std::istringstream stream(text);
    std::string line;
    
    DiffHunk currentHunk;
    bool inHunk = false;
    
    while (std::getline(stream, line)) {
        // Remove trailing carriage return
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        if (line.substr(0, 4) == "--- ") {
            diff.oldPath = line.substr(4);
        } else if (line.substr(0, 4) == "+++ ") {
            diff.newPath = line.substr(4);
        } else if (line.substr(0, 4) == "@@ -") {
            // Save previous hunk
            if (inHunk) {
                diff.hunks.push_back(currentHunk);
            }
            
            // Parse hunk header: @@ -oldStart,oldCount +newStart,newCount @@
            currentHunk = DiffHunk();
            inHunk = true;
            
            std::regex hunkRegex("@@ -(\\d+)(?:,(\\d+))? \\u002b(\\d+)(?:,(\\d+))? @@");
            std::smatch match;
            if (std::regex_search(line, match, hunkRegex)) {
                currentHunk.oldStart = std::stoi(match[1]);
                currentHunk.oldCount = match[2].matched ? std::stoi(match[2]) : 1;
                currentHunk.newStart = std::stoi(match[3]);
                currentHunk.newCount = match[4].matched ? std::stoi(match[4]) : 1;
            }
        } else if (inHunk && !line.empty()) {
            DiffLine diffLine;
            diffLine.content = line.substr(1);
            
            switch (line[0]) {
                case ' ':
                    diffLine.type = DiffLineType::Context;
                    diffLine.oldLineNum = currentHunk.oldStart + currentHunk.lines.size();
                    diffLine.newLineNum = currentHunk.newStart + currentHunk.lines.size();
                    break;
                case '-':
                    diffLine.type = DiffLineType::Removed;
                    diffLine.oldLineNum = currentHunk.oldStart + currentHunk.lines.size();
                    diffLine.newLineNum = -1;
                    diff.additions++;
                    break;
                case '+':
                    diffLine.type = DiffLineType::Added;
                    diffLine.oldLineNum = -1;
                    diffLine.newLineNum = currentHunk.newStart + currentHunk.lines.size();
                    diff.deletions++;
                    break;
                case '\\':
                    // "\ No newline at end of file" - skip
                    continue;
                default:
                    diffLine.type = DiffLineType::Context;
                    diffLine.content = line;
                    break;
            }
            
            currentHunk.lines.push_back(diffLine);
        }
    }
    
    // Save last hunk
    if (inHunk) {
        diff.hunks.push_back(currentHunk);
    }
    
    return diff;
}

void GitDiffViewer::GoToNextHunk() {
    if (m_currentHunk + 1 < m_currentDiff.hunks.size()) {
        m_currentHunk++;
        UpdateStatusBar();
        // Scroll to hunk
    }
}

void GitDiffViewer::GoToPreviousHunk() {
    if (m_currentHunk > 0) {
        m_currentHunk--;
        UpdateStatusBar();
        // Scroll to hunk
    }
}

void GitDiffViewer::Show() {
    if (m_hwnd) {
        ShowWindow(m_hwnd, SW_SHOW);
        SetForegroundWindow(m_hwnd);
    }
}

void GitDiffViewer::Hide() {
    if (m_hwnd) {
        ShowWindow(m_hwnd, SW_HIDE);
    }
}

void GitDiffViewer::SetTitle(const std::string& title) {
    if (m_hwnd) {
        std::wstring wtitle(title.begin(), title.end());
        SetWindowText(m_hwnd, wtitle.c_str());
    }
}

void GitDiffViewer::CenterOnParent() {
    if (!m_hwnd || !m_hwndParent) return;
    
    RECT rcParent, rcWindow;
    GetWindowRect(m_hwndParent, &rcParent);
    GetWindowRect(m_hwnd, &rcWindow);
    
    int width = rcWindow.right - rcWindow.left;
    int height = rcWindow.bottom - rcWindow.top;
    int parentWidth = rcParent.right - rcParent.left;
    int parentHeight = rcParent.bottom - rcParent.top;
    
    int x = rcParent.left + (parentWidth - width) / 2;
    int y = rcParent.top + (parentHeight - height) / 2;
    
    SetWindowPos(m_hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

// Static dialog procedure
INT_PTR CALLBACK GitDiffViewer::DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GitDiffViewer* viewer = reinterpret_cast<GitDiffViewer*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    
    if (viewer) {
        return viewer->HandleMessage(msg, wParam, lParam);
    }
    
    return FALSE;
}

INT_PTR GitDiffViewer::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SIZE:
            LayoutControls();
            return TRUE;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_VIEW_SIDEBYSIDE:
                    SetViewMode(ViewMode::SideBySide);
                    return TRUE;
                case ID_VIEW_UNIFIED:
                    SetViewMode(ViewMode::Unified);
                    return TRUE;
                case ID_NAV_NEXT:
                    GoToNextHunk();
                    return TRUE;
                case ID_NAV_PREV:
                    GoToPreviousHunk();
                    return TRUE;
                case IDOK:
                case IDCANCEL:
                    Destroy();
                    return TRUE;
            }
            break;
            
        case WM_CLOSE:
            Destroy();
            return TRUE;
    }
    
    return FALSE;
}

// ============================================================================
// GitDiffDialog Implementation
// ============================================================================

bool GitDiffDialog::Show(HWND hwndParent, const std::string& diffText, 
                         const std::string& title) {
    GitDiffViewer viewer;
    
    if (!viewer.Create(hwndParent, GetModuleHandle(nullptr))) {
        return false;
    }
    
    viewer.SetTitle(title);
    viewer.SetDiff(diffText);
    viewer.CenterOnParent();
    viewer.Show();
    
    // Modal loop
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessage(viewer.IsCreated() ? viewer.GetHwnd() : nullptr, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        
        if (!viewer.IsCreated()) {
            break;
        }
    }
    
    return true;
}

bool GitDiffDialog::ShowForFile(HWND hwndParent, const std::string& filePath,
                                const std::string& revision) {
    // Execute git diff command
    std::string cmd = "git diff ";
    if (!revision.empty()) {
        cmd += revision + " ";
    }
    cmd += "\"" + filePath + "\"";
    
    // Execute and capture output
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) {
        return false;
    }
    
    std::string diffText;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        diffText += buffer;
    }
    _pclose(pipe);
    
    if (diffText.empty()) {
        // No changes
        MessageBoxA(hwndParent, "No changes to display.", "Git Diff", MB_OK | MB_ICONINFORMATION);
        return true;
    }
    
    return Show(hwndParent, diffText, "Git Diff - " + filePath);
}

} // namespace RawrXD::IDE
