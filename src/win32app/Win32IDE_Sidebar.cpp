// Win32IDE_Sidebar.cpp - Primary Sidebar Implementation
// Implements VS Code-style Activity Bar and Sidebar with 5 views:
// Explorer, Search, Source Control, Run & Debug, Extensions

#include "Win32IDE.h"
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <algorithm>
#include <cctype>
#include <regex>     
#include <filesystem>
#include <fstream>   
#include <sstream>   
#include "QtLogCompat.h"

// Define GET_X_LPARAM and GET_Y_LPARAM if not available
#ifndef GET_X_LPARAM
#define GET_X_LPARAM(lp) ((int)(short)LOWORD(lp))
#endif
#ifndef GET_Y_LPARAM
#define GET_Y_LPARAM(lp) ((int)(short)HIWORD(lp))
#endif

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Modal single-line text prompt (real Win32, no Qt, no fabricated INPUTBOXPARAMS
// API - see the repair note in newFolderInExplorer()).
//
// The previous code called ShowInputBox(m_hwnd, &params, buf) with an
// INPUTBOXPARAMS struct; neither the type nor the function exists anywhere in
// this tree or in the Win32 SDK, so the call could never have compiled. This is
// a genuine replacement: a WS_POPUP owner-drawn dialog driven by a nested
// message loop, with the owner disabled so it behaves modally.
// ---------------------------------------------------------------------------
namespace {

bool isWorkspaceCandidate(const std::string& path)
{
    if (path.empty()) return false;

    std::string normalized = path;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (normalized.find("\\windowsapps\\") != std::string::npos ||
        normalized.find("/windowsapps/") != std::string::npos) {
        return false;
    }

    const DWORD attributes = GetFileAttributesA(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return false;
    }

    const std::string gitMarker = path + "\\.git";
    const std::string cmakeMarker = path + "\\CMakeLists.txt";
    const std::string sourceMarker = path + "\\src";
    const bool hasGit = GetFileAttributesA(gitMarker.c_str()) != INVALID_FILE_ATTRIBUTES;
    const bool hasBuildLayout =
        GetFileAttributesA(cmakeMarker.c_str()) != INVALID_FILE_ATTRIBUTES &&
        GetFileAttributesA(sourceMarker.c_str()) != INVALID_FILE_ATTRIBUTES;
    return hasGit || hasBuildLayout;
}

std::string resolveWorkspaceRoot()
{
    // Installations and launchers can provide an explicit checkout without
    // forcing a developer-specific absolute path into the binary.
    constexpr const char* kWorkspaceOverrides[] = {
        "RAWRXD_WORKSPACE",
        "RAWRXD_WORKSPACE_ROOT",
        "RAWRXD_PROJECT_ROOT"
    };
    for (const char* variable : kWorkspaceOverrides) {
        char value[MAX_PATH] = {};
        const DWORD length = GetEnvironmentVariableA(variable, value, MAX_PATH);
        if (length > 0 && length < MAX_PATH && isWorkspaceCandidate(value)) {
            return value;
        }
    }

    // Resolve from the executable first.  This keeps a launch from a shell,
    // desktop shortcut, or the Codex host independent of its inherited CWD.
    char executablePath[32768] = {};
    const DWORD executableLength = GetModuleFileNameA(
        nullptr, executablePath, static_cast<DWORD>(sizeof(executablePath)));
    if (executableLength > 0 && executableLength < sizeof(executablePath)) {
        std::string candidate(executablePath, executableLength);
        size_t slash = candidate.find_last_of("\\/");
        if (slash != std::string::npos) candidate.resize(slash);

        for (int depth = 0; depth < 16 && !candidate.empty(); ++depth) {
            if (isWorkspaceCandidate(candidate)) return candidate;
            const size_t parentSlash = candidate.find_last_of("\\/");
            if (parentSlash == std::string::npos || parentSlash <= 2) break;
            candidate.resize(parentSlash);
        }
    }

    // A valid project CWD is still supported, but arbitrary launch locations
    // (especially WindowsApps) must never become the active workspace.
    char currentDirectory[MAX_PATH] = {};
    const DWORD currentLength = GetCurrentDirectoryA(MAX_PATH, currentDirectory);
    if (currentLength > 0 && currentLength < MAX_PATH &&
        isWorkspaceCandidate(currentDirectory)) {
        return currentDirectory;
    }
    return {};
}

constexpr wchar_t PROMPT_CLASS_NAME[] = L"RawrXDPromptClass";

struct PromptState {
    HWND owner = nullptr;
    HWND self = nullptr;
    HWND edit = nullptr;
    HWND okButton = nullptr;
    HWND cancelButton = nullptr;
    HWND promptLabel = nullptr;
    std::string title;
    std::string prompt;
    std::string initial;
    bool confirmed = false;
};

BOOL PromptRegisterClass(HINSTANCE hInst)
{
    static bool registered = false;
    if (registered) return TRUE;

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        PromptState* st = reinterpret_cast<PromptState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

        switch (msg) {
        case WM_CREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
            st = static_cast<PromptState*>(cs->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(st));
            if (!st) return -1;
            st->self = hwnd;

            HINSTANCE hInstance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(hwnd, GWLP_HINSTANCE));

            const int padding = 12;
            const int labelHeight = 18;
            const int editHeight = 24;
            const int buttonHeight = 24;
            const int buttonWidth = 80;
            const int clientWidth = 380;
            const int clientHeight = padding + labelHeight + 6 + editHeight + 12 + buttonHeight + padding;

            RECT desired = { 0, 0, clientWidth, clientHeight };
            AdjustWindowRectEx(&desired, WS_POPUP | WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_DLGMODALFRAME);
            const int windowWidth = desired.right - desired.left;
            const int windowHeight = desired.bottom - desired.top;

            RECT ownerRect = { 0, 0, 0, 0 };
            if (st->owner && IsWindow(st->owner)) GetWindowRect(st->owner, &ownerRect);
            const int originX = ownerRect.left + ((ownerRect.right - ownerRect.left) - windowWidth) / 2;
            const int originY = ownerRect.top + ((ownerRect.bottom - ownerRect.top) - windowHeight) / 2;
            SetWindowPos(hwnd, st->owner, originX, originY, windowWidth, windowHeight, SWP_NOZORDER);

            SetWindowTextW(hwnd, std::wstring(st->title.begin(), st->title.end()).c_str());

            st->promptLabel = CreateWindowExW(0, L"STATIC",
                std::wstring(st->prompt.begin(), st->prompt.end()).c_str(),
                WS_CHILD | WS_VISIBLE, padding, padding,
                clientWidth - 2 * padding, labelHeight, hwnd, nullptr, hInstance, nullptr);

            st->edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
                std::wstring(st->initial.begin(), st->initial.end()).c_str(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                padding, padding + labelHeight + 6,
                clientWidth - 2 * padding, editHeight, hwnd, nullptr, hInstance, nullptr);

            const int buttonY = padding + labelHeight + 6 + editHeight + 12;
            st->okButton = CreateWindowExW(0, L"BUTTON", L"OK",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                clientWidth - 2 * buttonWidth - 12 - padding, buttonY,
                buttonWidth, buttonHeight, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDOK)),
                hInstance, nullptr);

            st->cancelButton = CreateWindowExW(0, L"BUTTON", L"Cancel",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                clientWidth - buttonWidth - padding, buttonY,
                buttonWidth, buttonHeight, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDCANCEL)),
                hInstance, nullptr);

            SendMessageW(st->edit, EM_SETSEL, 0, -1);
            SetFocus(st->edit);
            return 0;
        }

        case WM_COMMAND:
            if (!st) break;
            if (LOWORD(wParam) == IDOK) {
                wchar_t buffer[512] = {};
                GetWindowTextW(st->edit, buffer, static_cast<int>(std::size(buffer)));
                // Narrow back to the ANSI/multibyte charset this IDE uses.
                const int needed = WideCharToMultiByte(CP_ACP, 0, buffer, -1, nullptr, 0, nullptr, nullptr);
                if (needed > 0) {
                    std::string text(static_cast<size_t>(needed - 1), '\0');
                    WideCharToMultiByte(CP_ACP, 0, buffer, -1, text.data(), needed, nullptr, nullptr);
                    st->initial = text;
                } else {
                    st->initial.clear();
                }
                st->confirmed = true;
                DestroyWindow(hwnd);
                return 0;
            }
            if (LOWORD(wParam) == IDCANCEL) {
                st->confirmed = false;
                DestroyWindow(hwnd);
                return 0;
            }
            break;

        case WM_CLOSE:
            if (st) st->confirmed = false;
            DestroyWindow(hwnd);
            return 0;

        default:
            break;
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    };
    wc.hInstance = hInst;
    wc.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32512)); // IDI_APPLICATION
    wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512)); // IDC_ARROW
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = PROMPT_CLASS_NAME;

    registered = (RegisterClassExW(&wc) != 0) || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered ? TRUE : FALSE;
}

// Returns true (and fills `out`) when the user confirms, false on cancel.
bool PromptText(HWND owner, const std::string& title, const std::string& prompt,
                const std::string& initial, std::string& out)
{
    HINSTANCE hInstance = GetModuleHandleW(nullptr);
    if (!PromptRegisterClass(hInstance)) return false;

    PromptState state;
    state.owner = owner;
    state.title = title;
    state.prompt = prompt;
    state.initial = initial;

    HWND dialog = CreateWindowExW(WS_EX_DLGMODALFRAME, PROMPT_CLASS_NAME, L"",
                                  WS_POPUP | WS_CAPTION | WS_SYSMENU,
                                  CW_USEDEFAULT, CW_USEDEFAULT, 0, 0,
                                  owner, nullptr, hInstance, &state);
    if (!dialog) return false;

    ShowWindow(dialog, SW_SHOW);
    UpdateWindow(dialog);

    // Modal behaviour: disable the owner and pump a nested message loop.
    HWND previousOwner = owner;
    if (previousOwner) EnableWindow(previousOwner, FALSE);

    MSG msg;
    BOOL running = TRUE;
    while (running && IsWindow(dialog)) {
        if (GetMessageW(&msg, nullptr, 0, 0) <= 0) {
            running = FALSE;
            break;
        }
        if (!IsDialogMessageW(dialog, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if (previousOwner) {
        EnableWindow(previousOwner, TRUE);
        SetActiveWindow(previousOwner);
    }

    if (state.confirmed) {
        out = state.initial;
        return true;
    }
    return false;
}

} // namespace

// Activity Bar constants
constexpr int ACTIVITY_BAR_WIDTH = 48;
constexpr int SIDEBAR_DEFAULT_WIDTH = 250;
constexpr int ACTIVITY_ICON_SIZE = 32;
constexpr int ACTIVITY_BUTTON_HEIGHT = 48;

// Control IDs
constexpr int IDC_ACTIVITY_EXPLORER = 6001;
constexpr int IDC_ACTIVITY_SEARCH = 6002;
constexpr int IDC_ACTIVITY_SCM = 6003;
constexpr int IDC_ACTIVITY_DEBUG = 6004;
constexpr int IDC_ACTIVITY_EXTENSIONS = 6005;

constexpr int IDC_EXPLORER_TREE = 6010;
constexpr int IDC_EXPLORER_NEW_FILE = 6011;
constexpr int IDC_EXPLORER_NEW_FOLDER = 6012;
constexpr int IDC_EXPLORER_REFRESH = 6013;
constexpr int IDC_EXPLORER_COLLAPSE = 6014;

constexpr int IDC_SEARCH_INPUT = 6020;
constexpr int IDC_SEARCH_BUTTON = 6021;
constexpr int IDC_SEARCH_RESULTS = 6022;
constexpr int IDC_SEARCH_REGEX = 6023;
constexpr int IDC_SEARCH_CASE = 6024;
constexpr int IDC_SEARCH_WHOLE_WORD = 6025;
constexpr int IDC_SEARCH_INCLUDE = 6026;
constexpr int IDC_SEARCH_EXCLUDE = 6027;

constexpr int IDC_SCM_FILE_LIST = 6030;
constexpr int IDC_SCM_STAGE = 6031;
constexpr int IDC_SCM_UNSTAGE = 6032;
constexpr int IDC_SCM_COMMIT = 6033;
constexpr int IDC_SCM_SYNC = 6034;
constexpr int IDC_SCM_MESSAGE = 6035;

constexpr int IDC_DEBUG_CONFIGS = 6040;
constexpr int IDC_DEBUG_START = 6041;
constexpr int IDC_DEBUG_STOP = 6042;
constexpr int IDC_DEBUG_VARIABLES = 6043;
constexpr int IDC_DEBUG_CALLSTACK = 6044;
constexpr int IDC_DEBUG_CONSOLE = 6045;

constexpr int IDC_EXT_SEARCH = 6050;
constexpr int IDC_EXT_LIST = 6051;
constexpr int IDC_EXT_DETAILS = 6052;
constexpr int IDC_EXT_INSTALL = 6053;
constexpr int IDC_EXT_UNINSTALL = 6054;

// ============================================================================
// Activity Bar Implementation
// ============================================================================

void Win32IDE::createActivityBar(HWND hwndParent)
{
    m_hwndActivityBar = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        0, 0, ACTIVITY_BAR_WIDTH, 600,
        hwndParent, nullptr, m_hInstance, nullptr
    );

    SetWindowLongPtrA(m_hwndActivityBar, GWLP_USERDATA, (LONG_PTR)this);
    SetWindowLongPtrA(m_hwndActivityBar, GWLP_WNDPROC, (LONG_PTR)ActivityBarProc);

    // Create activity buttons (icon buttons for each view)
    int y = 10;
    const struct { int id; const char* text; } buttons[] = {
        {IDC_ACTIVITY_EXPLORER, "Files"},
        {IDC_ACTIVITY_SEARCH, "Search"},
        {IDC_ACTIVITY_SCM, "Source"},
        {IDC_ACTIVITY_DEBUG, "Debug"},
        {IDC_ACTIVITY_EXTENSIONS, "Exts"}
    };

    for (const auto& btn : buttons) {
        HWND hwndBtn = CreateWindowExA(
            0, "BUTTON", btn.text,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
            4, y, 40, 40,
            m_hwndActivityBar, (HMENU)(INT_PTR)btn.id, m_hInstance, nullptr
        );
        y += 48;
    }

    appendToOutput("Activity Bar created with 5 views\n", "Output", OutputSeverity::Info);
}

LRESULT CALLBACK Win32IDE::ActivityBarProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = (Win32IDE*)GetWindowLongPtrA(hwnd, GWLP_USERDATA);

    switch (uMsg) {
    case WM_COMMAND:
        if (pThis) {
            int id = LOWORD(wParam);
            switch (id) {
            case IDC_ACTIVITY_EXPLORER: pThis->setSidebarView(SidebarView::Explorer); break;
            case IDC_ACTIVITY_SEARCH: pThis->setSidebarView(SidebarView::Search); break;
            case IDC_ACTIVITY_SCM: pThis->setSidebarView(SidebarView::SourceControl); break;
            case IDC_ACTIVITY_DEBUG: pThis->setSidebarView(SidebarView::RunDebug); break;
            case IDC_ACTIVITY_EXTENSIONS: pThis->setSidebarView(SidebarView::Extensions); break;
            }
        }
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        
        // Dark background for activity bar
        HBRUSH hBrush = CreateSolidBrush(RGB(51, 51, 51));
        FillRect(hdc, &rc, hBrush);
        DeleteObject(hBrush);
        
        EndPaint(hwnd, &ps);
        return 0;
    }
    }

    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

// ============================================================================
// Primary Sidebar Container
// ============================================================================

void Win32IDE::createPrimarySidebar(HWND hwndParent)
{
    m_hwndSidebar = CreateWindowExA(
        0, "STATIC", "Sidebar",
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        ACTIVITY_BAR_WIDTH, 0, SIDEBAR_DEFAULT_WIDTH, 600,
        hwndParent, nullptr, m_hInstance, nullptr
    );

    m_hwndSidebarContent = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | WS_VISIBLE,
        0, 0, SIDEBAR_DEFAULT_WIDTH, 600,
        m_hwndSidebar, nullptr, m_hInstance, nullptr
    );

    SetWindowLongPtrA(m_hwndSidebar, GWLP_USERDATA, (LONG_PTR)this);
    SetWindowLongPtrA(m_hwndSidebar, GWLP_WNDPROC, (LONG_PTR)SidebarProc);

    m_sidebarVisible = true;
    m_sidebarWidth = SIDEBAR_DEFAULT_WIDTH;
    m_currentSidebarView = SidebarView::None;

    // Create all views (hidden initially)
    createExplorerView(m_hwndSidebarContent);
    createSearchView(m_hwndSidebarContent);
    createSourceControlView(m_hwndSidebarContent);
    createRunDebugView(m_hwndSidebarContent);
    createExtensionsView(m_hwndSidebarContent);

    // Default to Explorer view
    setSidebarView(SidebarView::Explorer);

    appendToOutput("Primary Sidebar initialized\n", "Output", OutputSeverity::Info);
}

LRESULT CALLBACK Win32IDE::SidebarProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = (Win32IDE*)GetWindowLongPtrA(hwnd, GWLP_USERDATA);

    switch (uMsg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        
        // Light gray background
        HBRUSH hBrush = CreateSolidBrush(RGB(37, 37, 38));
        FillRect(hdc, &rc, hBrush);
        DeleteObject(hBrush);
        
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_SIZE: {
        if (pThis) {
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);
            pThis->resizeSidebar(width, height);
        }
        return 0;
    }
    }

    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

void Win32IDE::toggleSidebar()
{
    m_sidebarVisible = !m_sidebarVisible;
    ShowWindow(m_hwndSidebar, m_sidebarVisible ? SW_SHOW : SW_HIDE);
    
    // Trigger layout recalculation
    RECT rc;
    GetClientRect(m_hwndMain, &rc);
    onSize(rc.right, rc.bottom);
    
    appendToOutput(m_sidebarVisible ? "Sidebar shown (Ctrl+B)\n" : "Sidebar hidden (Ctrl+B)\n", 
                   "Output", OutputSeverity::Info);
}

void Win32IDE::setSidebarView(SidebarView view)
{
    if (m_currentSidebarView == view) return;

    // Every view also owns static labels and nested controls whose HWNDs are
    // intentionally not all retained as members.  Hiding only the headline
    // controls left those children visible, so switching the activity bar
    // painted Search/Debug words over the Explorer tree.  Enumerate the
    // complete content subtree before showing the selected view; this makes
    // the activity-bar transition atomic and prevents stale pixels/controls
    // from leaking between views.
    if (m_hwndSidebarContent) {
        EnumChildWindows(m_hwndSidebarContent,
            [](HWND child, LPARAM) -> BOOL {
                ShowWindow(child, SW_HIDE);
                return TRUE;
            }, 0);
        ShowWindow(m_hwndSidebarContent, SW_SHOW);
    }

    m_currentSidebarView = view;

    // Show selected view
    switch (view) {
    case SidebarView::Explorer:
        ShowWindow(m_hwndExplorerTree, SW_SHOW);
        ShowWindow(m_hwndExplorerToolbar, SW_SHOW);
        refreshFileTree();
        appendToOutput("Explorer view activated\n", "Output", OutputSeverity::Info);
        break;

    case SidebarView::Search:
        ShowWindow(m_hwndSearchInput, SW_SHOW);
        ShowWindow(m_hwndSearchResults, SW_SHOW);
        ShowWindow(m_hwndSearchOptions, SW_SHOW);
        SetFocus(m_hwndSearchInput);
        appendToOutput("Search view activated\n", "Output", OutputSeverity::Info);
        break;

    case SidebarView::SourceControl:
        ShowWindow(m_hwndSCMFileList, SW_SHOW);
        ShowWindow(m_hwndSCMToolbar, SW_SHOW);
        ShowWindow(m_hwndSCMMessageBox, SW_SHOW);
        refreshSourceControlView();
        appendToOutput("Source Control view activated\n", "Output", OutputSeverity::Info);
        break;

    case SidebarView::RunDebug:
        ShowWindow(m_hwndDebugConfigs, SW_SHOW);
        ShowWindow(m_hwndDebugToolbar, SW_SHOW);
        ShowWindow(m_hwndDebugVariables, SW_SHOW);
        appendToOutput("Run and Debug view activated\n", "Output", OutputSeverity::Info);
        break;

    case SidebarView::Extensions:
        ShowWindow(m_hwndExtensionsList, SW_SHOW);
        ShowWindow(m_hwndExtensionSearch, SW_SHOW);
        loadInstalledExtensions();
        appendToOutput("Extensions view activated\n", "Output", OutputSeverity::Info);
        break;

    default:
        break;
    }

    updateSidebarContent();
}

void Win32IDE::updateSidebarContent()
{
    // Refresh current view's content
    switch (m_currentSidebarView) {
    case SidebarView::Explorer:
        refreshFileTree();
        break;
    case SidebarView::Search:
        // Search results are updated on demand
        break;
    case SidebarView::SourceControl:
        refreshSourceControlView();
        break;
    case SidebarView::RunDebug:
        updateDebugVariables();
        break;
    case SidebarView::Extensions:
        loadInstalledExtensions();
        break;
    default:
        break;
    }
}

void Win32IDE::resizeSidebar(int width, int height)
{
    if (!m_hwndSidebarContent) return;

    MoveWindow(m_hwndSidebarContent, 0, 0, width, height, TRUE);

    // Resize active view controls
    if (m_hwndExplorerTree && m_currentSidebarView == SidebarView::Explorer) {
        MoveWindow(m_hwndExplorerToolbar, 0, 0, width, 30, TRUE);
        MoveWindow(m_hwndExplorerTree, 0, 30, width, height - 30, TRUE);
    }
    else if (m_hwndSearchInput && m_currentSidebarView == SidebarView::Search) {
        MoveWindow(m_hwndSearchInput, 5, 10, width - 10, 25, TRUE);
        MoveWindow(m_hwndSearchOptions, 5, 40, width - 10, 80, TRUE);
        MoveWindow(m_hwndSearchResults, 5, 125, width - 10, height - 130, TRUE);
    }
    else if (m_hwndSCMFileList && m_currentSidebarView == SidebarView::SourceControl) {
        MoveWindow(m_hwndSCMToolbar, 0, 0, width, 35, TRUE);
        MoveWindow(m_hwndSCMMessageBox, 5, 40, width - 10, 60, TRUE);
        MoveWindow(m_hwndSCMFileList, 5, 105, width - 10, height - 110, TRUE);
    }
    else if (m_hwndDebugConfigs && m_currentSidebarView == SidebarView::RunDebug) {
        MoveWindow(m_hwndDebugToolbar, 0, 0, width, 35, TRUE);
        MoveWindow(m_hwndDebugConfigs, 5, 40, width - 10, 100, TRUE);
        MoveWindow(m_hwndDebugVariables, 5, 145, width - 10, height - 150, TRUE);
    }
    else if (m_hwndExtensionsList && m_currentSidebarView == SidebarView::Extensions) {
        MoveWindow(m_hwndExtensionSearch, 5, 10, width - 10, 25, TRUE);
        MoveWindow(m_hwndExtensionsList, 5, 40, width - 10, height - 45, TRUE);
    }
}

// ============================================================================
// Explorer View Implementation
// ============================================================================

void Win32IDE::createExplorerView(HWND hwndParent)
{
    appendToOutput("createExplorerView() called\n", "Output", OutputSeverity::Info);
    
    // Toolbar with actions
    m_hwndExplorerToolbar = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | SS_OWNERDRAW,
        0, 0, SIDEBAR_DEFAULT_WIDTH, 30,
        hwndParent, nullptr, m_hInstance, nullptr
    );
    if (!m_hwndExplorerToolbar) {
        appendToOutput("Failed to create explorer toolbar\n", "Output", OutputSeverity::Error);
        return;
    }

    // Toolbar buttons
    const struct { int id; const char* text; int x; } buttons[] = {
        {IDC_EXPLORER_NEW_FILE, "New", 5},
        {IDC_EXPLORER_NEW_FOLDER, "Folder", 50},
        {IDC_EXPLORER_REFRESH, "Refresh", 105},
        {IDC_EXPLORER_COLLAPSE, "Collapse", 165}
    };

    for (const auto& btn : buttons) {
        CreateWindowExA(
            0, "BUTTON", btn.text,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            btn.x, 3, 45, 24,
            m_hwndExplorerToolbar, (HMENU)(INT_PTR)btn.id, m_hInstance, nullptr
        );
    }

    // TreeView for file/folder structure
    appendToOutput("Creating Explorer TreeView control\n", "Output", OutputSeverity::Debug);
    m_hwndExplorerTree = CreateWindowExA(
        WS_EX_CLIENTEDGE, WC_TREEVIEWA, "",
        WS_CHILD | TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
        0, 30, SIDEBAR_DEFAULT_WIDTH, 570,
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_EXPLORER_TREE)), m_hInstance, nullptr
    );
    if (!m_hwndExplorerTree) {
        appendToOutput("Failed to create Explorer TreeView\n", "Output", OutputSeverity::Error);
        return;
    }

    SetWindowLongPtrA(m_hwndExplorerTree, GWLP_USERDATA, (LONG_PTR)this);
    // Preserve the native TreeView procedure.  Replacing it without chaining
    // back to the original control procedure breaks selection, hit testing,
    // and arrow expansion even though the window still paints.
    m_explorerTreeOriginalProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrA(
        m_hwndExplorerTree, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(ExplorerTreeProc)));

    // Resolve the workspace independently of the inherited CWD.  A desktop
    // or host-app launch commonly inherits a WindowsApps directory, which is
    // not a project and must never become the agent/model workspace.  Keep
    // both explorer state fields synchronized because model discovery and the
    // legacy file actions still consume m_currentExplorerPath.
    m_explorerRootPath = resolveWorkspaceRoot();
    m_currentExplorerPath = m_explorerRootPath;

    appendToOutput("Explorer view created; workspace root: " +
                   (m_explorerRootPath.empty() ? std::string("(unavailable)") : m_explorerRootPath) + "\n",
                   "Output", OutputSeverity::Info);
}

void Win32IDE::refreshFileTree()
{
    appendToOutput("refreshFileTree() called\n", "Output", OutputSeverity::Debug);
    if (!m_hwndExplorerTree) {
        appendToOutput("Cannot refresh file tree - m_hwndExplorerTree is null\n", "Output", OutputSeverity::Warning);
        return;
    }

    TreeView_DeleteAllItems(m_hwndExplorerTree);
    m_treeItemPaths.clear();

    struct ExplorerRoot { std::string label; std::string path; };
    std::vector<ExplorerRoot> roots;
    auto addRoot = [&roots](const std::string& label, const std::string& path) {
        if (path.empty() || GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) return;
        for (const auto& existing : roots) {
            if (_stricmp(existing.path.c_str(), path.c_str()) == 0) return;
        }
        roots.push_back({label, path});
    };

    if (!m_explorerRootPath.empty()) {
        addRoot("Workspace (" + m_explorerRootPath + ")", m_explorerRootPath);
    }

    // Enumerate all mounted logical drives.  This intentionally does not
    // filter by DRIVE_FIXED: removable, network, optical and RAM drives are
    // valid explorer roots too, including roots hidden from normal project
    // discovery.
    const DWORD driveChars = GetLogicalDriveStringsA(0, nullptr);
    if (driveChars > 0) {
        std::vector<char> driveBuffer(static_cast<size_t>(driveChars) + 1, '\0');
        if (GetLogicalDriveStringsA(driveChars, driveBuffer.data()) != 0) {
            for (const char* drive = driveBuffer.data(); *drive; drive += std::strlen(drive) + 1) {
                const std::string path(drive);
                const DWORD type = GetDriveTypeA(path.c_str());
                const char* typeName = "Drive";
                switch (type) {
                    case DRIVE_REMOVABLE: typeName = "Removable"; break;
                    case DRIVE_FIXED: typeName = "Fixed"; break;
                    case DRIVE_REMOTE: typeName = "Network"; break;
                    case DRIVE_CDROM: typeName = "Optical"; break;
                    case DRIVE_RAMDISK: typeName = "RAM"; break;
                    default: break;
                }
                addRoot(path + " [" + typeName + "]", path);
            }
        }
    }

    for (const auto& root : roots) {
        TVINSERTSTRUCTA tvis = {};
        tvis.hParent = TVI_ROOT;
        tvis.hInsertAfter = TVI_LAST;
        tvis.item.mask = TVIF_TEXT | TVIF_PARAM;
        tvis.item.pszText = const_cast<char*>(root.label.c_str());
        tvis.item.lParam = 1; // directory/root
        const HTREEITEM hRoot = TreeView_InsertItem(m_hwndExplorerTree, &tvis);
        if (!hRoot) continue;
        m_treeItemPaths[hRoot] = root.path;

        // Lazy expansion keeps the UI responsive on large model volumes.
        TVINSERTSTRUCTA placeholder = {};
        placeholder.hParent = hRoot;
        placeholder.hInsertAfter = TVI_LAST;
        placeholder.item.mask = TVIF_TEXT | TVIF_PARAM;
        placeholder.item.pszText = const_cast<char*>("Loading...");
        placeholder.item.lParam = 0;
        TreeView_InsertItem(m_hwndExplorerTree, &placeholder);
    }

    appendToOutput("File tree refreshed with " + std::to_string(roots.size()) +
                   " mounted drive/workspace roots\n", "Output", OutputSeverity::Info);
}

void Win32IDE::expandFolder(const std::string& path)
{
    if (!m_hwndExplorerTree || path.empty()) return;

    HTREEITEM parent = TreeView_GetSelection(m_hwndExplorerTree);
    if (!parent) return;

    // Remove the lazy placeholder once, preserving any already-populated
    // children when the user toggles the same folder repeatedly.
    HTREEITEM child = TreeView_GetChild(m_hwndExplorerTree, parent);
    if (child) {
        char text[MAX_PATH] = {};
        TVITEMA item{};
        item.hItem = child;
        item.mask = TVIF_TEXT;
        item.pszText = text;
        item.cchTextMax = MAX_PATH;
        if (TreeView_GetItem(m_hwndExplorerTree, &item) && std::strcmp(text, "Loading...") == 0) {
            TreeView_DeleteItem(m_hwndExplorerTree, child);
        } else {
            return;
        }
    }

    try {
        for (const auto& entry : fs::directory_iterator(
                 path, fs::directory_options::skip_permission_denied)) {
            try {
                const std::string name = entry.path().filename().string();
                TVINSERTSTRUCTA tvis{};
                tvis.hParent = parent;
                tvis.hInsertAfter = TVI_LAST;
                tvis.item.mask = TVIF_TEXT | TVIF_PARAM;
                tvis.item.pszText = const_cast<char*>(name.c_str());
                tvis.item.lParam = entry.is_directory() ? 1 : 0;
                const HTREEITEM item = TreeView_InsertItem(m_hwndExplorerTree, &tvis);
                if (!item) continue;
                m_treeItemPaths[item] = entry.path().string();
                if (entry.is_directory()) {
                    TVINSERTSTRUCTA placeholder{};
                    placeholder.hParent = item;
                    placeholder.hInsertAfter = TVI_LAST;
                    placeholder.item.mask = TVIF_TEXT | TVIF_PARAM;
                    placeholder.item.pszText = const_cast<char*>("Loading...");
                    placeholder.item.lParam = 0;
                    TreeView_InsertItem(m_hwndExplorerTree, &placeholder);
                }
            } catch (...) {
                // A single inaccessible or malformed entry must not abort the
                // remainder of a drive listing.
            }
        }
    } catch (const std::exception& e) {
        appendToOutput("Explorer access denied or unavailable: " + std::string(e.what()) + "\n",
                       "Output", OutputSeverity::Warning);
    }

    appendToOutput("Expanded folder: " + path + "\n", "Output", OutputSeverity::Info);
}

void Win32IDE::collapseAllFolders()
{
    if (!m_hwndExplorerTree) return;
    
    HTREEITEM hRoot = TreeView_GetRoot(m_hwndExplorerTree);
    TreeView_Expand(m_hwndExplorerTree, hRoot, TVE_COLLAPSE | TVE_COLLAPSERESET);
    
    appendToOutput("All folders collapsed\n", "Output", OutputSeverity::Info);
}

void Win32IDE::newFileInExplorer()
{
    qInfo() << "[Win32IDE] DEBUG: Starting new file creation from Explorer";
    
    try {
        // newFile() is void - it reports its own progress through
        // appendToOutput and its own Save-changes prompt, and its outcome is
        // "no exception thrown" (same semantics as the File > New menu path).
        newFile();

        qInfo() << "[Win32IDE] INFO: New file created successfully from Explorer";
        
        // Log metrics
        qDebug() << "[Win32IDE] METRIC: new_file_created=1";
        qDebug() << "[Win32IDE] METRIC: source=explorer";
    } catch (const std::exception& e) {
        qCritical() << "[Win32IDE] CRITICAL: Exception during new file creation:" << e.what();
        
        MessageBoxA(m_hwndMain, 
                   "An unexpected error occurred while creating the file.", 
                   "System Error", 
                   MB_ICONERROR | MB_OK);
    }
}

void Win32IDE::newFolderInExplorer()
{
    qInfo() << "[Win32IDE] DEBUG: Starting new folder creation from Explorer";

    std::string folderName;
    if (!PromptText(m_hwndMain, "Create New Folder", "Enter folder name:",
                    "NewFolder", folderName)) {
        qInfo() << "[Win32IDE] INFO: Folder creation cancelled by user";
        return;
    }

    try {
        std::string fullPath = m_explorerRootPath + "\\" + folderName;

        // Validate folder name
        if (folderName.empty()) {
            qWarning() << "[Win32IDE] ERROR: Empty folder name provided";
            MessageBoxA(m_hwndMain, "Folder name cannot be empty.", "Invalid Input", MB_ICONWARNING);
            return;
        }

        // Check if folder already exists
        if (fs::exists(fullPath)) {
            qWarning() << "[Win32IDE] ERROR: Folder already exists:" << fullPath.c_str();
            MessageBoxA(m_hwndMain, "A folder with this name already exists.", "Folder Exists", MB_ICONWARNING);
            return;
        }

        // Create the folder
        if (fs::create_directory(fullPath)) {
            qInfo() << "[Win32IDE] INFO: New folder created:" << fullPath.c_str();

            // Refresh file tree to show new folder
            refreshFileTree();

            // Log metrics
            qDebug() << "[Win32IDE] METRIC: new_folder_created=1";
            qDebug() << "[Win32IDE] METRIC: source=explorer";

            appendToOutput("New folder created: " + fullPath + "\n", "Explorer", OutputSeverity::Info);
        } else {
            qError() << "[Win32IDE] ERROR: Failed to create folder:" << fullPath.c_str();
            MessageBoxA(m_hwndMain, "Failed to create folder. Check permissions.", "Creation Failed", MB_ICONERROR);
        }
    } catch (const std::exception& e) {
        qCritical() << "[Win32IDE] CRITICAL: Exception during folder creation:" << e.what();
        MessageBoxA(m_hwndMain, "An error occurred while creating the folder.", "System Error", MB_ICONERROR);
    }
}

void Win32IDE::deleteItemInExplorer()
{
    HTREEITEM hSelected = TreeView_GetSelection(m_hwndExplorerTree);
    if (!hSelected) return;

    TVITEMA item = {};
    char text[MAX_PATH] = {};
    item.hItem = hSelected;
    item.mask = TVIF_PARAM | TVIF_TEXT;
    item.pszText = text;
    item.cchTextMax = MAX_PATH;
    if (!TreeView_GetItem(m_hwndExplorerTree, &item)) return;

    std::string fullPath = getTreeItemPath(hSelected);
    if (fullPath.empty()) return;

    std::string prompt = "Delete '" + fullPath + "'? This action cannot be undone.";
    if (MessageBoxA(m_hwndMain, prompt.c_str(), "Confirm Delete", MB_YESNO | MB_ICONWARNING) == IDYES) {
        try {
            if (std::filesystem::is_directory(fullPath)) {
                std::filesystem::remove_all(fullPath);
            } else {
                std::filesystem::remove(fullPath);
            }
            refreshFileTree();
            appendToOutput("Deleted: " + fullPath + "\n", "Output", OutputSeverity::Info);
        }
        catch (const std::exception& e) {
            appendToOutput(std::string("Error deleting: ") + e.what() + "\n", "Output", OutputSeverity::Error);
        }
    }
}

void Win32IDE::renameItemInExplorer()
{
    HTREEITEM hSelected = TreeView_GetSelection(m_hwndExplorerTree);
    if (!hSelected) return;

    std::string oldPath = getTreeItemPath(hSelected);
    if (oldPath.empty()) return;

    // Use GetSaveFileName to prompt for new name
    char buffer[MAX_PATH] = {};
    strcpy_s(buffer, oldPath.c_str());

    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFile = buffer;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "All Files\0*.*\0";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetSaveFileNameA(&ofn)) {
        std::string newPath = buffer;
        try {
            std::filesystem::rename(oldPath, newPath);
            refreshFileTree();
            appendToOutput("Renamed: " + oldPath + " -> " + newPath + "\n", "Output", OutputSeverity::Info);
        }
        catch (const std::exception& e) {
            appendToOutput(std::string("Error renaming: ") + e.what() + "\n", "Output", OutputSeverity::Error);
        }
    }
}

void Win32IDE::revealInExplorer(const std::string& filePath)
{
    if (filePath.empty()) return;

    // Try to find matching tree item
    for (const auto& kv : m_treeItemPaths) {
        if (_stricmp(kv.second.c_str(), filePath.c_str()) == 0) {
            // Select and expand parents
            HTREEITEM item = kv.first;
            HTREEITEM parent = TreeView_GetParent(m_hwndExplorerTree, item);
            while (parent) {
                TreeView_Expand(m_hwndExplorerTree, parent, TVE_EXPAND);
                parent = TreeView_GetParent(m_hwndExplorerTree, parent);
            }
            TreeView_SelectItem(m_hwndExplorerTree, item);
            SetFocus(m_hwndExplorerTree);
            appendToOutput("Revealed in Explorer: " + filePath + "\n", "Output", OutputSeverity::Info);
            return;
        }
    }

    // Fallback: open system Explorer and select the file
    ShellExecuteA(nullptr, "open", "explorer.exe", ("/select,\"" + filePath + "\"").c_str(), nullptr, SW_SHOWNORMAL);
}

void Win32IDE::handleExplorerContextMenu(POINT pt)
{
    HMENU hMenu = CreatePopupMenu();
    AppendMenuA(hMenu, MF_STRING, IDC_EXPLORER_NEW_FILE, "New File");
    AppendMenuA(hMenu, MF_STRING, IDC_EXPLORER_NEW_FOLDER, "New Folder");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hMenu, MF_STRING, 999, "Delete");
    AppendMenuA(hMenu, MF_STRING, 1000, "Rename");
    
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, m_hwndMain, nullptr);
    DestroyMenu(hMenu);
}

LRESULT CALLBACK Win32IDE::ExplorerTreeProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = (Win32IDE*)GetWindowLongPtrA(hwnd, GWLP_USERDATA);

    switch (uMsg) {
    case WM_LBUTTONDOWN: {
        const LRESULT result = pThis && pThis->m_explorerTreeOriginalProc
            ? CallWindowProcA(pThis->m_explorerTreeOriginalProc, hwnd, uMsg, wParam, lParam)
            : DefWindowProcA(hwnd, uMsg, wParam, lParam);
        if (pThis) {
            TVHITTESTINFO hit{};
            hit.pt.x = GET_X_LPARAM(lParam);
            hit.pt.y = GET_Y_LPARAM(lParam);
            const HTREEITEM hItem = TreeView_HitTest(hwnd, &hit);
            if (hItem && (hit.flags & TVHT_ONITEMBUTTON)) {
                const std::string path = pThis->getTreeItemPath(hItem);
                if (!path.empty()) {
                    TreeView_SelectItem(hwnd, hItem);
                    pThis->expandFolder(path);
                    TreeView_Expand(hwnd, hItem, TVE_EXPAND);
                }
            }
        }
        return result;
    }

    case WM_RBUTTONDOWN: {
        if (pThis) {
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            ClientToScreen(hwnd, &pt);
            pThis->handleExplorerContextMenu(pt);
        }
        return 0;
    }

    case WM_LBUTTONDBLCLK: {
        if (pThis) {
            HTREEITEM hItem = TreeView_GetSelection(hwnd);
            if (hItem) {
                TVITEMA item = {};
                char text[260];
                item.mask = TVIF_TEXT | TVIF_PARAM;
                item.pszText = text;
                item.cchTextMax = 260;
                item.hItem = hItem;
                
                if (TreeView_GetItem(hwnd, &item)) {
                    const std::string filePath = pThis->getTreeItemPath(hItem);
                    if (!filePath.empty()) {
                        const DWORD attributes = GetFileAttributesA(filePath.c_str());
                        if (attributes != INVALID_FILE_ATTRIBUTES &&
                            (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
                            pThis->expandFolder(filePath);
                            TreeView_Expand(hwnd, hItem, TVE_EXPAND);
                        } else if (attributes != INVALID_FILE_ATTRIBUTES) {
                            std::ifstream file(filePath, std::ios::binary);
                            if (file.is_open()) {
                                file.seekg(0, std::ios::end);
                                const std::streamoff fileSize = file.tellg();
                                file.seekg(0, std::ios::beg);
                                if (fileSize <= 10 * 1024 * 1024) {
                                    const std::string content(
                                        (std::istreambuf_iterator<char>(file)),
                                        std::istreambuf_iterator<char>());
                                    pThis->setEditorText(content);
                                    pThis->m_currentFile = filePath;
                                    pThis->m_fileModified = false;
                                    pThis->updateTitleBarText();
                                    pThis->appendToOutput("Opening file: " + filePath + "\n",
                                                          "Output", OutputSeverity::Info);
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0;
    }
    }

    return pThis && pThis->m_explorerTreeOriginalProc
        ? CallWindowProcA(pThis->m_explorerTreeOriginalProc, hwnd, uMsg, wParam, lParam)
        : DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

// ============================================================================
// Search View Implementation
// ============================================================================

void Win32IDE::createSearchView(HWND hwndParent)
{
    // Search input
    m_hwndSearchInput = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | ES_AUTOHSCROLL,
        5, 10, SIDEBAR_DEFAULT_WIDTH - 10, 25,
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_SEARCH_INPUT)), m_hInstance, nullptr
    );

    // Options panel
    m_hwndSearchOptions = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | WS_BORDER,
        5, 40, SIDEBAR_DEFAULT_WIDTH - 10, 80,
        hwndParent, nullptr, m_hInstance, nullptr
    );

    CreateWindowExA(0, "BUTTON", "Regex", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                    5, 5, 70, 20, m_hwndSearchOptions, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_SEARCH_REGEX)), m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Case", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                    80, 5, 70, 20, m_hwndSearchOptions, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_SEARCH_CASE)), m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Whole", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                    155, 5, 70, 20, m_hwndSearchOptions, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_SEARCH_WHOLE_WORD)), m_hInstance, nullptr);

    CreateWindowExA(0, "STATIC", "Include:", WS_CHILD | WS_VISIBLE,
                    5, 30, 50, 20, m_hwndSearchOptions, nullptr, m_hInstance, nullptr);
    m_hwndIncludePattern = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "*.ps1,*.cpp",
                                           WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                           60, 28, 160, 20, m_hwndSearchOptions, 
                                           reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_SEARCH_INCLUDE)), m_hInstance, nullptr);

    CreateWindowExA(0, "STATIC", "Exclude:", WS_CHILD | WS_VISIBLE,
                    5, 55, 50, 20, m_hwndSearchOptions, nullptr, m_hInstance, nullptr);
    m_hwndExcludePattern = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "node_modules,bin",
                                           WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                           60, 53, 160, 20, m_hwndSearchOptions, 
                                           reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_SEARCH_EXCLUDE)), m_hInstance, nullptr);

    // Results listbox
    m_hwndSearchResults = CreateWindowExA(
        WS_EX_CLIENTEDGE, "LISTBOX", "",
        WS_CHILD | LBS_NOTIFY | WS_VSCROLL,
        5, 125, SIDEBAR_DEFAULT_WIDTH - 10, 470,
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_SEARCH_RESULTS)), m_hInstance, nullptr
    );

    m_searchInProgress = false;

    appendToOutput("Search view created with regex/case options\n", "Output", OutputSeverity::Info);
}

void Win32IDE::performWorkspaceSearch(const std::string& query, bool useRegex, 
                                      bool caseSensitive, bool wholeWord)
{
    if (query.empty()) return;

    m_searchInProgress = true;
    m_searchResults.clear();
    SendMessageA(m_hwndSearchResults, LB_RESETCONTENT, 0, 0);

    appendToOutput("Searching for: '" + query + "'\n", "Output", OutputSeverity::Info);

    try {
        std::regex pattern(query, caseSensitive ? std::regex::ECMAScript : std::regex::icase);
        
        for (const auto& entry : fs::recursive_directory_iterator(m_explorerRootPath)) {
            if (!entry.is_regular_file()) continue;
            
            std::string ext = entry.path().extension().string();
            if (ext != ".ps1" && ext != ".cpp" && ext != ".h" && ext != ".txt") continue;

            std::ifstream file(entry.path());
            std::string line;
            int lineNum = 0;

            while (std::getline(file, line)) {
                lineNum++;
                if (useRegex) {
                    if (std::regex_search(line, pattern)) {
                        std::string result = entry.path().filename().string() + 
                                             " (" + std::to_string(lineNum) + "): " + line;
                        m_searchResults.push_back(result);
                        SendMessageA(m_hwndSearchResults, LB_ADDSTRING, 0, (LPARAM)result.c_str());
                    }
                }
                else {
                    std::string searchLine = caseSensitive ? line : line;
                    std::string searchQuery = caseSensitive ? query : query;
                    
                    if (searchLine.find(searchQuery) != std::string::npos) {
                        std::string result = entry.path().filename().string() + 
                                             " (" + std::to_string(lineNum) + "): " + line;
                        m_searchResults.push_back(result);
                        SendMessageA(m_hwndSearchResults, LB_ADDSTRING, 0, (LPARAM)result.c_str());
                    }
                }
            }
        }
    }
    catch (const std::exception& e) {
        appendToOutput("Search error: " + std::string(e.what()) + "\n", "Output", OutputSeverity::Error);
    }

    m_searchInProgress = false;
    appendToOutput("Search complete: " + std::to_string(m_searchResults.size()) + " results\n", 
                   "Output", OutputSeverity::Info);
}

void Win32IDE::updateSearchResults(const std::vector<std::string>& results)
{
    SendMessageA(m_hwndSearchResults, LB_RESETCONTENT, 0, 0);
    for (const auto& result : results) {
        SendMessageA(m_hwndSearchResults, LB_ADDSTRING, 0, (LPARAM)result.c_str());
    }
}

void Win32IDE::applySearchFilters(const std::string& includePattern, const std::string& excludePattern)
{
    // Placeholder - would filter search results based on patterns
    appendToOutput("Apply filters - Include: " + includePattern + ", Exclude: " + excludePattern + "\n",
                   "Output", OutputSeverity::Info);
}

void Win32IDE::searchInFiles(const std::string& query)
{
    bool useRegex = (SendMessageA(GetDlgItem(m_hwndSearchOptions, IDC_SEARCH_REGEX), BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool caseSensitive = (SendMessageA(GetDlgItem(m_hwndSearchOptions, IDC_SEARCH_CASE), BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool wholeWord = (SendMessageA(GetDlgItem(m_hwndSearchOptions, IDC_SEARCH_WHOLE_WORD), BM_GETCHECK, 0, 0) == BST_CHECKED);
    
    performWorkspaceSearch(query, useRegex, caseSensitive, wholeWord);
}

void Win32IDE::replaceInFiles(const std::string& searchText, const std::string& replaceText)
{
    if (searchText.empty()) return;

    if (MessageBoxA(m_hwndMain, "Replace occurrences across workspace?", "Confirm Replace", MB_YESNO | MB_ICONQUESTION) != IDYES) return;

    size_t totalReplacements = 0;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(m_explorerRootPath)) {
            if (!entry.is_regular_file()) continue;

            std::string ext = entry.path().extension().string();
            if (ext != ".ps1" && ext != ".cpp" && ext != ".h" && ext != ".txt" && ext != ".md") continue;

            std::ifstream file(entry.path());
            if (!file.is_open()) continue;
            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();

            size_t count = 0;
            size_t pos = 0;
            while ((pos = content.find(searchText, pos)) != std::string::npos) {
                content.replace(pos, searchText.length(), replaceText);
                pos += replaceText.length();
                count++;
            }

            if (count > 0) {
                // Backup original
                std::string backup = entry.path().string() + ".bak";
                std::filesystem::copy_file(entry.path(), backup, std::filesystem::copy_options::overwrite_existing);

                // Write new content
                std::ofstream out(entry.path(), std::ios::binary | std::ios::trunc);
                out << content;
                out.close();

                totalReplacements += count;
                appendToOutput("Replaced " + std::to_string(count) + " occurrences in " + entry.path().string() + "\n", "Output", OutputSeverity::Info);
            }
        }
    }
    catch (const std::exception& e) {
        appendToOutput(std::string("Replace in files error: ") + e.what() + "\n", "Output", OutputSeverity::Error);
        return;
    }

    appendToOutput("Replace complete: " + std::to_string(totalReplacements) + " total replacements\n", "Output", OutputSeverity::Info);
}

void Win32IDE::clearSearchResults()
{
    m_searchResults.clear();
    SendMessageA(m_hwndSearchResults, LB_RESETCONTENT, 0, 0);
}

// ============================================================================
// Source Control View Implementation
// ============================================================================

void Win32IDE::createSourceControlView(HWND hwndParent)
{
    // Toolbar
    m_hwndSCMToolbar = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | SS_OWNERDRAW,
        0, 0, SIDEBAR_DEFAULT_WIDTH, 35,
        hwndParent, nullptr, m_hInstance, nullptr
    );

    const struct { int id; const char* text; int x; } buttons[] = {
        {IDC_SCM_STAGE, "Stage", 5},
        {IDC_SCM_UNSTAGE, "Unstage", 55},
        {IDC_SCM_COMMIT, "Commit", 115},
        {IDC_SCM_SYNC, "Sync", 175}
    };

    for (const auto& btn : buttons) {
        CreateWindowExA(0, "BUTTON", btn.text, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                        btn.x, 5, 50, 25, m_hwndSCMToolbar, (HMENU)(INT_PTR)btn.id, 
                        m_hInstance, nullptr);
    }

    // Commit message box
    CreateWindowExA(0, "STATIC", "Message:", WS_CHILD | WS_VISIBLE,
                    5, 40, 60, 20, hwndParent, nullptr, m_hInstance, nullptr);
    m_hwndSCMMessageBox = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
        5, 40, SIDEBAR_DEFAULT_WIDTH - 10, 60,
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_SCM_MESSAGE)), m_hInstance, nullptr
    );

    // File list (ListView for changed files)
    m_hwndSCMFileList = CreateWindowExA(
        WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_VSCROLL,
        5, 105, SIDEBAR_DEFAULT_WIDTH - 10, 490,
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_SCM_FILE_LIST)), m_hInstance, nullptr
    );

    // Setup columns
    LVCOLUMNA col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.cx = 40;
    col.pszText = (LPSTR)"Stat";
    ListView_InsertColumn(m_hwndSCMFileList, 0, &col);

    col.cx = 180;
    col.pszText = (LPSTR)"File";
    ListView_InsertColumn(m_hwndSCMFileList, 1, &col);

    appendToOutput("Source Control view created with Git integration\n", "Output", OutputSeverity::Info);
}

void Win32IDE::refreshSourceControlView()
{
    if (!m_hwndSCMFileList) return;

    ListView_DeleteAllItems(m_hwndSCMFileList);

    // Get changed files from Git
    std::vector<GitFile> files = getGitChangedFiles();

    LVITEMA item = {};
    item.mask = LVIF_TEXT;

    for (size_t i = 0; i < files.size(); i++) {
        item.iItem = (int)i;
        item.iSubItem = 0;
        
        char status[3] = { files[i].status, 0, 0 };
        item.pszText = status;
        ListView_InsertItem(m_hwndSCMFileList, &item);

        item.iSubItem = 1;
        item.pszText = (LPSTR)files[i].path.c_str();
        ListView_SetItem(m_hwndSCMFileList, &item);
    }

    appendToOutput("Source Control refreshed: " + std::to_string(files.size()) + " changes\n",
                   "Output", OutputSeverity::Info);
}

void Win32IDE::stageSelectedFiles()
{
    int idx = ListView_GetNextItem(m_hwndSCMFileList, -1, LVNI_SELECTED);
    if (idx >= 0) {
        char file[260];
        LVITEMA lvi = { 0 };
        lvi.iSubItem = 1;
        lvi.pszText = file;
        lvi.cchTextMax = 260;
        SendMessage(m_hwndSCMFileList, LVM_GETITEMTEXTA, idx, (LPARAM)&lvi);
        gitStageFile(file);
        refreshSourceControlView();
    }
}

void Win32IDE::unstageSelectedFiles()
{
    int idx = ListView_GetNextItem(m_hwndSCMFileList, -1, LVNI_SELECTED);
    if (idx >= 0) {
        char file[260];
        LVITEMA lvi = { 0 };
        lvi.iSubItem = 1;
        lvi.pszText = file;
        lvi.cchTextMax = 260;
        SendMessage(m_hwndSCMFileList, LVM_GETITEMTEXTA, idx, (LPARAM)&lvi);
        gitUnstageFile(file);
        refreshSourceControlView();
    }
}

void Win32IDE::discardChanges()
{
    if (MessageBoxA(m_hwndMain, "Discard all changes? This cannot be undone.", 
                    "Confirm", MB_YESNO | MB_ICONWARNING) == IDYES) {
        std::string output;
        executeGitCommand("git reset --hard HEAD", output);
        refreshSourceControlView();
        appendToOutput("Changes discarded\n", "Output", OutputSeverity::Warning);
    }
}

void Win32IDE::commitChangesFromSidebar()
{
    char message[512];
    GetWindowTextA(m_hwndSCMMessageBox, message, 512);
    
    if (strlen(message) > 0) {
        gitCommit(message);
        SetWindowTextA(m_hwndSCMMessageBox, "");
        refreshSourceControlView();
    }
    else {
        MessageBoxA(m_hwndMain, "Please enter a commit message", "Commit", MB_OK | MB_ICONWARNING);
    }
}

void Win32IDE::syncRepository()
{
    gitPull();
    gitPush();
    refreshSourceControlView();
}

void Win32IDE::showSCMContextMenu(POINT pt)
{
    HMENU hMenu = CreatePopupMenu();
    AppendMenuA(hMenu, MF_STRING, IDC_SCM_STAGE, "Stage");
    AppendMenuA(hMenu, MF_STRING, IDC_SCM_UNSTAGE, "Unstage");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hMenu, MF_STRING, 998, "Discard Changes");
    
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, m_hwndMain, nullptr);
    DestroyMenu(hMenu);
}

// ============================================================================
// Run and Debug View Implementation
// ============================================================================

void Win32IDE::createRunDebugView(HWND hwndParent)
{
    // Toolbar
    m_hwndDebugToolbar = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | SS_OWNERDRAW,
        0, 0, SIDEBAR_DEFAULT_WIDTH, 35,
        hwndParent, nullptr, m_hInstance, nullptr
    );

    CreateWindowExA(0, "BUTTON", "Start", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    5, 5, 50, 25, m_hwndDebugToolbar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_DEBUG_START)), m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Stop", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    60, 5, 50, 25, m_hwndDebugToolbar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_DEBUG_STOP)), m_hInstance, nullptr);

    // Configuration dropdown
    m_hwndDebugConfigs = CreateWindowExA(
        0, "COMBOBOX", "",
        WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
        5, 40, SIDEBAR_DEFAULT_WIDTH - 10, 100,
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_DEBUG_CONFIGS)), m_hInstance, nullptr
    );

    SendMessageA(m_hwndDebugConfigs, CB_ADDSTRING, 0, (LPARAM)"PowerShell Script");
    SendMessageA(m_hwndDebugConfigs, CB_ADDSTRING, 0, (LPARAM)"C++ Debug");
    SendMessageA(m_hwndDebugConfigs, CB_ADDSTRING, 0, (LPARAM)"Python Script");
    SendMessageA(m_hwndDebugConfigs, CB_SETCURSEL, 0, 0);

    // Variables view
    CreateWindowExA(0, "STATIC", "Variables:", WS_CHILD | WS_VISIBLE,
                    5, 145, 100, 20, hwndParent, nullptr, m_hInstance, nullptr);
    m_hwndDebugVariables = CreateWindowExA(
        WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
        WS_CHILD | LVS_REPORT | WS_VSCROLL,
        5, 145, SIDEBAR_DEFAULT_WIDTH - 10, 450,
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_DEBUG_VARIABLES)), m_hInstance, nullptr
    );

    LVCOLUMNA col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.cx = 80;
    col.pszText = (LPSTR)"Name";
    ListView_InsertColumn(m_hwndDebugVariables, 0, &col);

    col.cx = 140;
    col.pszText = (LPSTR)"Value";
    ListView_InsertColumn(m_hwndDebugVariables, 1, &col);

    m_debuggingActive = false;

    appendToOutput("Run and Debug view created\n", "Output", OutputSeverity::Info);
}

void Win32IDE::createLaunchConfiguration()
{
    appendToOutput("Creating launch configuration...\n", "Output", OutputSeverity::Info);
    // Placeholder - would create launch.json equivalent
}

void Win32IDE::startDebugging()
{
    m_debuggingActive = true;
    appendToOutput("Debugging started\n", "Output", OutputSeverity::Info);
    updateDebugVariables();
}

void Win32IDE::stopDebugging()
{
    m_debuggingActive = false;
    ListView_DeleteAllItems(m_hwndDebugVariables);
    appendToOutput("Debugging stopped\n", "Output", OutputSeverity::Info);
}

// setBreakpoint and removeBreakpoint are implemented in Win32IDE_Debugger.cpp

void Win32IDE::stepOver()
{
    appendToOutput("Step Over\n", "Output", OutputSeverity::Info);
}

void Win32IDE::stepInto()
{
    appendToOutput("Step Into\n", "Output", OutputSeverity::Info);
}

void Win32IDE::stepOut()
{
    appendToOutput("Step Out\n", "Output", OutputSeverity::Info);
}

void Win32IDE::continueExecution()
{
    appendToOutput("Continue Execution\n", "Output", OutputSeverity::Info);
}

void Win32IDE::showDebugConsole()
{
    appendToOutput("Debug Console shown\n", "Output", OutputSeverity::Info);
}

void Win32IDE::updateDebugVariables()
{
    if (!m_debuggingActive || !m_hwndDebugVariables) return;

    // Placeholder - would query actual debugger variables
    ListView_DeleteAllItems(m_hwndDebugVariables);

    char currentDirectory[MAX_PATH] = {};
    GetCurrentDirectoryA(MAX_PATH, currentDirectory);
    const struct { const char* name; const char* value; } vars[] = {
        {"$PSVersionTable", "7.4.6"},
        {"$PWD", currentDirectory},
        {"$ErrorCount", "0"}
    };

    LVITEMA item = {};
    item.mask = LVIF_TEXT;

    for (int i = 0; i < 3; i++) {
        item.iItem = i;
        item.iSubItem = 0;
        item.pszText = (LPSTR)vars[i].name;
        ListView_InsertItem(m_hwndDebugVariables, &item);

        item.iSubItem = 1;
        item.pszText = (LPSTR)vars[i].value;
        ListView_SetItem(m_hwndDebugVariables, &item);
    }
}

// ============================================================================
// Extensions View Implementation
// ============================================================================

void Win32IDE::createExtensionsView(HWND hwndParent)
{
    // Search box
    m_hwndExtensionSearch = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | ES_AUTOHSCROLL,
        5, 10, SIDEBAR_DEFAULT_WIDTH - 10, 25,
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_EXT_SEARCH)), m_hInstance, nullptr
    );

    // Extensions list
    m_hwndExtensionsList = CreateWindowExA(
        WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_VSCROLL,
        5, 40, SIDEBAR_DEFAULT_WIDTH - 10, 555,
        hwndParent, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_EXT_LIST)), m_hInstance, nullptr
    );

    // Setup columns
    LVCOLUMNA col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.cx = 150;
    col.pszText = (LPSTR)"Name";
    ListView_InsertColumn(m_hwndExtensionsList, 0, &col);

    col.cx = 60;
    col.pszText = (LPSTR)"Version";
    ListView_InsertColumn(m_hwndExtensionsList, 1, &col);

    appendToOutput("Extensions view created\n", "Output", OutputSeverity::Info);
}

void Win32IDE::searchExtensions(const std::string& query)
{
    appendToOutput("Searching extensions: " + query + "\n", "Output", OutputSeverity::Info);
    // Placeholder - would query extension marketplace
}

void Win32IDE::installExtension(const std::string& extensionId)
{
    appendToOutput("Installing extension: " + extensionId + "\n", "Output", OutputSeverity::Info);
    // Placeholder
}

void Win32IDE::uninstallExtension(const std::string& extensionId)
{
    appendToOutput("Uninstalling extension: " + extensionId + "\n", "Output", OutputSeverity::Info);
    // Placeholder
}

void Win32IDE::enableExtension(const std::string& extensionId)
{
    for (auto& ext : m_extensions) {
        if (ext.id == extensionId) {
            ext.enabled = true;
            appendToOutput("Extension enabled: " + extensionId + "\n", "Output", OutputSeverity::Info);
            break;
        }
    }
}

void Win32IDE::disableExtension(const std::string& extensionId)
{
    for (auto& ext : m_extensions) {
        if (ext.id == extensionId) {
            ext.enabled = false;
            appendToOutput("Extension disabled: " + extensionId + "\n", "Output", OutputSeverity::Info);
            break;
        }
    }
}

void Win32IDE::updateExtension(const std::string& extensionId)
{
    appendToOutput("Updating extension: " + extensionId + "\n", "Output", OutputSeverity::Info);
    // Placeholder
}

void Win32IDE::showExtensionDetails(const std::string& extensionId)
{
    appendToOutput("Showing details for: " + extensionId + "\n", "Output", OutputSeverity::Info);
    // Placeholder
}

void Win32IDE::loadInstalledExtensions()
{
    if (!m_hwndExtensionsList || !IsWindow(m_hwndExtensionsList)) return;
    // setSidebarView() and updateSidebarContent() can both be reached from a
    // single activity-bar click. Do not re-enter filesystem enumeration or
    // mutate the list view while a prior refresh is still active.
    if (m_extensionsLoadInProgress) return;
    m_extensionsLoadInProgress = true;
    struct LoadingReset {
        bool& flag;
        ~LoadingReset() { flag = false; }
    } loadingReset{m_extensionsLoadInProgress};

    // Extension discovery touches user-controlled filesystem roots and JSON
    // manifests.  A malformed manifest, transient reparse point, or STL
    // filesystem exception must never terminate the IDE while the user is
    // merely opening the Extensions view.
    try {
        if (!IsWindow(m_hwndExtensionsList)) return;
        ListView_DeleteAllItems(m_hwndExtensionsList);

    // Discover the actual installed VS Code/Cursor extensions.  The previous
    // implementation inserted a hard-coded list, which made GitHub Copilot
    // appear installed even when it was absent and hid extensions that really
    // existed on disk.
    m_extensions.clear();
    std::vector<fs::path> roots;
    if (const char* profile = std::getenv("USERPROFILE")) {
        const fs::path user(profile);
        roots.push_back(user / ".vscode" / "extensions");
        roots.push_back(user / ".vscode-insiders" / "extensions");
        roots.push_back(user / ".cursor" / "extensions");
    }
    if (const char* localAppData = std::getenv("LOCALAPPDATA")) {
        const fs::path local(localAppData);
        roots.push_back(local / "Programs" / "Microsoft VS Code" / "resources" / "app" / "extensions");
        roots.push_back(local / "Programs" / "Microsoft VS Code Insiders" / "resources" / "app" / "extensions");
    }

    // package.json files are untrusted user data. Do not use std::regex here:
    // the ECMAScript implementation can allocate heavily for a long or
    // malformed manifest and throw regex_error(error_stack) on the UI thread.
    // This scanner extracts one JSON string property without regex backtracking.
    auto jsonString = [](const std::string& text, const char* key) -> std::string {
        const std::string quotedKey = std::string("\"") + key + "\"";
        size_t searchFrom = 0;
        while (searchFrom < text.size()) {
            const size_t keyStart = text.find(quotedKey, searchFrom);
            if (keyStart == std::string::npos) return {};

            size_t before = keyStart;
            while (before > 0 && std::isspace(static_cast<unsigned char>(text[before - 1]))) {
                --before;
            }
            if (before == 0 || (text[before - 1] != '{' && text[before - 1] != ',')) {
                searchFrom = keyStart + quotedKey.size();
                continue;
            }

            size_t cursor = keyStart + quotedKey.size();
            while (cursor < text.size() && std::isspace(static_cast<unsigned char>(text[cursor]))) {
                ++cursor;
            }
            if (cursor >= text.size() || text[cursor] != ':') {
                searchFrom = keyStart + quotedKey.size();
                continue;
            }
            ++cursor;
            while (cursor < text.size() && std::isspace(static_cast<unsigned char>(text[cursor]))) {
                ++cursor;
            }
            if (cursor >= text.size() || text[cursor] != '"') return {};
            ++cursor;

            std::string decoded;
            decoded.reserve(64);
            bool escaped = false;
            for (; cursor < text.size(); ++cursor) {
                const char c = text[cursor];
                if (escaped) {
                    switch (c) {
                    case 'n': decoded.push_back('\n'); break;
                    case 'r': decoded.push_back('\r'); break;
                    case 't': decoded.push_back('\t'); break;
                    case 'b': decoded.push_back('\b'); break;
                    case 'f': decoded.push_back('\f'); break;
                    default: decoded.push_back(c); break;
                    }
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    return decoded;
                } else {
                    decoded.push_back(c);
                }
            }
            return {};
        }
        return {};
    };

    std::unordered_set<std::string> seen;
    for (const auto& root : roots) {
        std::error_code ec;
        if (!fs::is_directory(root, ec)) continue;
        for (fs::directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
             !ec && it != fs::directory_iterator(); it.increment(ec)) {
            if (ec || !it->is_directory(ec)) continue;
            const fs::path manifest = it->path() / "package.json";
            std::ifstream file(manifest, std::ios::binary);
            if (!file) continue;
            std::error_code sizeEc;
            const auto manifestBytes = fs::file_size(manifest, sizeEc);
            constexpr uintmax_t kMaxExtensionManifestBytes = 4u * 1024u * 1024u;
            if (sizeEc || manifestBytes > kMaxExtensionManifestBytes) {
                appendToOutput("Skipped oversized or unreadable extension manifest: " +
                               manifest.string() + "\n", "Errors", OutputSeverity::Warning);
                continue;
            }
            std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            if (text.empty()) continue;
            std::string publisher = jsonString(text, "publisher");
            std::string name = jsonString(text, "name");
            std::string displayName = jsonString(text, "displayName");
            std::string version = jsonString(text, "version");
            if (name.empty()) name = it->path().filename().string();
            if (displayName.empty()) displayName = name;
            const std::string id = publisher.empty() ? name : publisher + "." + name;
            const std::string key = id + "|" + version;
            if (!seen.insert(key).second) continue;
            m_extensions.push_back({id, displayName, version,
                jsonString(text, "description"), publisher, true, true});
        }
    }

    std::sort(m_extensions.begin(), m_extensions.end(),
        [](const Extension& a, const Extension& b) { return a.name < b.name; });

    LVITEMA item = {};
    item.mask = LVIF_TEXT;

    for (size_t i = 0; i < m_extensions.size(); i++) {
        if (!IsWindow(m_hwndExtensionsList)) return;
        item.iItem = (int)i;
        item.iSubItem = 0;
        item.pszText = (LPSTR)m_extensions[i].name.c_str();
        ListView_InsertItem(m_hwndExtensionsList, &item);

        item.iSubItem = 1;
        item.pszText = (LPSTR)m_extensions[i].version.c_str();
        ListView_SetItem(m_hwndExtensionsList, &item);
    }

        appendToOutput("Discovered " + std::to_string(m_extensions.size()) +
                       " installed extensions from local VS Code/Cursor roots\n",
                       "Output", OutputSeverity::Info);
    } catch (const std::exception& ex) {
        m_extensions.clear();
        ListView_DeleteAllItems(m_hwndExtensionsList);
        appendToOutput(std::string("Extensions discovery failed safely: ") +
                       ex.what() + "\n", "Errors", OutputSeverity::Error);
    } catch (...) {
        m_extensions.clear();
        ListView_DeleteAllItems(m_hwndExtensionsList);
        appendToOutput("Extensions discovery failed safely: unknown exception\n",
                       "Errors", OutputSeverity::Error);
    }
}

// ============================================================================
// Outline View Implementation - Shows code structure (functions, classes, etc.)
// ============================================================================

void Win32IDE::createOutlineView(HWND hwndParent)
{
    // Create TreeView for outline
    m_hwndOutlineTree = CreateWindowExA(
        WS_EX_CLIENTEDGE, WC_TREEVIEWA, "",
        WS_CHILD | TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
        0, 0, 280, 300,
        hwndParent, nullptr, m_hInstance, nullptr
    );
    
    SetWindowLongPtrA(m_hwndOutlineTree, GWLP_USERDATA, (LONG_PTR)this);
    
    appendToOutput("Outline view created\n", "Output", OutputSeverity::Info);
}

void Win32IDE::updateOutlineView()
{
    if (!m_hwndOutlineTree) return;
    
    TreeView_DeleteAllItems(m_hwndOutlineTree);
    m_outlineItems.clear();
    
    // Parse current file for outline
    parseCodeForOutline();
    
    // Populate tree view
    TVINSERTSTRUCTA tvis = {};
    tvis.hParent = TVI_ROOT;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask = TVIF_TEXT | TVIF_PARAM;
    
    for (size_t i = 0; i < m_outlineItems.size(); ++i) {
        const auto& item = m_outlineItems[i];
        std::string text = item.type + " " + item.name + " (line " + std::to_string(item.line) + ")";
        tvis.item.pszText = (LPSTR)text.c_str();
        tvis.item.lParam = (LPARAM)i;
        TreeView_InsertItem(m_hwndOutlineTree, &tvis);
    }
}

void Win32IDE::parseCodeForOutline()
{
    if (!m_hwndEditor) return;
    
    int textLen = GetWindowTextLengthA(m_hwndEditor);
    if (textLen == 0) return;
    
    std::string text(textLen + 1, '\0');
    GetWindowTextA(m_hwndEditor, &text[0], textLen + 1);
    text.resize(textLen);
    
    // Simple regex-based parsing for common patterns
    std::regex functionRegex(R"((function|def|void|int|string|bool|public|private)\s+(\w+)\s*\()");
    std::regex classRegex(R"((class|struct|interface)\s+(\w+))");
    std::regex variableRegex(R"(\$([\w_]+)\s*=)");
    
    // Split by lines for line number tracking
    std::istringstream stream(text);
    std::string line;
    int lineNum = 1;
    
    while (std::getline(stream, line)) {
        std::smatch match;
        
        // Check for function definitions
        if (std::regex_search(line, match, functionRegex)) {
            OutlineItem item;
            item.type = "function";
            item.name = match[2].str();
            item.line = lineNum;
            item.column = (int)match.position();
            m_outlineItems.push_back(item);
        }
        
        // Check for class definitions
        if (std::regex_search(line, match, classRegex)) {
            OutlineItem item;
            item.type = match[1].str();
            item.name = match[2].str();
            item.line = lineNum;
            item.column = (int)match.position();
            m_outlineItems.push_back(item);
        }
        
        // Check for PowerShell variables (top-level)
        if (std::regex_search(line, match, variableRegex)) {
            // Only add if it looks like a significant variable (not inside a function)
            if (line.find("function") == std::string::npos) {
                OutlineItem item;
                item.type = "variable";
                item.name = "$" + match[1].str();
                item.line = lineNum;
                item.column = (int)match.position();
                m_outlineItems.push_back(item);
            }
        }
        
        ++lineNum;
    }
    
    appendToOutput("Parsed " + std::to_string(m_outlineItems.size()) + " outline items\n", 
                   "Output", OutputSeverity::Info);
}

void Win32IDE::goToOutlineItem(int index)
{
    if (index < 0 || index >= (int)m_outlineItems.size()) return;
    
    const auto& item = m_outlineItems[index];
    
    // Navigate to line in editor
    int charIndex = (int)SendMessage(m_hwndEditor, EM_LINEINDEX, item.line - 1, 0);
    charIndex += item.column;
    
    SendMessage(m_hwndEditor, EM_SETSEL, charIndex, charIndex);
    SendMessage(m_hwndEditor, EM_SCROLLCARET, 0, 0);
    SetFocus(m_hwndEditor);
    
    appendToOutput("Navigated to: " + item.name + " at line " + std::to_string(item.line) + "\n",
                   "Output", OutputSeverity::Info);
}

// ============================================================================
// Timeline View Implementation - Shows file history (Git commits, local saves)
// ============================================================================

void Win32IDE::createTimelineView(HWND hwndParent)
{
    // Create ListView for timeline
    m_hwndTimelineList = CreateWindowExA(
        WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        0, 0, 280, 200,
        hwndParent, nullptr, m_hInstance, nullptr
    );
    
    // Add columns
    LVCOLUMNA lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    
    lvc.pszText = (LPSTR)"Date";
    lvc.cx = 80;
    lvc.iSubItem = 0;
    ListView_InsertColumn(m_hwndTimelineList, 0, &lvc);
    
    lvc.pszText = (LPSTR)"Author";
    lvc.cx = 70;
    lvc.iSubItem = 1;
    ListView_InsertColumn(m_hwndTimelineList, 1, &lvc);
    
    lvc.pszText = (LPSTR)"Message";
    lvc.cx = 120;
    lvc.iSubItem = 2;
    ListView_InsertColumn(m_hwndTimelineList, 2, &lvc);
    
    SetWindowLongPtrA(m_hwndTimelineList, GWLP_USERDATA, (LONG_PTR)this);
    
    appendToOutput("Timeline view created\n", "Output", OutputSeverity::Info);
}

void Win32IDE::updateTimelineView()
{
    if (!m_hwndTimelineList) return;
    
    ListView_DeleteAllItems(m_hwndTimelineList);
    m_timelineEntries.clear();
    
    // Load Git history for current file
    loadGitHistory();
    
    // Populate list view
    LVITEMA lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    
    for (size_t i = 0; i < m_timelineEntries.size(); ++i) {
        const auto& entry = m_timelineEntries[i];
        
        lvi.iItem = (int)i;
        lvi.iSubItem = 0;
        lvi.pszText = (LPSTR)entry.date.c_str();
        ListView_InsertItem(m_hwndTimelineList, &lvi);
        
        // Use SendMessage directly for setting item text
        LVITEMA lviSet = { 0 };
        lviSet.iSubItem = 1;
        lviSet.pszText = (LPSTR)entry.author.c_str();
        SendMessage(m_hwndTimelineList, LVM_SETITEMTEXTA, (int)i, (LPARAM)&lviSet);
        
        lviSet.iSubItem = 2;
        lviSet.pszText = (LPSTR)entry.message.c_str();
        SendMessage(m_hwndTimelineList, LVM_SETITEMTEXTA, (int)i, (LPARAM)&lviSet);
    }
}

void Win32IDE::loadGitHistory()
{
    if (m_currentFile.empty() || !isGitRepository()) {
        // Add placeholder entries for non-Git files
        TimelineEntry entry;
        entry.message = "File opened";
        entry.author = "Local";
        entry.date = "Today";
        entry.isGitCommit = false;
        m_timelineEntries.push_back(entry);
        return;
    }
    
    // Run git log for current file
    std::string command = "git log --oneline -10 --format=\"%h|%an|%ad|%s\" --date=short -- \"" + m_currentFile + "\"";
    std::string output;
    
    if (executeGitCommand(command, output)) {
        std::istringstream stream(output);
        std::string line;
        
        while (std::getline(stream, line)) {
            if (line.empty()) continue;
            
            // Parse: hash|author|date|message
            std::vector<std::string> parts;
            size_t start = 0;
            size_t end = 0;
            while ((end = line.find('|', start)) != std::string::npos) {
                parts.push_back(line.substr(start, end - start));
                start = end + 1;
            }
            parts.push_back(line.substr(start));
            
            if (parts.size() >= 4) {
                TimelineEntry entry;
                entry.commitHash = parts[0];
                entry.author = parts[1];
                entry.date = parts[2];
                entry.message = parts[3];
                entry.isGitCommit = true;
                m_timelineEntries.push_back(entry);
            }
        }
    }
    
    appendToOutput("Loaded " + std::to_string(m_timelineEntries.size()) + " timeline entries\n",
                   "Output", OutputSeverity::Info);
}

void Win32IDE::goToTimelineEntry(int index)
{
    if (index < 0 || index >= (int)m_timelineEntries.size()) return;
    
    const auto& entry = m_timelineEntries[index];
    
    if (entry.isGitCommit && !entry.commitHash.empty()) {
        // Show diff for this commit
        std::string command = "git show " + entry.commitHash + " -- \"" + m_currentFile + "\"";
        std::string output;
        
        if (executeGitCommand(command, output)) {
            // Display in output panel
            appendToOutput("\n=== Commit: " + entry.commitHash + " ===\n", "Output", OutputSeverity::Info);
            appendToOutput(output + "\n", "Output", OutputSeverity::Info);
        }
    } else {
        appendToOutput("Selected local entry: " + entry.message + "\n", "Output", OutputSeverity::Info);
    }
}
