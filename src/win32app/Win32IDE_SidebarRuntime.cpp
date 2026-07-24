#include "Win32IDE.h"
#include "Win32IDE_Commands.h"

#include <commctrl.h>

namespace
{
constexpr int kActivityBarWidth = 48;
constexpr int kSidebarDefaultWidth = 250;
constexpr int kSidebarHeightHint = 600;

constexpr int IDC_ACTIVITY_EXPLORER = 6001;
constexpr int IDC_ACTIVITY_SEARCH = 6002;
constexpr int IDC_ACTIVITY_SCM = 6003;
constexpr int IDC_ACTIVITY_DEBUG = 6004;
constexpr int IDC_ACTIVITY_EXTENSIONS = 6005;
constexpr int IDC_ACTIVITY_GITHUB = 6006;
constexpr int IDC_ACTIVITY_GITHUB_PULL_RELEASE = 6007;
constexpr int IDC_ACTIVITY_ACCOUNTS = 6008;
constexpr int IDC_ACTIVITY_MANAGE = 6009;
constexpr int IDC_ACTIVITY_RECOVERY = 6010;
constexpr int IDC_ACTIVITY_CHAT = 6011;

constexpr int IDC_GITHUB_OPEN_REPO = 6060;
constexpr int IDC_GITHUB_OPEN_ISSUES = 6061;
constexpr int IDC_GITHUB_OPEN_PULLS = 6062;
constexpr int IDC_GITHUB_OPEN_RELEASES = 6063;
constexpr int IDC_ACCOUNTS_OPEN_SETTINGS = 6064;
constexpr int IDC_ACCOUNTS_OPEN_GITHUB_LOGIN = 6065;
constexpr int IDC_MANAGE_OPEN_EXTENSIONS = 6066;
constexpr int IDC_MANAGE_OPEN_SETTINGS = 6067;
constexpr int IDC_MANAGE_OPEN_LAYOUTS = 6068;

constexpr int IDC_DEBUG_CONFIGS = 6040;
constexpr int IDC_DEBUG_START = 6041;
constexpr int IDC_DEBUG_STOP = 6042;
constexpr int IDC_DEBUG_VARIABLES = 6043;
constexpr int IDC_DEBUG_VARIABLES_LABEL = 6046;

void destroySidebarChildren(HWND sidebar)
{
    if (!sidebar)
        return;

    HWND child = GetWindow(sidebar, GW_CHILD);
    while (child)
    {
        HWND next = GetWindow(child, GW_HWNDNEXT);
        DestroyWindow(child);
        child = next;
    }
}

void createSidebarHeaderText(HWND parent, const char* title, const char* subtitle)
{
    if (!parent)
        return;

    CreateWindowExA(0, "STATIC", title, WS_CHILD | WS_VISIBLE | SS_LEFT,
                    8, 8, 220, 20, parent, nullptr, nullptr, nullptr);

    CreateWindowExA(0, "STATIC", subtitle, WS_CHILD | WS_VISIBLE | SS_LEFT,
                    8, 30, 230, 32, parent, nullptr, nullptr, nullptr);
}

void createSidebarActionButton(HWND parent, int id, const char* label, int y)
{
    if (!parent)
        return;

    CreateWindowExA(0, "BUTTON", label, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    8, y, 220, 28,
                    parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr, nullptr);
}
}

// NOTE: The following functions are defined in Win32IDE.cpp to avoid duplicate symbol linker errors:
// - createActivityBar()
// - createPrimarySidebar()
// - toggleSidebar()
// - toggleSecondarySidebar()
// - setSidebarView()
// - updateSidebarContent()
// - resizeSidebar()

LRESULT CALLBACK Win32IDE::ActivityBarProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* ide = reinterpret_cast<Win32IDE*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));
    switch (uMsg)
    {
        case WM_COMMAND:
            if (!ide)
                return 0;
            switch (LOWORD(wParam))
            {
                case IDC_ACTIVITY_EXPLORER:
                    ide->setSidebarView(SidebarView::Explorer);
                    if (!ide->m_sidebarVisible)
                        ide->toggleSidebar();
                    return 0;
                case IDC_ACTIVITY_SEARCH:
                    ide->setSidebarView(SidebarView::Search);
                    if (!ide->m_sidebarVisible)
                        ide->toggleSidebar();
                    return 0;
                case IDC_ACTIVITY_SCM:
                    ide->setSidebarView(SidebarView::SourceControl);
                    if (!ide->m_sidebarVisible)
                        ide->toggleSidebar();
                    return 0;
                case IDC_ACTIVITY_DEBUG:
                    ide->setSidebarView(SidebarView::RunDebug);
                    if (!ide->m_sidebarVisible)
                        ide->toggleSidebar();
                    return 0;
                case IDC_ACTIVITY_EXTENSIONS:
                    ide->setSidebarView(SidebarView::Extensions);
                    if (!ide->m_sidebarVisible)
                        ide->toggleSidebar();
                    return 0;
                case IDC_ACTIVITY_GITHUB:
                    ide->setSidebarView(SidebarView::GitHub);
                    if (!ide->m_sidebarVisible)
                        ide->toggleSidebar();
                    return 0;
                case IDC_ACTIVITY_GITHUB_PULL_RELEASE:
                    ide->setSidebarView(SidebarView::GitHubPullRelease);
                    if (!ide->m_sidebarVisible)
                        ide->toggleSidebar();
                    return 0;
                case IDC_ACTIVITY_ACCOUNTS:
                    ide->setSidebarView(SidebarView::Accounts);
                    if (!ide->m_sidebarVisible)
                        ide->toggleSidebar();
                    return 0;
                case IDC_ACTIVITY_MANAGE:
                    ide->setSidebarView(SidebarView::Manage);
                    if (!ide->m_sidebarVisible)
                        ide->toggleSidebar();
                    return 0;
                case IDC_ACTIVITY_RECOVERY:
                    ide->setSidebarView(SidebarView::DiskRecovery);
                    if (!ide->m_sidebarVisible)
                        ide->toggleSidebar();
                    return 0;
                case IDC_ACTIVITY_CHAT:
                    ide->toggleSecondarySidebar();
                    return 0;
            }
            break;
        case WM_PAINT:
        {
            PAINTSTRUCT ps = {};
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            HBRUSH brush = CreateSolidBrush(RGB(51, 51, 51));
            FillRect(hdc, &rc, brush);
            DeleteObject(brush);
            EndPaint(hwnd, &ps);
            return 0;
        }
    }

    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK Win32IDE::SidebarProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* ide = reinterpret_cast<Win32IDE*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));
    switch (uMsg)
    {
        case WM_COMMAND:
            if (!ide)
                return 0;

            switch (LOWORD(wParam))
            {
                case IDC_GITHUB_OPEN_REPO:
                    ShellExecuteA(nullptr, "open", "https://github.com/ItsMehRAWRXD/RawrXD", nullptr, nullptr, SW_SHOW);
                    return 0;
                case IDC_GITHUB_OPEN_ISSUES:
                    ShellExecuteA(nullptr, "open", "https://github.com/ItsMehRAWRXD/RawrXD/issues", nullptr, nullptr,
                                 SW_SHOW);
                    return 0;
                case IDC_GITHUB_OPEN_PULLS:
                    ShellExecuteA(nullptr, "open", "https://github.com/ItsMehRAWRXD/RawrXD/pulls", nullptr, nullptr,
                                 SW_SHOW);
                    return 0;
                case IDC_GITHUB_OPEN_RELEASES:
                    ShellExecuteA(nullptr, "open", "https://github.com/ItsMehRAWRXD/RawrXD/releases", nullptr, nullptr,
                                 SW_SHOW);
                    return 0;
                case IDC_ACCOUNTS_OPEN_SETTINGS:
                    PostMessageA(ide->m_hwndMain, WM_COMMAND, IDM_T1_SETTINGS_GUI, 0);
                    return 0;
                case IDC_ACCOUNTS_OPEN_GITHUB_LOGIN:
                    ShellExecuteA(nullptr, "open", "https://github.com/login", nullptr, nullptr, SW_SHOW);
                    return 0;
                case IDC_MANAGE_OPEN_EXTENSIONS:
                    ide->setSidebarView(SidebarView::Extensions);
                    return 0;
                case IDC_MANAGE_OPEN_SETTINGS:
                    PostMessageA(ide->m_hwndMain, WM_COMMAND, IDM_T1_SETTINGS_GUI, 0);
                    return 0;
                case IDC_MANAGE_OPEN_LAYOUTS:
                    PostMessageA(ide->m_hwndMain, WM_COMMAND, IDM_VIEW_LAYOUT_PROFILE_APPLY, 0);
                    return 0;
            }
            break;
        case WM_SIZE:
            if (ide)
                ide->resizeSidebar(LOWORD(lParam), HIWORD(lParam));
            return 0;
        case WM_ERASEBKGND:
        {
            HDC hdc = (HDC)wParam;
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            HBRUSH brush = CreateSolidBrush(RGB(37, 37, 38));
            FillRect(hdc, &rc, brush);
            DeleteObject(brush);
            return 1;
        }
        case WM_PAINT:
        {
            PAINTSTRUCT ps = {};
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            HBRUSH brush = CreateSolidBrush(RGB(37, 37, 38));
            FillRect(hdc, &rc, brush);
            DeleteObject(brush);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_CTLCOLORSTATIC:
        {
            // Paint all sidebar child STATIC labels with dark background
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, RGB(37, 37, 38));
            SetTextColor(hdc, RGB(204, 204, 204));
            static HBRUSH hDarkBrush = CreateSolidBrush(RGB(37, 37, 38));
            return (LRESULT)hDarkBrush;
        }
    }

    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK Win32IDE::SidebarContentProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_ERASEBKGND:
        {
            HDC hdc = (HDC)wParam;
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            HBRUSH brush = CreateSolidBrush(RGB(37, 37, 38));
            FillRect(hdc, &rc, brush);
            DeleteObject(brush);
            return 1;
        }
        case WM_CTLCOLORSTATIC:
        {
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, RGB(37, 37, 38));
            SetTextColor(hdc, RGB(204, 204, 204));
            static HBRUSH hDarkBrush = CreateSolidBrush(RGB(37, 37, 38));
            return (LRESULT)hDarkBrush;
        }
    }
    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

void Win32IDE::createExplorerView(HWND hwndParent)
{
    createFileExplorer(hwndParent ? hwndParent : m_hwndSidebar);
}

void Win32IDE::refreshFileTree()
{
    populateFileTree();
}

// NOTE: The following functions are defined in Win32IDE.cpp to avoid duplicate symbol linker errors:
// - createSearchView()
// - createSourceControlView()
// - refreshSourceControlView()
// - createRunDebugView()

void Win32IDE::updateDebugVariables()
{
    if (!m_hwndDebugVariables || !IsWindow(m_hwndDebugVariables))
        return;

    ListView_DeleteAllItems(m_hwndDebugVariables);
    for (size_t i = 0; i < m_localVariables.size(); ++i)
    {
        const auto& variable = m_localVariables[i];

        LVITEMA item = {};
        item.mask = LVIF_TEXT;
        item.iItem = static_cast<int>(i);
        item.pszText = const_cast<char*>(variable.name.c_str());
        ListView_InsertItem(m_hwndDebugVariables, &item);
        ListView_SetItemText(m_hwndDebugVariables, static_cast<int>(i), 1, const_cast<char*>(variable.value.c_str()));
    }
}
