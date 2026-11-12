// Win32IDE_Sidebar.cpp — File Explorer SysTreeView product path (C29)
#include "Win32IDE.h"
#include "Win32IDE_CommandIDs.h"
#include <commctrl.h>
#include <string>
#include <vector>

namespace {
WNDPROC g_sidebarPrevProc = nullptr;

LRESULT CALLBACK SidebarForwardProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // STATIC parents swallow child BN_CLICKED; forward to the IDE main window.
    if (msg == WM_COMMAND) {
        HWND main = GetParent(hwnd);
        if (main) {
            return SendMessageW(main, WM_COMMAND, wParam, lParam);
        }
    }
    if (g_sidebarPrevProc) {
        return CallWindowProcW(g_sidebarPrevProc, hwnd, msg, wParam, lParam);
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void InsertTreeRoot(HWND tree, const std::string& path) {
    if (!tree || path.empty()) return;
    wchar_t text[MAX_PATH] = {};
    MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, text, MAX_PATH);
    TVINSERTSTRUCTW tvis = {};
    tvis.hParent = TVI_ROOT;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask = TVIF_TEXT;
    tvis.item.pszText = text;
    (void)SendMessageW(tree, TVM_INSERTITEMW, 0, (LPARAM)&tvis);
}
}  // namespace

void Win32IDE::createFileExplorer() {
    if (m_hwndSidebar && m_hwndFileTree && IsWindow(m_hwndFileTree)) return;

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_TREEVIEW_CLASSES };
    InitCommonControlsEx(&icc);

    const int w = m_sidebarWidth > 0 ? m_sidebarWidth : 250;
    if (!m_hwndSidebar) {
        m_hwndSidebar = CreateWindowExW(
            0, L"STATIC", L"File Explorer",
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
            0, 30, w, 500, m_hwndMain, nullptr, m_hInstance, nullptr);
        if (m_hwndSidebar && !g_sidebarPrevProc) {
            g_sidebarPrevProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(
                m_hwndSidebar, GWLP_WNDPROC,
                reinterpret_cast<LONG_PTR>(SidebarForwardProc)));
        }
    }
    if (!m_hwndSidebar) return;

    if (!m_hwndFileExplorer) {
        m_hwndFileExplorer = CreateWindowExW(
            0, L"STATIC", L"File Explorer",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            4, 2, w - 8, 18, m_hwndSidebar,
            (HMENU)(UINT_PTR)IDC_FILE_EXPLORER, m_hInstance, nullptr);
    }

    if (!m_hwndFileTree) {
        m_hwndFileTree = CreateWindowExW(
            WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | TVS_HASLINES |
                TVS_LINESATROOT | TVS_HASBUTTONS | TVS_SHOWSELALWAYS,
            4, 22, w - 8, 470, m_hwndSidebar,
            (HMENU)(UINT_PTR)IDC_FILE_TREE, m_hInstance, nullptr);
        if (m_hwndFileTree) {
            SendMessageW(m_hwndFileTree, WM_SETFONT,
                         (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
        }
    }

    refreshFileExplorer();
}

void Win32IDE::refreshFileExplorer() {
    if (!m_hwndFileTree || !IsWindow(m_hwndFileTree)) return;
    SendMessageW(m_hwndFileTree, TVM_DELETEITEM, 0, (LPARAM)TVI_ROOT);

    std::vector<std::string> roots = listWorkspaceRoots();
    if (!m_currentExplorerPath.empty()) roots.push_back(m_currentExplorerPath);
    char cwd[MAX_PATH] = {};
    if (GetCurrentDirectoryA(MAX_PATH, cwd) > 0) roots.emplace_back(cwd);
    // Prefer explicit workspace / cwd only — avoid hard-forcing a mono-repo root
    // that makes project search hang during product UIA.

    std::vector<std::string> uniq;
    for (const auto& r : roots) {
        bool seen = false;
        for (const auto& u : uniq) {
            if (_stricmp(u.c_str(), r.c_str()) == 0) { seen = true; break; }
        }
        if (!seen && !r.empty()) uniq.push_back(r);
    }
    for (const auto& r : uniq) InsertTreeRoot(m_hwndFileTree, r);
}
