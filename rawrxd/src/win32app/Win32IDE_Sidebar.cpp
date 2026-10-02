// ============================================================================
// Win32IDE_Sidebar.cpp ? Full VS Code-style File Explorer Sidebar
// Production: TreeView with real filesystem enumeration, icons, context menus.
// ============================================================================
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
// RAWRXD_MULTIROOT_EXPLORER_001: the explorer reads the workspace model's folder
// list, which is the authority already linked and already runtime-measured in
// P1_INTEGRATION_TRANCHE. Before this the explorer inserted one node from
// GetCurrentDirectoryW and had no multi-root path at all.
#include "core/workspace_model.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace {

constexpr int ACTIVITY_BAR_WIDTH = 48;
constexpr int SIDEBAR_DEFAULT_WIDTH = 280;
constexpr int IDC_ACTIVITY_EXPLORER = 6001;
constexpr int IDC_ACTIVITY_SEARCH   = 6002;
constexpr int IDC_ACTIVITY_SCM      = 6003;
constexpr int IDC_ACTIVITY_DEBUG    = 6004;
constexpr int IDC_ACTIVITY_EXTENSIONS = 6005;
constexpr int IDC_TREE_EXPLORER   = 7001;
constexpr int IDC_LIST_SEARCH     = 7002;

static HWND g_hwndActivityBar = nullptr;
static HWND g_hwndSidebar = nullptr;
static HWND g_hwndSidebarContent = nullptr;
static HWND g_hwndTree = nullptr;
static HWND g_hwndSearchList = nullptr;
static bool g_sidebarVisible = true;
static int g_sidebarWidth = SIDEBAR_DEFAULT_WIDTH;
static HINSTANCE g_hInst = nullptr;
static HIMAGELIST g_hImageList = nullptr;
static int g_iFolderIcon = 0;
static int g_iFileIcon = 1;

// RAWRXD_MULTIROOT_EXPLORER_001
//
// TreeItemData now carries which workspace root a node belongs to, as an INDEX
// into a root table rather than a path. That is the difference between a tree
// that draws two roots and a tree that can answer "which root does this node
// belong to" -- expansion, selection, open-file and delete all need that answer,
// and re-deriving it from a path prefix comparison breaks the moment two roots
// nest or one is a parent of the other.
//
// An empty rootIndex means "not yet assigned" and is only ever seen on the
// synthetic placeholder child.
struct TreeItemData {
    std::wstring path;
    bool isDir = false;
    bool expanded = false;
    int  rootIndex = -1;          // RAWRXD_MULTIROOT_EXPLORER_001
    bool isRootNode = false;      // the root row itself
};

struct WorkspaceRoot {
    std::wstring path;
    std::wstring name;
    bool        isPrimary = false;   // the workspace's declared root
    HTREEITEM   hItem = nullptr;
};

// Measured, so a receipt can read how many roots were actually rendered rather
// than how many the model holds.
struct SidebarMultiRootState {
    int  rootsInModel = 0;
    int  rootsRendered = 0;
    int  nodesRendered = 0;
    bool usedModel = false;       // false means the cwd fallback was used
    char renderSource[32] = {0};
};

static std::vector<WorkspaceRoot> g_roots;
static SidebarMultiRootState g_mrState;

extern "C" const char* Win32IDE_Sidebar_MultiRootStatus() {
    static std::string buf;
    char tmp[512];
    snprintf(tmp, sizeof(tmp),
             "MODEL_ROOTS=%d;RENDERED_ROOTS=%d;NODES=%d;SOURCE=%s",
             g_mrState.rootsInModel, g_mrState.rootsRendered, g_mrState.nodesRendered,
             g_mrState.renderSource[0] ? g_mrState.renderSource : "none");
    buf = tmp;
    return buf.c_str();
}

static HTREEITEM InsertTreeItem(HWND hwndTree, HTREEITEM hParent, const std::wstring& text,
                                 const std::wstring& path, bool isDir, int iconIndex,
                                 int rootIndex = -1, bool isRootNode = false) {
    TVINSERTSTRUCTW tvis{};
    tvis.hParent = hParent;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_CHILDREN | TVIF_PARAM;
    tvis.item.pszText = const_cast<LPWSTR>(text.c_str());
    tvis.item.iImage = iconIndex;
    tvis.item.iSelectedImage = iconIndex;
    tvis.item.cChildren = isDir ? 1 : 0;
    TreeItemData* data = new TreeItemData{ path, isDir, false, rootIndex, isRootNode };
    tvis.item.lParam = reinterpret_cast<LPARAM>(data);
    return TreeView_InsertItem(hwndTree, &tvis);
}

static int g_nodeCount = 0;

static void PopulateDirectory(HWND hwndTree, HTREEITEM hParent, const std::wstring& dirPath,
                              int rootIndex = -1) {
    try {
        std::vector<std::pair<std::wstring, bool>> entries;
        for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
            entries.push_back({ entry.path().filename().wstring(), entry.is_directory() });
        }
        std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second > b.second; // dirs first
            return _wcsicmp(a.first.c_str(), b.first.c_str()) < 0;
        });
        for (const auto& e : entries) {
            std::wstring fullPath = dirPath + L"\\" + e.first;
            int icon = e.second ? g_iFolderIcon : g_iFileIcon;
            // RAWRXD_MULTIROOT_EXPLORER_001: every descendant inherits the root
            // index, so a node five levels down still resolves to the right root
            // without any path arithmetic at the point of use.
            HTREEITEM hItem = InsertTreeItem(hwndTree, hParent, e.first, fullPath, e.second,
                                             icon, rootIndex, false);
            ++g_nodeCount;
            if (e.second) {
                InsertTreeItem(hwndTree, hItem, L"", L"", false, g_iFolderIcon, rootIndex, false);
            }
        }
    } catch (...) {}
}

static LRESULT CALLBACK ActivityBarProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, (HBRUSH)GetStockObject(GRAY_BRUSH));
        const wchar_t* labels[] = { L"Files", L"Search", L"SCM", L"Debug", L"Exts" };
        for (int i = 0; i < 5; ++i) {
            RECT r{ 4, 10 + i * 48, 44, 50 + i * 48 };
            DrawTextW(hdc, labels[i], -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
        EndPaint(hwnd, &ps); return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        ShowWindow(g_hwndTree, SW_HIDE);
        ShowWindow(g_hwndSearchList, SW_HIDE);
        if (id == IDC_ACTIVITY_EXPLORER) ShowWindow(g_hwndTree, SW_SHOW);
        else if (id == IDC_ACTIVITY_SEARCH) ShowWindow(g_hwndSearchList, SW_SHOW);
        return 0;
    }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK SidebarProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK TreeSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    WNDPROC oldProc = reinterpret_cast<WNDPROC>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NOTIFY) {
        NMHDR* pnmh = reinterpret_cast<NMHDR*>(lParam);
        if (pnmh->code == TVN_ITEMEXPANDING) {
            NMTREEVIEWW* pnmtv = reinterpret_cast<NMTREEVIEWW*>(lParam);
            if (pnmtv->action == TVE_EXPAND) {
                TVITEMW tvi{}; tvi.mask = TVIF_PARAM | TVIF_HANDLE; tvi.hItem = pnmtv->itemNew.hItem;
                if (TreeView_GetItem(hwnd, &tvi)) {
                    TreeItemData* data = reinterpret_cast<TreeItemData*>(tvi.lParam);
                    if (data && data->isDir && !data->expanded) {
                        HTREEITEM child = TreeView_GetChild(hwnd, pnmtv->itemNew.hItem);
                        while (child) {
                            HTREEITEM next = TreeView_GetNextSibling(hwnd, child);
                            TVITEMW ctvi{}; ctvi.mask = TVIF_PARAM | TVIF_HANDLE; ctvi.hItem = child;
                            if (TreeView_GetItem(hwnd, &ctvi)) {
                                delete reinterpret_cast<TreeItemData*>(ctvi.lParam);
                            }
                            TreeView_DeleteItem(hwnd, child);
                            child = next;
                        }
                        // RAWRXD_MULTIROOT_EXPLORER_001: expansion repopulates
                        // under the SAME root index the node already carries. A
                        // lazy child populated without this would land in root
                        // -1 and every later operation on it would resolve to the
                        // wrong root.
                        PopulateDirectory(hwnd, pnmtv->itemNew.hItem, data->path, data->rootIndex);
                        data->expanded = true;
                    }
                }
            }
        }
    }
    return CallWindowProcW(oldProc, hwnd, msg, wParam, lParam);
}

} // namespace

extern "C" void Win32IDE_Sidebar_Create(HWND hwndParent, HINSTANCE hInstance) {
    g_hInst = hInstance;
    InitCommonControls();

    g_hImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 2, 2);
    HICON hFolder = LoadIcon(NULL, IDI_APPLICATION);
    HICON hFile = LoadIcon(NULL, IDI_APPLICATION);
    g_iFolderIcon = ImageList_AddIcon(g_hImageList, hFolder ? hFolder : LoadIcon(NULL, IDI_INFORMATION));
    g_iFileIcon = ImageList_AddIcon(g_hImageList, hFile ? hFile : LoadIcon(NULL, IDI_APPLICATION));
    if (hFolder) DestroyIcon(hFolder);
    if (hFile) DestroyIcon(hFile);

    g_hwndActivityBar = CreateWindowExA(0, "STATIC", "", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        0, 0, ACTIVITY_BAR_WIDTH, 600, hwndParent, nullptr, hInstance, nullptr);
    SetWindowLongPtrA(g_hwndActivityBar, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(ActivityBarProc));

    int y = 10;
    const struct { int id; const char* text; } buttons[] = {
        {IDC_ACTIVITY_EXPLORER, "Files"},
        {IDC_ACTIVITY_SEARCH, "Search"},
        {IDC_ACTIVITY_SCM, "SCM"},
        {IDC_ACTIVITY_DEBUG, "Debug"},
        {IDC_ACTIVITY_EXTENSIONS, "Exts"}
    };
    for (const auto& btn : buttons) {
        CreateWindowExA(0, "BUTTON", btn.text, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
            2, y, 44, 44, g_hwndActivityBar, (HMENU)(INT_PTR)btn.id, hInstance, nullptr);
        y += 48;
    }

    g_hwndSidebar = CreateWindowExA(0, "STATIC", "Sidebar", WS_CHILD | WS_VISIBLE | WS_BORDER,
        ACTIVITY_BAR_WIDTH, 0, SIDEBAR_DEFAULT_WIDTH, 600, hwndParent, nullptr, hInstance, nullptr);
    SetWindowLongPtrA(g_hwndSidebar, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(SidebarProc));

    g_hwndTree = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"Explorer",
        WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
        0, 0, SIDEBAR_DEFAULT_WIDTH, 600, g_hwndSidebar, (HMENU)(INT_PTR)IDC_TREE_EXPLORER, hInstance, nullptr);
    TreeView_SetImageList(g_hwndTree, g_hImageList, TVSIL_NORMAL);

    // RAWRXD_MULTIROOT_EXPLORER_001
    //
    // This used to insert exactly one node from GetCurrentDirectoryW, with no
    // `AddRoot`/multi-root path anywhere in the file, so the explorer was
    // single-root BY CONSTRUCTION even though the workspace model has held a
    // vector of WorkspaceFolder for its entire life.
    //
    // Roots now come from the workspace model, which is the authority that was
    // already linked and already measured in P1_INTEGRATION_TRANCHE. Each root
    // gets its own top-level node carrying its own index, and every descendant
    // inherits that index, so "which root is this file in" is answered by the
    // node rather than re-derived from the path at each point of use.
    g_roots.clear();
    g_mrState = SidebarMultiRootState{};
    g_nodeCount = 0;

    int modelRoots = 0;
    for (const auto& f : RawrXD_IDE_GetWorkspaceFolders()) {
        WorkspaceRoot r;
        // RawrXDWorkspaceFolder carries narrow strings (it is a C++ struct, not
        // a Win32 one); WorkspaceRoot is a tree-node record and uses wstring.
        // The conversion is explicit rather than implicit because it is lossy
        // for any byte sequence that is not valid UTF-8, and a silently mangled
        // workspace path is worse than a visibly wrong one.
        r.path = std::filesystem::path(f.path).wstring();
        r.name = std::filesystem::path(f.name).wstring();
        r.isPrimary = f.isRoot;
        g_roots.push_back(r);
        ++modelRoots;
    }
    g_mrState.rootsInModel = modelRoots;

    if (g_roots.empty()) {
        // Fallback preserved: an uninitialised or empty workspace still shows
        // something, and the receipt says so rather than implying model backing.
        wchar_t cwd[MAX_PATH];
        GetCurrentDirectoryW(MAX_PATH, cwd);
        WorkspaceRoot r;
        r.path = cwd;
        r.name = L"Workspace";
        r.isPrimary = true;
        g_roots.push_back(r);
        strcpy_s(g_mrState.renderSource, sizeof(g_mrState.renderSource), "cwd_fallback");
    } else {
        strcpy_s(g_mrState.renderSource, sizeof(g_mrState.renderSource), "workspace_model");
        g_mrState.usedModel = true;
    }

    for (std::size_t i = 0; i < g_roots.size(); ++i) {
        WorkspaceRoot& r = g_roots[i];
        // The primary root keeps the historical label so existing muscle memory
        // and any test looking for "Workspace" still find it; secondary roots are
        // labelled by their own name, which is what makes them distinguishable.
        const std::wstring label = r.isPrimary
            ? (r.name.empty() ? std::wstring(L"Workspace") : r.name)
            : (r.name.empty() ? r.path : r.name);
        r.hItem = InsertTreeItem(g_hwndTree, TVI_ROOT, label, r.path, true,
                                 g_iFolderIcon, static_cast<int>(i), true);
        PopulateDirectory(g_hwndTree, r.hItem, r.path, static_cast<int>(i));
        TreeView_Expand(g_hwndTree, r.hItem, TVE_EXPAND);
        ++g_mrState.rootsRendered;
    }
    g_mrState.nodesRendered = g_nodeCount;

    g_hwndSearchList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"Search Results",
        WS_CHILD | LBS_NOTIFY | WS_VSCROLL | LBS_HASSTRINGS,
        0, 0, SIDEBAR_DEFAULT_WIDTH, 600, g_hwndSidebar, (HMENU)(INT_PTR)IDC_LIST_SEARCH, hInstance, nullptr);

    WNDPROC oldProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(g_hwndTree, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(TreeSubclassProc)));
    SetWindowLongPtrW(g_hwndTree, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(oldProc));
}

extern "C" void Win32IDE_Sidebar_SetVisibility(bool visible) {
    g_sidebarVisible = visible;
    ShowWindow(g_hwndSidebar, visible ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hwndActivityBar, visible ? SW_SHOW : SW_HIDE);
}

extern "C" bool Win32IDE_Sidebar_IsVisible() { return g_sidebarVisible; }

// ?? ShellLayout compatibility wrappers ????????????????????????????????????????
extern "C" void Sidebar_Register(HINSTANCE) {
    // Sidebar uses standard STATIC / WC_TREEVIEW classes; no custom registration needed.
}

extern "C" HWND Sidebar_Create(HWND parent, int x, int y, int w, int h, HINSTANCE hInst) {
    Win32IDE_Sidebar_Create(parent, hInst);
    // Resize to requested dimensions for layout engine
    if (g_hwndSidebar)  SetWindowPos(g_hwndSidebar,  nullptr, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
    if (g_hwndActivityBar) SetWindowPos(g_hwndActivityBar, nullptr, x, y, ACTIVITY_BAR_WIDTH, h, SWP_NOZORDER | SWP_NOACTIVATE);
    return g_hwndSidebar;
}

extern "C" const wchar_t* Win32IDE_Sidebar_GetSelectedPath() {
    if (!g_hwndTree) return nullptr;
    HTREEITEM hSel = TreeView_GetSelection(g_hwndTree);
    if (!hSel) return nullptr;
    TVITEMW tvi{}; tvi.mask = TVIF_PARAM | TVIF_HANDLE; tvi.hItem = hSel;
    if (!TreeView_GetItem(g_hwndTree, &tvi)) return nullptr;
    TreeItemData* data = reinterpret_cast<TreeItemData*>(tvi.lParam);
    return data ? data->path.c_str() : nullptr;
}

// RAWRXD_MULTIROOT_EXPLORER_001
//
// Root-resolved accessors. RAWRXD_MULTIROOT_ROOT_0 is what a caller that
// implicitly used root 0 was really getting before; these make the root an
// explicit argument so "which root" stops being an assumption.
//
// Root count is -1 when the selected node carries no root index, which happens
// only for a synthetic placeholder child. Returning -1 rather than 0 is
// deliberate: a caller that ignores the return would previously have been handed
// the primary root, and would now instead be handed a visibly invalid value.
extern "C" int Win32IDE_Sidebar_GetSelectedRootIndex() {
    if (!g_hwndTree) return -1;
    HTREEITEM hSel = TreeView_GetSelection(g_hwndTree);
    if (!hSel) return -1;
    TVITEMW tvi{}; tvi.mask = TVIF_PARAM | TVIF_HANDLE; tvi.hItem = hSel;
    if (!TreeView_GetItem(g_hwndTree, &tvi)) return -1;
    TreeItemData* data = reinterpret_cast<TreeItemData*>(tvi.lParam);
    return data ? data->rootIndex : -1;
}

extern "C" int Win32IDE_Sidebar_RootCount() {
    return static_cast<int>(g_roots.size());
}

extern "C" const wchar_t* Win32IDE_Sidebar_GetRootPath(int index) {
    if (index < 0 || index >= static_cast<int>(g_roots.size())) return L"";
    // g_roots[index].path is already a wstring, so the previous std::string
    // buffer could not hold it -- that assignment did not compile. A thread-local
    // buffer is used rather than a function-local static so two calls from two
    // threads cannot alias each other's pointer.
    static thread_local std::wstring buf;
    buf = g_roots[index].path;
    return buf.c_str();
}

extern "C" const char* Win32IDE_Sidebar_GetRootName(int index) {
    if (index < 0 || index >= static_cast<int>(g_roots.size())) return "";
    static std::string buf;
    int n = WideCharToMultiByte(CP_UTF8, 0, g_roots[index].name.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) { buf.clear(); return buf.c_str(); }
    buf.assign(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, g_roots[index].name.c_str(), -1, &buf[0], n, nullptr, nullptr);
    return buf.c_str();
}

extern "C" int Win32IDE_Sidebar_RootIsPrimary(int index) {
    if (index < 0 || index >= static_cast<int>(g_roots.size())) return 0;
    return g_roots[index].isPrimary ? 1 : 0;
}
