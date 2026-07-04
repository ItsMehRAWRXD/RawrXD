#include "RawrXD_FileBrowser.h"
#include <commctrl.h>
#include <shlwapi.h>
#include <vector>
#include <algorithm>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")

namespace RawrXD {
namespace GUI {

static const wchar_t* FILEBROWSER_CLASS = L"RawrXD_FileBrowser";
static bool s_classRegistered = false;

FileBrowser::FileBrowser() = default;

FileBrowser::~FileBrowser() {
    if (m_hImageList) {
        ImageList_Destroy(m_hImageList);
    }
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
    }
}

bool FileBrowser::Create(HWND parentHwnd, HINSTANCE hInstance, int x, int y, int width, int height) {
    if (!s_classRegistered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = FileBrowser::WndProc;
        wc.hInstance = hInstance;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = FILEBROWSER_CLASS;
        
        if (!RegisterClassExW(&wc)) {
            return false;
        }
        s_classRegistered = true;
    }
    
    m_hwnd = CreateWindowExW(
        WS_EX_CONTROLPARENT,
        FILEBROWSER_CLASS,
        L"File Browser",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, width, height,
        parentHwnd,
        nullptr,
        hInstance,
        this
    );
    
    return m_hwnd != nullptr;
}

void FileBrowser::SetRootPath(const std::string& path) {
    m_rootPath = path;
    if (m_hwndPathBar) {
        SetWindowTextA(m_hwndPathBar, path.c_str());
    }
    PopulateTree();
}

std::string FileBrowser::GetSelectedFile() const {
    return m_selectedFile;
}

void FileBrowser::OnFileSelected(std::function<void(const std::string&)> callback) {
    m_onFileSelected = callback;
}

void FileBrowser::Refresh() {
    PopulateTree();
}

LRESULT CALLBACK FileBrowser::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    FileBrowser* pThis = nullptr;
    
    if (msg == WM_CREATE) {
        LPCREATESTRUCT lpcs = reinterpret_cast<LPCREATESTRUCT>(lParam);
        pThis = reinterpret_cast<FileBrowser*>(lpcs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        pThis->m_hwnd = hwnd;
        pThis->OnCreate();
        return 0;
    }
    
    pThis = reinterpret_cast<FileBrowser*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    if (pThis) {
        return pThis->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT FileBrowser::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SIZE:
            OnSize(LOWORD(lParam), HIWORD(lParam));
            return 0;
            
        case WM_COMMAND:
            OnCommand(wParam, lParam);
            return 0;
            
        case WM_NOTIFY:
            OnNotify(lParam);
            return 0;
            
        case WM_DESTROY:
            m_hwnd = nullptr;
            return 0;
    }
    
    return DefWindowProc(m_hwnd, msg, wParam, lParam);
}

void FileBrowser::OnCreate() {
    HINSTANCE hInst = GetModuleHandle(nullptr);
    
    // Path bar
    m_hwndPathBar = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_READONLY | WS_BORDER,
        PADDING, PADDING, 200, PATHBAR_HEIGHT,
        m_hwnd, nullptr, hInst, nullptr);
    
    // Refresh button
    m_hwndRefreshBtn = CreateWindowW(L"BUTTON", L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        210, PADDING, 60, PATHBAR_HEIGHT,
        m_hwnd, (HMENU)2001, hInst, nullptr);
    
    // Tree view
    m_hwndTree = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
        WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_LINESATROOT | 
        TVS_HASBUTTONS | TVS_SHOWSELALWAYS | TVS_TRACKSELECT,
        PADDING, PADDING + PATHBAR_HEIGHT + PADDING, 300, 400,
        m_hwnd, (HMENU)2002, hInst, nullptr);
    
    // Create image list for icons
    m_hImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 2, 0);
    
    // Add folder and file icons (using system icons)
    HICON hFolder = LoadIcon(nullptr, IDI_APPLICATION);  // Placeholder
    HICON hFile = LoadIcon(nullptr, IDI_INFORMATION);   // Placeholder
    ImageList_AddIcon(m_hImageList, hFolder);
    ImageList_AddIcon(m_hImageList, hFile);
    
    TreeView_SetImageList(m_hwndTree, m_hImageList, TVSIL_NORMAL);
    
    // Set default root
    SetRootPath(".");
}

void FileBrowser::OnSize(int width, int height) {
    if (width < 50 || height < 50) return;
    
    int contentWidth = width - (PADDING * 2);
    
    // Path bar
    SetWindowPos(m_hwndPathBar, nullptr,
        PADDING, PADDING, contentWidth - 70, PATHBAR_HEIGHT,
        SWP_NOZORDER);
    
    // Refresh button
    SetWindowPos(m_hwndRefreshBtn, nullptr,
        width - PADDING - 60, PADDING, 60, PATHBAR_HEIGHT,
        SWP_NOZORDER);
    
    // Tree view fills rest
    int treeTop = PADDING + PATHBAR_HEIGHT + PADDING;
    SetWindowPos(m_hwndTree, nullptr,
        PADDING, treeTop, contentWidth, height - treeTop - PADDING,
        SWP_NOZORDER);
}

void FileBrowser::OnCommand(WPARAM wParam, LPARAM lParam) {
    int id = LOWORD(wParam);
    
    switch (id) {
        case 2001:  // Refresh
            Refresh();
            break;
    }
}

void FileBrowser::OnNotify(LPARAM lParam) {
    LPNMHDR pnmh = reinterpret_cast<LPNMHDR>(lParam);
    
    if (pnmh->idFrom == 2002) {  // Tree view
        switch (pnmh->code) {
            case TVN_SELCHANGED:
                OnItemSelected();
                break;
                
            case TVN_ITEMEXPANDING:
                // Auto-expand on click
                break;
                
            case NM_DBLCLK:
                OnItemDoubleClick();
                break;
        }
    }
}

void FileBrowser::PopulateTree() {
    TreeView_DeleteAllItems(m_hwndTree);
    
    if (m_rootPath.empty()) return;
    
    auto items = ScanDirectory(m_rootPath);
    
    // Sort: directories first, then alphabetically
    std::sort(items.begin(), items.end(), [](const FileItem& a, const FileItem& b) {
        if (a.isDirectory != b.isDirectory) return a.isDirectory > b.isDirectory;
        return a.name < b.name;
    });
    
    for (const auto& item : items) {
        AddTreeItem(TVI_ROOT, item.name, item.isDirectory, item.fullPath);
    }
}

void FileBrowser::OnItemSelected() {
    HTREEITEM hItem = TreeView_GetSelection(m_hwndTree);
    if (!hItem) return;
    
    TVITEMEX item = {};
    item.mask = TVIF_PARAM | TVIF_TEXT;
    item.hItem = hItem;
    char text[MAX_PATH];
    item.pszText = text;
    item.cchTextMax = MAX_PATH;
    
    if (TreeView_GetItem(m_hwndTree, &item)) {
        m_selectedFile = reinterpret_cast<char*>(item.lParam);
        
        if (m_onFileSelected) {
            m_onFileSelected(m_selectedFile);
        }
    }
}

void FileBrowser::OnItemDoubleClick() {
    HTREEITEM hItem = TreeView_GetSelection(m_hwndTree);
    if (!hItem) return;
    
    TVITEMEX item = {};
    item.mask = TVIF_PARAM;
    item.hItem = hItem;
    
    if (TreeView_GetItem(m_hwndTree, &item)) {
        std::string path = reinterpret_cast<char*>(item.lParam);
        
        // Check if directory
        DWORD attrs = GetFileAttributesA(path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            SetRootPath(path);
        }
    }
}

std::vector<FileItem> FileBrowser::ScanDirectory(const std::string& path) {
    std::vector<FileItem> items;
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA((path + "\\*").c_str(), &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::string name = findData.cFileName;
            if (name == "." || name == "..") continue;
            
            FileItem item;
            item.name = name;
            item.fullPath = path + "\\" + name;
            item.isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            item.lastModified = findData.ftLastWriteTime;
            item.fileSize = (findData.nFileSizeHigh * (MAXDWORD + 1)) + findData.nFileSizeLow;
            
            items.push_back(item);
        } while (FindNextFileA(hFind, &findData));
        
        FindClose(hFind);
    }
    
    return items;
}

HTREEITEM FileBrowser::AddTreeItem(HTREEITEM parent, const std::string& text, bool isDir, const std::string& fullPath) {
    TVINSERTSTRUCTA tvis = {};
    tvis.hParent = parent;
    tvis.hInsertAfter = TVI_SORT;
    tvis.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;
    tvis.item.pszText = const_cast<char*>(text.c_str());
    tvis.item.iImage = isDir ? 0 : 1;
    tvis.item.iSelectedImage = isDir ? 0 : 1;
    
    // Store full path in lParam (need to allocate)
    char* pathCopy = new char[fullPath.length() + 1];
    strcpy_s(pathCopy, fullPath.length() + 1, fullPath.c_str());
    tvis.item.lParam = reinterpret_cast<LPARAM>(pathCopy);
    
    return TreeView_InsertItem(m_hwndTree, &tvis);
}

} // namespace GUI
} // namespace RawrXD
