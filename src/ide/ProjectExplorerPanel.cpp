// ============================================================================
// ProjectExplorerPanel.cpp - Project Explorer Implementation
// ============================================================================

#include "ProjectExplorerPanel.hpp"
#include <shlobj.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <algorithm>

#pragma comment(lib, "shlwapi.lib")

namespace RawrXD {
namespace IDE {

// ============================================================================
// Global Instance
// ============================================================================
static ProjectExplorerPanel* g_pProjectExplorer = nullptr;

ProjectExplorerPanel* GetProjectExplorer() {
    return g_pProjectExplorer;
}

bool InitializeProjectExplorer(HWND hwndParent, HINSTANCE hInstance,
                                int x, int y, int width, int height) {
    if (g_pProjectExplorer) return true;
    
    g_pProjectExplorer = new ProjectExplorerPanel();
    if (!g_pProjectExplorer->Create(hwndParent, hInstance, x, y, width, height)) {
        delete g_pProjectExplorer;
        g_pProjectExplorer = nullptr;
        return false;
    }
    return true;
}

void ShutdownProjectExplorer() {
    if (g_pProjectExplorer) {
        delete g_pProjectExplorer;
        g_pProjectExplorer = nullptr;
    }
}

// ============================================================================
// Construction / Destruction
// ============================================================================
ProjectExplorerPanel::ProjectExplorerPanel() = default;

ProjectExplorerPanel::~ProjectExplorerPanel() {
    Destroy();
}

// ============================================================================
// Creation
// ============================================================================
bool ProjectExplorerPanel::Create(HWND hwndParent, HINSTANCE hInstance,
                                   int x, int y, int width, int height) {
    hwndParent_ = hwndParent;
    hInstance_ = hInstance;
    
    // Create panel window
    hwndPanel_ = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        WC_STATICW,
        L"",
        WS_CHILD | WS_VISIBLE | SS_BLACKRECT,
        x, y, width, height,
        hwndParent, nullptr, hInstance, this
    );
    
    if (!hwndPanel_) return false;
    
    // Set window procedure
    SetWindowLongPtrW(hwndPanel_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    
    // Create tree view
    hwndTree_ = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        WC_TREEVIEWW,
        L"",
        WS_CHILD | WS_VISIBLE | TVS_HASBUTTONS | TVS_HASLINES | 
        TVS_LINESATROOT | TVS_SHOWSELALWAYS | TVS_TRACKSELECT,
        0, 0, width, height,
        hwndPanel_, nullptr, hInstance, nullptr
    );
    
    if (!hwndTree_) {
        DestroyWindow(hwndPanel_);
        hwndPanel_ = nullptr;
        return false;
    }
    
    // Initialize image list
    InitializeImageList();
    
    // Subclass tree for custom handling
    originalTreeProc_ = reinterpret_cast<WNDPROC>(
        SetWindowLongPtrW(hwndTree_, GWLP_WNDPROC, 
                         reinterpret_cast<LONG_PTR>(TreeSubclassProc))
    );
    
    // Store this pointer in tree
    SetWindowLongPtrW(hwndTree_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    
    return true;
}

void ProjectExplorerPanel::Destroy() {
    StopFileWatcher();
    
    if (hwndTree_) {
        DestroyWindow(hwndTree_);
        hwndTree_ = nullptr;
    }
    
    if (hwndPanel_) {
        DestroyWindow(hwndPanel_);
        hwndPanel_ = nullptr;
    }
    
    if (hImageList_) {
        ImageList_Destroy(hImageList_);
        hImageList_ = nullptr;
    }
    
    rootNode_.reset();
}

// ============================================================================
// Project Management
// ============================================================================
bool ProjectExplorerPanel::OpenProject(const std::wstring& projectPath) {
    if (!IsCreated()) return false;
    
    // Validate path
    DWORD attrs = GetFileAttributesW(projectPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return false;
    }
    
    CloseProject();
    
    projectRoot_ = projectPath;
    
    // Extract project name
    size_t pos = projectPath.find_last_of(L"\\/");
    projectName_ = (pos != std::wstring::npos) ? projectPath.substr(pos + 1) : projectPath;
    
    // Build tree
    BuildTree();
    
    // Start file watching
    StartFileWatcher();
    
    return true;
}

void ProjectExplorerPanel::CloseProject() {
    StopFileWatcher();
    
    if (hwndTree_) {
        TreeView_DeleteAllItems(hwndTree_);
    }
    
    rootNode_.reset();
    projectRoot_.clear();
    projectName_.clear();
    selectedNode_.reset();
}

// ============================================================================
// Tree Building
// ============================================================================
void ProjectExplorerPanel::BuildTree() {
    if (!hwndTree_ || projectRoot_.empty()) return;
    
    TreeView_DeleteAllItems(hwndTree_);
    
    // Create root node
    rootNode_ = std::make_shared<FileNode>();
    rootNode_->name = projectName_;
    rootNode_->fullPath = projectRoot_;
    rootNode_->type = FileNodeType::Root;
    rootNode_->isExpanded = true;
    
    // Scan and build
    ScanNode(rootNode_);
    
    // Insert into tree
    TVINSERTSTRUCTW tvis = {};
    tvis.hParent = TVI_ROOT;
    tvis.hInsertAfter = TVI_FIRST;
    tvis.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;
    tvis.item.pszText = const_cast<LPWSTR>(rootNode_->name.c_str());
    tvis.item.iImage = GetIconIndex(rootNode_->fullPath, true);
    tvis.item.iSelectedImage = tvis.item.iImage;
    tvis.item.lParam = reinterpret_cast<LPARAM>(rootNode_.get());
    
    HTREEITEM hRoot = TreeView_InsertItem(hwndTree_, &tvis);
    rootNode_->treeItem = hRoot;
    
    // Build children
    BuildNode(rootNode_, hRoot);
    
    // Expand root
    TreeView_Expand(hwndTree_, hRoot, TVE_EXPAND);
}

void ProjectExplorerPanel::BuildNode(FileNodePtr parent, HTREEITEM parentItem) {
    if (!parent || !hwndTree_) return;
    
    for (auto& child : parent->children) {
        InsertTreeItem(child, parentItem);
    }
}

HTREEITEM ProjectExplorerPanel::InsertTreeItem(FileNodePtr node, HTREEITEM parent) {
    if (!hwndTree_) return nullptr;
    
    TVINSERTSTRUCTW tvis = {};
    tvis.hParent = parent;
    tvis.hInsertAfter = TVI_SORT;
    tvis.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;
    tvis.item.pszText = const_cast<LPWSTR>(node->name.c_str());
    tvis.item.iImage = node->iconIndex >= 0 ? node->iconIndex : 
                       GetIconIndex(node->fullPath, node->IsDirectory());
    tvis.item.iSelectedImage = tvis.item.iImage;
    tvis.item.lParam = reinterpret_cast<LPARAM>(node.get());
    
    HTREEITEM hItem = TreeView_InsertItem(hwndTree_, &tvis);
    node->treeItem = hItem;
    
    // If folder and expanded, build children
    if (node->IsDirectory() && node->isExpanded) {
        BuildNode(node, hItem);
        TreeView_Expand(hwndTree_, hItem, TVE_EXPAND);
    }
    
    return hItem;
}

// ============================================================================
// File System Scanning
// ============================================================================
FileNodePtr ProjectExplorerPanel::ScanDirectory(const std::wstring& path, FileNodePtr parent) {
    FileNodePtr node = std::make_shared<FileNode>();
    node->fullPath = path;
    node->parent = parent;
    
    // Get name from path
    size_t pos = path.find_last_of(L"\\/");
    node->name = (pos != std::wstring::npos && pos < path.length() - 1) ? 
                  path.substr(pos + 1) : path;
    
    // Determine type
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
            node->type = FileNodeType::Folder;
        } else {
            node->type = FileNodeType::File;
        }
        node->isReadOnly = (attrs & FILE_ATTRIBUTE_READONLY) != 0;
    }
    
    // Get file info
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW((path + L"\\*").c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring name = findData.cFileName;
            if (name == L"." || name == L"..") continue;
            
            std::wstring childPath = path + L"\\" + name;
            FileNodePtr child = ScanDirectory(childPath, node);
            if (child) {
                node->children.push_back(child);
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    
    // Sort children: folders first, then files
    node->SortChildren();
    
    return node;
}

void ProjectExplorerPanel::ScanNode(FileNodePtr node) {
    if (!node || !node->IsDirectory()) return;
    
    node->children.clear();
    
    WIN32_FIND_DATAW findData;
    std::wstring searchPath = node->fullPath + L"\\*";
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring name = findData.cFileName;
            if (name == L"." || name == L"..") continue;
            
            // Skip hidden files
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) continue;
            
            std::wstring childPath = node->fullPath + L"\\" + name;
            
            FileNodePtr child = std::make_shared<FileNode>();
            child->name = name;
            child->fullPath = childPath;
            child->parent = node;
            child->lastWriteTime = findData.ftLastWriteTime;
            child->fileSize = (findData.nFileSizeHigh * (MAXDWORD + 1)) + findData.nFileSizeLow;
            
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                child->type = FileNodeType::Folder;
            } else {
                child->type = FileNodeType::File;
            }
            
            child->isReadOnly = (findData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0;
            child->iconIndex = GetIconIndex(childPath, child->IsDirectory());
            
            node->children.push_back(child);
            
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    
    node->SortChildren();
}

// ============================================================================
// Icon Management
// ============================================================================
void ProjectExplorerPanel::InitializeImageList() {
    if (!hwndTree_) return;
    
    hImageList_ = ImageList_Create(ICON_SIZE, ICON_SIZE, ILC_COLOR32 | ILC_MASK, 10, 10);
    if (!hImageList_) return;
    
    // Add default icons
    HICON hFolder = LoadIconW(nullptr, IDI_FOLDER);
    HICON hFile = LoadIconW(nullptr, IDI_APPLICATION);
    
    ImageList_AddIcon(hImageList_, hFolder);
    ImageList_AddIcon(hImageList_, hFile);
    
    TreeView_SetImageList(hwndTree_, hImageList_, TVSIL_NORMAL);
}

int ProjectExplorerPanel::GetIconIndex(const std::wstring& path, bool isFolder) {
    if (!hImageList_) return isFolder ? 0 : 1;
    
    SHFILEINFOW sfi = {};
    UINT flags = SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES;
    
    if (isFolder) {
        flags |= SHGFI_ADDOVERLAYS;
    }
    
    DWORD attrs = isFolder ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    
    if (SHGetFileInfoW(path.c_str(), attrs, &sfi, sizeof(sfi), flags)) {
        int index = ImageList_AddIcon(hImageList_, sfi.hIcon);
        DestroyIcon(sfi.hIcon);
        return index;
    }
    
    return isFolder ? 0 : 1;
}

// ============================================================================
// Event Callbacks
// ============================================================================
void ProjectExplorerPanel::SetFileSelectedCallback(FileSelectedCallback callback) {
    onFileSelected_ = callback;
}

void ProjectExplorerPanel::SetFileActivatedCallback(FileActivatedCallback callback) {
    onFileActivated_ = callback;
}

void ProjectExplorerPanel::SetFileContextMenuCallback(FileContextMenuCallback callback) {
    onFileContextMenu_ = callback;
}

void ProjectExplorerPanel::SetFileDragDropCallback(FileDragDropCallback callback) {
    onFileDragDrop_ = callback;
}

// ============================================================================
// Tree Subclass Procedure
// ============================================================================
LRESULT CALLBACK ProjectExplorerPanel::TreeSubclassProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    
    auto* panel = reinterpret_cast<ProjectExplorerPanel*>(dwRefData);
    if (panel) {
        return panel->HandleTreeMessage(hwnd, msg, wParam, lParam);
    }
    
    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

LRESULT ProjectExplorerPanel::HandleTreeMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_LBUTTONDBLCLK: {
            // File activation on double click
            HTREEITEM hItem = TreeView_GetSelection(hwnd);
            if (hItem && onFileActivated_) {
                TVITEMW tvi = {};
                tvi.mask = TVIF_PARAM;
                tvi.hItem = hItem;
                if (TreeView_GetItem(hwnd, &tvi)) {
                    auto* node = reinterpret_cast<FileNode*>(tvi.lParam);
                    if (node && !node->IsDirectory()) {
                        onFileActivated_(node->fullPath);
                    }
                }
            }
            break;
        }
        
        case WM_RBUTTONDOWN: {
            // Context menu on right click
            TVHITTESTINFO ht = {};
            ht.pt.x = GET_X_LPARAM(lParam);
            ht.pt.y = GET_Y_LPARAM(lParam);
            ClientToScreen(hwnd, &ht.pt);
            ScreenToClient(hwnd, &ht.pt);
            
            TreeView_HitTest(hwnd, &ht);
            if (ht.hItem) {
                TreeView_SelectItem(hwnd, ht.hItem);
                
                if (onFileContextMenu_) {
                    POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                    ClientToScreen(hwnd, &pt);
                    
                    TVITEMW tvi = {};
                    tvi.mask = TVIF_PARAM;
                    tvi.hItem = ht.hItem;
                    if (TreeView_GetItem(hwnd, &tvi)) {
                        auto* node = reinterpret_cast<FileNode*>(tvi.lParam);
                        if (node) {
                            onFileContextMenu_(node->fullPath, pt);
                        }
                    }
                }
            }
            return 0;
        }
        
        case TVM_SELCHANGED: {
            // Selection changed
            NMTREEVIEWW* pnmtv = reinterpret_cast<NMTREEVIEWW*>(lParam);
            if (pnmtv && onFileSelected_) {
                auto* node = reinterpret_cast<FileNode*>(pnmtv->itemNew.lParam);
                if (node) {
                    selectedNode_ = node->shared_from_this();
                    onFileSelected_(node->fullPath);
                }
            }
            break;
        }
    }
    
    if (originalTreeProc_) {
        return CallWindowProcW(originalTreeProc_, hwnd, msg, wParam, lParam);
    }
    
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ============================================================================
// Utility Functions
// ============================================================================
void FileNode::SortChildren() {
    std::sort(children.begin(), children.end(),
        [](const FileNodePtr& a, const FileNodePtr& b) {
            // Folders first
            if (a->IsDirectory() != b->IsDirectory()) {
                return a->IsDirectory() > b->IsDirectory();
            }
            // Then alphabetical
            return _wcsicmp(a->name.c_str(), b->name.c_str()) < 0;
        });
}

std::wstring FileNode::GetExtension() const {
    size_t dot = name.find_last_of(L'.');
    if (dot != std::wstring::npos && dot < name.length() - 1) {
        return name.substr(dot + 1);
    }
    return L"";
}

// ============================================================================
// File Watching (Stub - would use ReadDirectoryChangesW)
// ============================================================================
void ProjectExplorerPanel::StartFileWatcher() {
    // TODO: Implement file system change watching
    // This would use ReadDirectoryChangesW with OVERLAPPED I/O
}

void ProjectExplorerPanel::StopFileWatcher() {
    fileWatcherRunning_ = false;
    
    if (hFileWatcher_ != INVALID_HANDLE_VALUE) {
        CancelIoEx(hFileWatcher_, &fileWatcherOverlap_);
        CloseHandle(hFileWatcher_);
        hFileWatcher_ = INVALID_HANDLE_VALUE;
    }
    
    if (hFileWatcherThread_) {
        WaitForSingleObject(hFileWatcherThread_, 1000);
        CloseHandle(hFileWatcherThread_);
        hFileWatcherThread_ = nullptr;
    }
}

void CALLBACK ProjectExplorerPanel::FileWatcherCallback(
    DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered,
    LPOVERLAPPED lpOverlapped) {
    // TODO: Handle file change notification
}

void ProjectExplorerPanel::HandleFileChange() {
    // Refresh affected nodes
    Refresh();
}

// ============================================================================
// Visibility
// ============================================================================
void ProjectExplorerPanel::Show() {
    if (hwndPanel_) ShowWindow(hwndPanel_, SW_SHOW);
}

void ProjectExplorerPanel::Hide() {
    if (hwndPanel_) ShowWindow(hwndPanel_, SW_HIDE);
}

bool ProjectExplorerPanel::IsVisible() const {
    return hwndPanel_ && IsWindowVisible(hwndPanel_);
}

void ProjectExplorerPanel::SetWidth(int width) {
    if (!hwndPanel_) return;
    
    RECT rc;
    GetWindowRect(hwndPanel_, &rc);
    int height = rc.bottom - rc.top;
    
    SetWindowPos(hwndPanel_, nullptr, 0, 0, width, height,
                 SWP_NOMOVE | SWP_NOZORDER);
    
    // Resize tree to fill panel
    if (hwndTree_) {
        SetWindowPos(hwndTree_, nullptr, 0, 0, width - 4, height - 4,
                     SWP_NOMOVE | SWP_NOZORDER);
    }
}

int ProjectExplorerPanel::GetWidth() const {
    if (!hwndPanel_) return 0;
    
    RECT rc;
    GetWindowRect(hwndPanel_, &rc);
    return rc.right - rc.left;
}

} // namespace IDE
} // namespace RawrXD
