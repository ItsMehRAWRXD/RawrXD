// ============================================================================
// ProjectExplorerPanel.hpp - Project Explorer / File Tree Panel
// ============================================================================
// Production-ready project file browser with:
// - Tree view of project files and folders
// - File icons based on extension
// - Context menu (New File, Delete, Rename, etc.)
// - Drag and drop support
// - Git status indicators
// - File watching for auto-refresh
// ============================================================================

#pragma once

#include <Windows.h>
#include <CommCtrl.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace RawrXD {
namespace IDE {

// Forward declarations
struct FileNode;
using FileNodePtr = std::shared_ptr<FileNode>;

// ============================================================================
// File Node Types
// ============================================================================
enum class FileNodeType {
    Root,       // Project root
    Folder,     // Directory
    File,       // Regular file
    Symlink     // Symbolic link
};

// ============================================================================
// File Node Structure
// ============================================================================
struct FileNode {
    std::wstring name;
    std::wstring fullPath;
    FileNodeType type;
    FileNodePtr parent;
    std::vector<FileNodePtr> children;
    
    // UI data
    HTREEITEM treeItem = nullptr;
    int iconIndex = -1;
    bool isExpanded = false;
    bool isSelected = false;
    
    // Git status
    bool isModified = false;
    bool isStaged = false;
    bool isUntracked = false;
    bool isIgnored = false;
    
    // File info
    FILETIME lastWriteTime;
    DWORD fileSize = 0;
    bool isReadOnly = false;
    
    // Methods
    bool IsDirectory() const { return type == FileNodeType::Folder; }
    std::wstring GetExtension() const;
    void SortChildren();
};

// ============================================================================
// Project Explorer Events
// ============================================================================
using FileSelectedCallback = std::function<void(const std::wstring& path)>;
using FileActivatedCallback = std::function<void(const std::wstring& path)>;
using FileContextMenuCallback = std::function<void(const std::wstring& path, POINT pt)>;
using FileDragDropCallback = std::function<void(const std::wstring& src, const std::wstring& dst)>;

// ============================================================================
// Project Explorer Panel
// ============================================================================
class ProjectExplorerPanel {
public:
    ProjectExplorerPanel();
    ~ProjectExplorerPanel();
    
    // Creation/Destruction
    bool Create(HWND hwndParent, HINSTANCE hInstance, 
                int x, int y, int width, int height);
    void Destroy();
    bool IsCreated() const { return hwndPanel_ != nullptr; }
    
    // Project management
    bool OpenProject(const std::wstring& projectPath);
    void CloseProject();
    bool IsProjectOpen() const { return !projectRoot_.empty(); }
    const std::wstring& GetProjectRoot() const { return projectRoot_; }
    
    // File operations
    void Refresh();
    void RefreshNode(FileNodePtr node);
    void ExpandNode(FileNodePtr node);
    void CollapseNode(FileNodePtr node);
    void SelectFile(const std::wstring& path);
    
    // File creation/deletion
    bool CreateNewFile(const std::wstring& parentPath, const std::wstring& filename);
    bool CreateNewFolder(const std::wstring& parentPath, const std::wstring& foldername);
    bool DeleteFile(const std::wstring& path);
    bool RenameFile(const std::wstring& oldPath, const std::wstring& newName);
    
    // Search
    std::vector<FileNodePtr> SearchFiles(const std::wstring& pattern);
    void ShowSearchResults(const std::vector<FileNodePtr>& results);
    void ClearSearch();
    
    // Git integration
    void UpdateGitStatus();
    void SetGitModified(const std::wstring& path, bool modified);
    void SetGitStaged(const std::wstring& path, bool staged);
    void SetGitUntracked(const std::wstring& path, bool untracked);
    
    // Event callbacks
    void SetFileSelectedCallback(FileSelectedCallback callback);
    void SetFileActivatedCallback(FileActivatedCallback callback);
    void SetFileContextMenuCallback(FileContextMenuCallback callback);
    void SetFileDragDropCallback(FileDragDropCallback callback);
    
    // Window handle access
    HWND GetPanelHandle() const { return hwndPanel_; }
    HWND GetTreeHandle() const { return hwndTree_; }
    
    // Visibility
    void Show();
    void Hide();
    bool IsVisible() const;
    void SetWidth(int width);
    int GetWidth() const;
    
private:
    // Window procedures
    static LRESULT CALLBACK PanelWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK TreeSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, 
                                              UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
    
    // Instance handlers
    LRESULT HandlePanelMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleTreeMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    // Tree building
    void BuildTree();
    void BuildNode(FileNodePtr parent, HTREEITEM parentItem);
    HTREEITEM InsertTreeItem(FileNodePtr node, HTREEITEM parent);
    void UpdateTreeItem(FileNodePtr node);
    
    // File system scanning
    FileNodePtr ScanDirectory(const std::wstring& path, FileNodePtr parent);
    void ScanNode(FileNodePtr node);
    
    // Icon management
    void InitializeImageList();
    int GetIconIndex(const std::wstring& path, bool isFolder);
    int GetFileIconIndex(const std::wstring& extension);
    
    // Context menu
    void ShowContextMenu(FileNodePtr node, POINT pt);
    HMENU CreateContextMenu(FileNodePtr node);
    
    // Drag and drop
    void BeginDrag(FileNodePtr node);
    void EndDrag(bool dropped);
    void HandleDrop(FileNodePtr target, POINT pt);
    
    // Utility
    FileNodePtr FindNodeByPath(const std::wstring& path);
    FileNodePtr FindNodeByTreeItem(HTREEITEM item);
    std::wstring GetSelectedPath();
    void SortChildrenRecursive(FileNodePtr node);
    
    // File watching
    void StartFileWatcher();
    void StopFileWatcher();
    static void CALLBACK FileWatcherCallback(DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered,
                                              LPOVERLAPPED lpOverlapped);
    void HandleFileChange();
    
    // Data
    HWND hwndPanel_ = nullptr;
    HWND hwndTree_ = nullptr;
    HWND hwndParent_ = nullptr;
    HINSTANCE hInstance_ = nullptr;
    
    HIMAGELIST hImageList_ = nullptr;
    WNDPROC originalTreeProc_ = nullptr;
    
    FileNodePtr rootNode_;
    std::wstring projectRoot_;
    std::wstring projectName_;
    
    // Event callbacks
    FileSelectedCallback onFileSelected_;
    FileActivatedCallback onFileActivated_;
    FileContextMenuCallback onFileContextMenu_;
    FileDragDropCallback onFileDragDrop_;
    
    // State
    bool isDragging_ = false;
    FileNodePtr dragSource_;
    FileNodePtr selectedNode_;
    
    // File watching
    HANDLE hFileWatcher_ = INVALID_HANDLE_VALUE;
    HANDLE hFileWatcherThread_ = nullptr;
    OVERLAPPED fileWatcherOverlap_;
    BYTE fileWatcherBuffer_[4096];
    bool fileWatcherRunning_ = false;
    
    // Constants
    static constexpr int PANEL_MIN_WIDTH = 150;
    static constexpr int PANEL_MAX_WIDTH = 500;
    static constexpr int ICON_SIZE = 16;
};

// ============================================================================
// Global Access
// ============================================================================

// Get global project explorer instance
ProjectExplorerPanel* GetProjectExplorer();

// Initialize global project explorer
bool InitializeProjectExplorer(HWND hwndParent, HINSTANCE hInstance,
                                int x, int y, int width, int height);

// Shutdown global project explorer
void ShutdownProjectExplorer();

} // namespace IDE
} // namespace RawrXD
