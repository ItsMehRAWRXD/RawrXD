#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
namespace GUI {

// File/Folder item
struct FileItem {
    std::string name;
    std::string fullPath;
    bool isDirectory;
    bool isSelected;
    FILETIME lastModified;
    DWORD fileSize;
};

// File browser with tree view
class FileBrowser {
public:
    FileBrowser();
    ~FileBrowser();

    // Create the file browser window
    bool Create(HWND parentHwnd, HINSTANCE hInstance, int x, int y, int width, int height);
    
    // Set root directory
    void SetRootPath(const std::string& path);
    
    // Get selected file
    std::string GetSelectedFile() const;
    
    // Set callback for file selection
    void OnFileSelected(std::function<void(const std::string&)> callback);
    
    // Refresh the view
    void Refresh();
    
    // Get native HWND
    HWND GetHwnd() const { return m_hwnd; }

private:
    // Window procedure
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    // UI creation
    void OnCreate();
    void OnSize(int width, int height);
    void OnCommand(WPARAM wParam, LPARAM lParam);
    void OnNotify(LPARAM lParam);
    
    // File operations
    void PopulateTree();
    void ExpandNode(HTREEITEM hItem);
    void OnItemSelected();
    void OnItemDoubleClick();
    std::vector<FileItem> ScanDirectory(const std::string& path);
    
    // Helpers
    HTREEITEM AddTreeItem(HTREEITEM parent, const std::string& text, bool isDir, const std::string& fullPath);
    int GetItemIcon(bool isDirectory);
    
    // Controls
    HWND m_hwnd = nullptr;
    HWND m_hwndTree = nullptr;
    HWND m_hwndPathBar = nullptr;
    HWND m_hwndRefreshBtn = nullptr;
    HIMAGELIST m_hImageList = nullptr;
    
    // Data
    std::string m_rootPath;
    std::string m_selectedFile;
    std::function<void(const std::string&)> m_onFileSelected;
    
    // Layout
    static constexpr int PATHBAR_HEIGHT = 24;
    static constexpr int PADDING = 4;
};

} // namespace GUI
} // namespace RawrXD
