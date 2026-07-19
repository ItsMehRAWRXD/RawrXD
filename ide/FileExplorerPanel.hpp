#pragma once
#include <string>
#include <vector>
#include <string>

namespace IDE {

class FileExplorerPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static void Toggle();
    static bool IsVisible();
    static const char* Id();
    
    // File operations
    static void OpenFile(const std::string& path);
    static void SelectFile(const std::string& path);
    static const std::string& GetSelectedFile();
    
    // Callback for file selection
    static void SetFileOpenCallback(std::function<void(const std::string&)> callback);
    
private:
    static void RenderToolbar();
    static void RenderFileTree();
    static void RenderFileTreeNode(const std::string& path, int depth);
    static void RenderContextMenu(const std::string& path);
    
    static bool s_visible;
    static bool s_initialized;
    static std::string s_selectedFile;
    static std::string s_expandedDir;
    static std::function<void(const std::string&)> s_fileOpenCallback;
    
    // Icons (using text for now)
    static const char* GetFileIcon(const std::string& extension);
    static const char* GetFolderIcon();
};

} // namespace IDE
