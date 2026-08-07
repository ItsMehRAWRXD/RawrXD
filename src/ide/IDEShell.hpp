// ============================================================================
// IDEShell.hpp - IDE Windowing & UI Shell
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace IDE {

struct EditorTab {
    std::string filePath;
    std::string title;
    bool isDirty;
    bool isPinned;
    size_t cursorLine;
    size_t cursorColumn;
    std::string language;
};

struct PanelInfo {
    std::string id;
    std::string title;
    bool isVisible;
    bool isFocused;
    enum Position { Left, Right, Bottom, Center };
    Position position;
    size_t width;
    size_t height;
};

class IDEShell {
public:
    IDEShell();
    ~IDEShell();

    bool Initialize();
    bool Shutdown();
    
    // Window management
    bool Show();
    bool Hide();
    void SetTitle(const std::string& title);
    void SetSize(int width, int height);
    
    // Editor management
    bool OpenFile(const std::string& filePath);
    bool CloseFile(const std::string& filePath);
    bool SaveFile(const std::string& filePath);
    std::vector<EditorTab> GetOpenTabs();
    EditorTab GetActiveTab();
    bool SetActiveTab(const std::string& filePath);
    
    // Panel management
    bool ShowPanel(const std::string& panelId);
    bool HidePanel(const std::string& panelId);
    std::vector<PanelInfo> GetPanels();
    
    // Status bar
    void SetStatusText(const std::string& text);
    void SetProgress(float percent);
    void ShowNotification(const std::string& message, int durationMs = 3000);
    
    // Events
    using FileOpenCallback = std::function<void(const std::string& filePath)>;
    using FileSaveCallback = std::function<void(const std::string& filePath)>;
    using FileCloseCallback = std::function<void(const std::string& filePath)>;
    
    void SetFileOpenCallback(FileOpenCallback cb);
    void SetFileSaveCallback(FileSaveCallback cb);
    void SetFileCloseCallback(FileCloseCallback cb);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace IDE
} // namespace RawrXD
