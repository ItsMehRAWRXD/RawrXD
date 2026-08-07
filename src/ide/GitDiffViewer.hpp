/**
 * @file GitDiffViewer.hpp
 * @brief Side-by-Side Git Diff Viewer Dialog
 * @status PRODUCTION - Full diff visualization with syntax highlighting
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <functional>

namespace RawrXD::IDE {

/**
 * @brief Diff line types
 */
enum class DiffLineType {
    Context,    // Unchanged line
    Added,      // Added in new version
    Removed,    // Removed in old version
    Header,     // Diff header (@@ lines, file paths)
    HunkHeader  // Hunk header with line numbers
};

/**
 * @brief Single line in a diff
 */
struct DiffLine {
    DiffLineType type;
    std::string content;
    int oldLineNum;   // Line number in old file (-1 if not applicable)
    int newLineNum;   // Line number in new file (-1 if not applicable)
};

/**
 * @brief A hunk (section) of a diff
 */
struct DiffHunk {
    int oldStart;     // Starting line in old file
    int oldCount;     // Number of lines in old file
    int newStart;     // Starting line in new file
    int newCount;     // Number of lines in new file
    std::vector<DiffLine> lines;
};

/**
 * @brief Complete diff for a single file
 */
struct FileDiff {
    std::string oldPath;
    std::string newPath;
    std::string oldMode;
    std::string newMode;
    std::string index;
    std::vector<DiffHunk> hunks;
    
    // Statistics
    int additions = 0;
    int deletions = 0;
    int changes = 0;
};

/**
 * @brief Side-by-Side Git Diff Viewer
 * 
 * Features:
 * - Unified or side-by-side view modes
 * - Syntax highlighting for code
 * - Line numbers for both versions
 * - Navigation between hunks
 * - Search within diff
 * - Copy/paste support
 * - Export to file
 */
class GitDiffViewer {
public:
    GitDiffViewer();
    ~GitDiffViewer();
    
    // Creation/Destruction
    bool Create(HWND hwndParent, HINSTANCE hInstance);
    void Destroy();
    bool IsCreated() const { return m_hwnd != nullptr; }
    HWND GetHwnd() const { return m_hwnd; }
    
    // Content
    void SetDiff(const std::string& diffText);
    void SetDiff(const FileDiff& diff);
    void Clear();
    
    // File operations
    void LoadFromGit(const std::string& filePath, const std::string& revision = "");
    void LoadWorkingTreeDiff(const std::string& filePath);
    void LoadStagedDiff(const std::string& filePath);
    
    // View modes
    enum class ViewMode {
        SideBySide,   // Split view: old | new
        Unified       // Inline view with +/- markers
    };
    void SetViewMode(ViewMode mode);
    ViewMode GetViewMode() const { return m_viewMode; }
    void ToggleViewMode();
    
    // Navigation
    void GoToNextHunk();
    void GoToPreviousHunk();
    void GoToHunk(size_t index);
    void GoToLine(int lineNum, bool inNewVersion);
    
    // Display options
    void SetShowLineNumbers(bool show);
    void SetShowWhitespace(bool show);
    void SetWordWrap(bool wrap);
    void SetSyntaxHighlighting(bool enable);
    
    // Search
    bool Find(const std::string& text, bool forward = true, bool caseSensitive = false);
    void FindNext();
    void FindPrevious();
    
    // Export
    bool ExportToFile(const std::string& path);
    bool CopySelectionToClipboard();
    
    // Window management
    void Show();
    void Hide();
    void SetTitle(const std::string& title);
    void SetPosition(int x, int y, int width, int height);
    void CenterOnParent();
    
    // Callbacks
    void SetNavigateToFileCallback(std::function<void(const std::string&, int)> callback);
    void SetApplyHunkCallback(std::function<void(size_t)> callback);
    void SetStageHunkCallback(std::function<void(size_t)> callback);

private:
    // Window handles
    HWND m_hwnd;
    HWND m_hwndParent;
    HWND m_hwndOldView;
    HWND m_hwndNewView;
    HWND m_hwndUnifiedView;
    HWND m_hwndToolbar;
    HWND m_hwndStatusBar;
    HWND m_hwndSplitter;
    
    // State
    HINSTANCE m_hInstance;
    ViewMode m_viewMode;
    FileDiff m_currentDiff;
    size_t m_currentHunk;
    std::string m_searchText;
    bool m_searchCaseSensitive;
    
    // Options
    bool m_showLineNumbers = true;
    bool m_showWhitespace = false;
    bool m_wordWrap = false;
    bool m_syntaxHighlighting = true;
    
    // Callbacks
    std::function<void(const std::string&, int)> m_navigateCallback;
    std::function<void(size_t)> m_applyHunkCallback;
    std::function<void(size_t)> m_stageHunkCallback;
    
    // Window procedure
    static INT_PTR CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    INT_PTR HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    // UI creation
    void CreateToolbar();
    void CreateViews();
    void CreateStatusBar();
    void LayoutControls();
    
    // Rendering
    void RenderSideBySide();
    void RenderUnified();
    void RenderLine(HWND hwnd, const DiffLine& line, int y);
    void UpdateStatusBar();
    
    // Parsing
    FileDiff ParseDiffText(const std::string& text);
    DiffHunk ParseHunk(const std::vector<std::string>& lines, size_t& index);
    
    // Colors
    static const COLORREF s_colorAdded;
    static const COLORREF s_colorAddedBg;
    static const COLORREF s_colorRemoved;
    static const COLORREF s_colorRemovedBg;
    static const COLORREF s_colorHeader;
    static const COLORREF s_colorHeaderBg;
    static const COLORREF s_colorLineNum;
    static const COLORREF s_colorLineNumBg;
    
    // Helpers
    void ApplyRichEditColors(HWND hwnd);
    std::string GetSelectedText();
    int GetLineHeight();
};

/**
 * @brief Modal dialog wrapper for quick diff viewing
 */
class GitDiffDialog {
public:
    /**
     * @brief Show diff dialog modally
     * @param hwndParent Parent window
     * @param diffText Git diff text to display
     * @param title Dialog title
     * @return true if user clicked OK/Apply, false if Cancel
     */
    static bool Show(HWND hwndParent, const std::string& diffText, 
                     const std::string& title = "Git Diff");
    
    /**
     * @brief Show diff for a file
     */
    static bool ShowForFile(HWND hwndParent, const std::string& filePath,
                            const std::string& revision = "");
};

} // namespace RawrXD::IDE
