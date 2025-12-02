#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>

// SCALAR-ONLY: Efficient multi-tab editor supporting 1000+ tabs

namespace RawrXD {

struct EditorTab {
    std::string tab_id;
    std::string file_path;
    std::string content;
    bool is_modified;
    bool is_loaded;         // Lazy loading
    int cursor_line;
    int cursor_column;
    int scroll_position;
    std::string language;   // cpp, python, javascript, etc.
    size_t file_size;
};

class MultiTabEditor {
public:
    MultiTabEditor();
    ~MultiTabEditor();

    // Tab management (scalar, supports 1000+ tabs)
    std::string OpenFile(const std::string& file_path);
    bool CloseTab(const std::string& tab_id);
    bool CloseAllTabs();
    bool CloseOtherTabs(const std::string& tab_id);
    bool CloseTabsToRight(const std::string& tab_id);
    bool CloseTabsToLeft(const std::string& tab_id);

    // Tab navigation
    void SetActiveTab(const std::string& tab_id);
    std::string GetActiveTabId() const { return active_tab_id_; }
    std::shared_ptr<EditorTab> GetActiveTab();
    std::shared_ptr<EditorTab> GetTab(const std::string& tab_id);
    std::vector<std::string> GetAllTabIds();
    int GetTabIndex(const std::string& tab_id);

    // Content operations (scalar)
    bool SaveTab(const std::string& tab_id);
    bool SaveAllTabs();
    bool ReloadTab(const std::string& tab_id);
    void SetTabContent(const std::string& tab_id, const std::string& content);
    std::string GetTabContent(const std::string& tab_id);

    // Lazy loading for performance
    void LoadTabContent(const std::string& tab_id);
    void UnloadTabContent(const std::string& tab_id);
    void LoadVisibleTabs(int start_index, int end_index);

    // Tab state
    void MarkTabModified(const std::string& tab_id, bool modified);
    bool IsTabModified(const std::string& tab_id);
    std::vector<std::string> GetModifiedTabs();

    // Search and navigation
    std::vector<std::string> FindTabsByPath(const std::string& path_pattern);
    std::vector<std::string> FindTabsByContent(const std::string& search_text);

    // Stats
    size_t GetTabCount() const { return tabs_.size(); }
    size_t GetLoadedTabCount() const;
    size_t GetTotalMemoryUsage() const;

private:
    std::map<std::string, std::shared_ptr<EditorTab>> tabs_;
    std::vector<std::string> tab_order_;  // Preserves tab order
    std::string active_tab_id_;
    int next_tab_number_;

    std::string GenerateTabId();
    std::string DetectLanguage(const std::string& file_path);
    bool ReadFileContent(const std::string& file_path, std::string& content);
    bool WriteFileContent(const std::string& file_path, const std::string& content);
};

} // namespace RawrXD
