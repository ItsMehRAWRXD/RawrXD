#include "multi_tab_editor.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <chrono>

namespace fs = std::filesystem;

namespace RawrXD {

MultiTabEditor::MultiTabEditor() : next_tab_number_(1) {}

MultiTabEditor::~MultiTabEditor() = default;

std::string MultiTabEditor::OpenFile(const std::string& file_path) {
    // Check if already open
    for (const auto& [id, tab] : tabs_) {
        if (tab->file_path == file_path) {
            SetActiveTab(id);
            return id;
        }
    }

    // Create new tab
    auto tab = std::make_shared<EditorTab>();
    tab->tab_id = GenerateTabId();
    tab->file_path = file_path;
    tab->is_modified = false;
    tab->is_loaded = false;  // Lazy loading
    tab->cursor_line = 0;
    tab->cursor_column = 0;
    tab->scroll_position = 0;
    tab->language = DetectLanguage(file_path);

    // Get file size without loading content
    try {
        tab->file_size = fs::file_size(file_path);
    } catch (...) {
        tab->file_size = 0;
    }

    tabs_[tab->tab_id] = tab;
    tab_order_.push_back(tab->tab_id);
    active_tab_id_ = tab->tab_id;

    return tab->tab_id;
}

bool MultiTabEditor::CloseTab(const std::string& tab_id) {
    auto it = tabs_.find(tab_id);
    if (it != tabs_.end()) {
        // Remove from order
        auto order_it = std::find(tab_order_.begin(), tab_order_.end(), tab_id);
        if (order_it != tab_order_.end()) {
            tab_order_.erase(order_it);
        }

        // Remove tab
        tabs_.erase(it);

        // Update active tab
        if (active_tab_id_ == tab_id) {
            active_tab_id_.clear();
            if (!tab_order_.empty()) {
                active_tab_id_ = tab_order_.back();
            }
        }

        return true;
    }
    return false;
}

bool MultiTabEditor::CloseAllTabs() {
    tabs_.clear();
    tab_order_.clear();
    active_tab_id_.clear();
    return true;
}

bool MultiTabEditor::CloseOtherTabs(const std::string& tab_id) {
    auto tab = GetTab(tab_id);
    if (!tab) return false;

    tabs_.clear();
    tab_order_.clear();
    
    tabs_[tab_id] = tab;
    tab_order_.push_back(tab_id);
    active_tab_id_ = tab_id;
    
    return true;
}

bool MultiTabEditor::CloseTabsToRight(const std::string& tab_id) {
    int index = GetTabIndex(tab_id);
    if (index < 0) return false;

    std::vector<std::string> to_close;
    for (size_t i = index + 1; i < tab_order_.size(); ++i) {
        to_close.push_back(tab_order_[i]);
    }

    for (const auto& id : to_close) {
        CloseTab(id);
    }

    return true;
}

bool MultiTabEditor::CloseTabsToLeft(const std::string& tab_id) {
    int index = GetTabIndex(tab_id);
    if (index <= 0) return false;

    std::vector<std::string> to_close;
    for (int i = 0; i < index; ++i) {
        to_close.push_back(tab_order_[i]);
    }

    for (const auto& id : to_close) {
        CloseTab(id);
    }

    return true;
}

void MultiTabEditor::SetActiveTab(const std::string& tab_id) {
    if (tabs_.find(tab_id) != tabs_.end()) {
        active_tab_id_ = tab_id;
        // Lazy load content if not already loaded
        LoadTabContent(tab_id);
    }
}

std::shared_ptr<EditorTab> MultiTabEditor::GetActiveTab() {
    return GetTab(active_tab_id_);
}

std::shared_ptr<EditorTab> MultiTabEditor::GetTab(const std::string& tab_id) {
    auto it = tabs_.find(tab_id);
    if (it != tabs_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::string> MultiTabEditor::GetAllTabIds() {
    return tab_order_;
}

int MultiTabEditor::GetTabIndex(const std::string& tab_id) {
    auto it = std::find(tab_order_.begin(), tab_order_.end(), tab_id);
    if (it != tab_order_.end()) {
        return std::distance(tab_order_.begin(), it);
    }
    return -1;
}

bool MultiTabEditor::SaveTab(const std::string& tab_id) {
    auto tab = GetTab(tab_id);
    if (!tab) return false;

    if (WriteFileContent(tab->file_path, tab->content)) {
        tab->is_modified = false;
        return true;
    }
    return false;
}

bool MultiTabEditor::SaveAllTabs() {
    bool all_saved = true;
    for (const auto& [id, tab] : tabs_) {
        if (tab->is_modified) {
            if (!SaveTab(id)) {
                all_saved = false;
            }
        }
    }
    return all_saved;
}

bool MultiTabEditor::ReloadTab(const std::string& tab_id) {
    auto tab = GetTab(tab_id);
    if (!tab) return false;

    std::string content;
    if (ReadFileContent(tab->file_path, content)) {
        tab->content = content;
        tab->is_modified = false;
        tab->is_loaded = true;
        return true;
    }
    return false;
}

void MultiTabEditor::SetTabContent(const std::string& tab_id, const std::string& content) {
    auto tab = GetTab(tab_id);
    if (tab) {
        tab->content = content;
        tab->is_loaded = true;
        tab->is_modified = true;
    }
}

std::string MultiTabEditor::GetTabContent(const std::string& tab_id) {
    auto tab = GetTab(tab_id);
    if (tab) {
        if (!tab->is_loaded) {
            LoadTabContent(tab_id);
        }
        return tab->content;
    }
    return "";
}

void MultiTabEditor::LoadTabContent(const std::string& tab_id) {
    auto tab = GetTab(tab_id);
    if (tab && !tab->is_loaded) {
        std::string content;
        if (ReadFileContent(tab->file_path, content)) {
            tab->content = content;
            tab->is_loaded = true;
        }
    }
}

void MultiTabEditor::UnloadTabContent(const std::string& tab_id) {
    auto tab = GetTab(tab_id);
    if (tab && tab->is_loaded && !tab->is_modified) {
        tab->content.clear();
        tab->content.shrink_to_fit();
        tab->is_loaded = false;
    }
}

void MultiTabEditor::LoadVisibleTabs(int start_index, int end_index) {
    for (int i = start_index; i <= end_index && i < (int)tab_order_.size(); ++i) {
        LoadTabContent(tab_order_[i]);
    }
}

void MultiTabEditor::MarkTabModified(const std::string& tab_id, bool modified) {
    auto tab = GetTab(tab_id);
    if (tab) {
        tab->is_modified = modified;
    }
}

bool MultiTabEditor::IsTabModified(const std::string& tab_id) {
    auto tab = GetTab(tab_id);
    return tab && tab->is_modified;
}

std::vector<std::string> MultiTabEditor::GetModifiedTabs() {
    std::vector<std::string> modified;
    for (const auto& [id, tab] : tabs_) {
        if (tab->is_modified) {
            modified.push_back(id);
        }
    }
    return modified;
}

std::vector<std::string> MultiTabEditor::FindTabsByPath(const std::string& path_pattern) {
    std::vector<std::string> results;
    std::string lower_pattern = path_pattern;
    std::transform(lower_pattern.begin(), lower_pattern.end(), lower_pattern.begin(), ::tolower);

    for (const auto& [id, tab] : tabs_) {
        std::string lower_path = tab->file_path;
        std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);
        
        if (lower_path.find(lower_pattern) != std::string::npos) {
            results.push_back(id);
        }
    }
    return results;
}

std::vector<std::string> MultiTabEditor::FindTabsByContent(const std::string& search_text) {
    std::vector<std::string> results;
    std::string lower_search = search_text;
    std::transform(lower_search.begin(), lower_search.end(), lower_search.begin(), ::tolower);

    for (const auto& [id, tab] : tabs_) {
        if (!tab->is_loaded) {
            LoadTabContent(id);
        }
        
        std::string lower_content = tab->content;
        std::transform(lower_content.begin(), lower_content.end(), lower_content.begin(), ::tolower);
        
        if (lower_content.find(lower_search) != std::string::npos) {
            results.push_back(id);
        }
    }
    return results;
}

size_t MultiTabEditor::GetLoadedTabCount() const {
    size_t count = 0;
    for (const auto& [id, tab] : tabs_) {
        if (tab->is_loaded) ++count;
    }
    return count;
}

size_t MultiTabEditor::GetTotalMemoryUsage() const {
    size_t total = 0;
    for (const auto& [id, tab] : tabs_) {
        if (tab->is_loaded) {
            total += tab->content.size();
        }
    }
    return total;
}

std::string MultiTabEditor::GenerateTabId() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return "tab_" + std::to_string(ms.count());
}

std::string MultiTabEditor::DetectLanguage(const std::string& file_path) {
    std::string ext = fs::path(file_path).extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    static const std::map<std::string, std::string> ext_map = {
        {".cpp", "cpp"}, {".h", "cpp"}, {".hpp", "cpp"}, {".cc", "cpp"},
        {".c", "c"}, {".py", "python"}, {".js", "javascript"}, {".ts", "typescript"},
        {".html", "html"}, {".css", "css"}, {".json", "json"}, {".xml", "xml"},
        {".md", "markdown"}, {".txt", "text"}, {".sh", "bash"}, {".ps1", "powershell"},
        {".asm", "assembly"}, {".java", "java"}, {".cs", "csharp"}, {".rs", "rust"}
    };

    auto it = ext_map.find(ext);
    return (it != ext_map.end()) ? it->second : "text";
}

bool MultiTabEditor::ReadFileContent(const std::string& file_path, std::string& content) {
    try {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) return false;

        std::ostringstream ss;
        ss << file.rdbuf();
        content = ss.str();
        return true;
    } catch (...) {
        return false;
    }
}

bool MultiTabEditor::WriteFileContent(const std::string& file_path, const std::string& content) {
    try {
        std::ofstream file(file_path, std::ios::binary);
        if (!file.is_open()) return false;

        file << content;
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace RawrXD
