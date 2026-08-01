// settings_ui.cpp — Settings UI Implementation
#include "settings_ui.hpp"
#include <algorithm>
#include <cctype>

namespace RawrXD {
namespace UX {

SettingsUIManager& SettingsUIManager::Get() {
    static SettingsUIManager instance;
    return instance;
}

void SettingsUIManager::RegisterSetting(const SettingDefinition& setting) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_settings[setting.id] = setting;
}

const SettingDefinition* SettingsUIManager::GetSetting(const std::string& id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_settings.find(id);
    return it != m_settings.end() ? &it->second : nullptr;
}

std::vector<const SettingDefinition*> SettingsUIManager::GetAllSettings() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<const SettingDefinition*> result;
    for (const auto& [id, setting] : m_settings) {
        result.push_back(&setting);
    }
    return result;
}

std::vector<const SettingDefinition*> SettingsUIManager::GetSettingsByCategory(const std::string& category) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<const SettingDefinition*> result;
    for (const auto& [id, setting] : m_settings) {
        if (setting.category == category) result.push_back(&setting);
    }
    return result;
}

std::vector<std::string> SettingsUIManager::GetCategories() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> categories;
    for (const auto& [id, setting] : m_settings) {
        if (std::find(categories.begin(), categories.end(), setting.category) == categories.end()) {
            categories.push_back(setting.category);
        }
    }
    return categories;
}

bool SettingsUIManager::SetValue(const std::string& id, const std::string& value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_settings.find(id);
    if (it == m_settings.end()) return false;

    it->second.currentValue = value;
    if (m_onChanged) m_onChanged(id, value);
    return true;
}

std::string SettingsUIManager::GetValue(const std::string& id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_settings.find(id);
    if (it == m_settings.end()) return {};
    return it->second.currentValue.empty() ? it->second.defaultValue : it->second.currentValue;
}

bool SettingsUIManager::ResetToDefault(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_settings.find(id);
    if (it == m_settings.end()) return false;

    it->second.currentValue.clear();
    if (m_onChanged) m_onChanged(id, it->second.defaultValue);
    return true;
}

void SettingsUIManager::ResetAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [id, setting] : m_settings) {
        setting.currentValue.clear();
    }
}

std::vector<const SettingDefinition*> SettingsUIManager::SearchSettings(const std::string& query) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<const SettingDefinition*> result;

    if (query.empty()) {
        for (const auto& [id, setting] : m_settings) {
            result.push_back(&setting);
        }
        return result;
    }

    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);

    for (const auto& [id, setting] : m_settings) {
        std::string lowerId = id;
        std::string lowerName = setting.displayName;
        std::string lowerDesc = setting.description;
        std::transform(lowerId.begin(), lowerId.end(), lowerId.begin(), ::tolower);
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        std::transform(lowerDesc.begin(), lowerDesc.end(), lowerDesc.begin(), ::tolower);

        if (lowerId.find(lowerQuery) != std::string::npos ||
            lowerName.find(lowerQuery) != std::string::npos ||
            lowerDesc.find(lowerQuery) != std::string::npos) {
            result.push_back(&setting);
        }
    }

    return result;
}

std::vector<const SettingDefinition*> SettingsUIManager::FilterSettings(const std::string& category, const std::string& query) const {
    auto settings = query.empty() ? GetAllSettings() : SearchSettings(query);

    if (category.empty()) return settings;

    std::vector<const SettingDefinition*> filtered;
    for (const auto* setting : settings) {
        if (setting->category == category) {
            filtered.push_back(setting);
        }
    }
    return filtered;
}

std::vector<const SettingDefinition*> SettingsUIManager::GetModifiedSettings() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<const SettingDefinition*> result;
    for (const auto& [id, setting] : m_settings) {
        if (!setting.currentValue.empty() && setting.currentValue != setting.defaultValue) {
            result.push_back(&setting);
        }
    }
    return result;
}

void SettingsUIManager::RegisterBuiltinSettings() {
    // Editor settings
    {
        SettingDefinition s;
        s.id = "editor.fontSize";
        s.displayName = "Font Size";
        s.description = "Controls the font size in pixels";
        s.type = SettingType::Integer;
        s.category = "editor";
        s.defaultValue = "14";
        s.minValue = "8";
        s.maxValue = "48";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "editor.fontFamily";
        s.displayName = "Font Family";
        s.description = "Controls the font family";
        s.type = SettingType::String;
        s.category = "editor";
        s.defaultValue = "Consolas, 'Courier New', monospace";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "editor.lineHeight";
        s.displayName = "Line Height";
        s.description = "Controls the line height";
        s.type = SettingType::Integer;
        s.category = "editor";
        s.defaultValue = "1.6";
        s.minValue = "1.0";
        s.maxValue = "3.0";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "editor.tabSize";
        s.displayName = "Tab Size";
        s.description = "The number of spaces a tab is equal to";
        s.type = SettingType::Integer;
        s.category = "editor";
        s.defaultValue = "4";
        s.minValue = "1";
        s.maxValue = "8";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "editor.insertSpaces";
        s.displayName = "Insert Spaces";
        s.description = "Insert spaces when pressing Tab";
        s.type = SettingType::Boolean;
        s.category = "editor";
        s.defaultValue = "true";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "editor.wordWrap";
        s.displayName = "Word Wrap";
        s.description = "Controls how lines should wrap";
        s.type = SettingType::Enum;
        s.category = "editor";
        s.defaultValue = "off";
        s.enumValues = {"off", "on", "wordWrapColumn", "bounded"};
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "editor.minimap.enabled";
        s.displayName = "Minimap";
        s.description = "Controls whether the minimap is shown";
        s.type = SettingType::Boolean;
        s.category = "editor";
        s.defaultValue = "true";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "editor.renderWhitespace";
        s.displayName = "Render Whitespace";
        s.description = "Controls how whitespace is rendered";
        s.type = SettingType::Enum;
        s.category = "editor";
        s.defaultValue = "selection";
        s.enumValues = {"none", "boundary", "selection", "trailing", "all"};
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "editor.cursorStyle";
        s.displayName = "Cursor Style";
        s.description = "Controls the cursor style";
        s.type = SettingType::Enum;
        s.category = "editor";
        s.defaultValue = "line";
        s.enumValues = {"line", "block", "underline", "line-thin", "block-outline", "underline-thin"};
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "editor.autoSave";
        s.displayName = "Auto Save";
        s.description = "Controls auto-save behavior";
        s.type = SettingType::Enum;
        s.category = "editor";
        s.defaultValue = "off";
        s.enumValues = {"off", "afterDelay", "onFocusChange", "onWindowChange"};
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "editor.autoSaveDelay";
        s.displayName = "Auto Save Delay";
        s.description = "Controls the delay in ms before auto-saving";
        s.type = SettingType::Integer;
        s.category = "editor";
        s.defaultValue = "1000";
        s.minValue = "100";
        s.maxValue = "10000";
        RegisterSetting(s);
    }

    // Terminal settings
    {
        SettingDefinition s;
        s.id = "terminal.fontSize";
        s.displayName = "Terminal Font Size";
        s.description = "Controls the font size in pixels for the terminal";
        s.type = SettingType::Integer;
        s.category = "terminal";
        s.defaultValue = "13";
        s.minValue = "8";
        s.maxValue = "48";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "terminal.fontFamily";
        s.displayName = "Terminal Font Family";
        s.description = "Controls the font family for the terminal";
        s.type = SettingType::String;
        s.category = "terminal";
        s.defaultValue = "Consolas, 'Courier New', monospace";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "terminal.integrated.shell.windows";
        s.displayName = "Terminal Shell Path";
        s.description = "The path to the shell used by the integrated terminal";
        s.type = SettingType::String;
        s.category = "terminal";
        s.defaultValue = "C:\\Windows\\System32\\cmd.exe";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "terminal.integrated.defaultLocation";
        s.displayName = "Terminal Location";
        s.description = "Where the terminal should be shown";
        s.type = SettingType::Enum;
        s.category = "terminal";
        s.defaultValue = "view";
        s.enumValues = {"view", "editor", "panel"};
        RegisterSetting(s);
    }

    // Workspace settings
    {
        SettingDefinition s;
        s.id = "workspace.trust.enabled";
        s.displayName = "Workspace Trust";
        s.description = "Controls whether workspace trust is enabled";
        s.type = SettingType::Boolean;
        s.category = "workspace";
        s.defaultValue = "true";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "files.autoSave";
        s.displayName = "Auto Save Files";
        s.description = "Controls auto-save for all files";
        s.type = SettingType::Enum;
        s.category = "workspace";
        s.defaultValue = "off";
        s.enumValues = {"off", "afterDelay", "onFocusChange", "onWindowChange"};
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "files.exclude";
        s.displayName = "Files: Exclude";
        s.description = "Configure glob patterns to exclude files from the explorer";
        s.type = SettingType::Array;
        s.category = "workspace";
        s.defaultValue = "**/.git/**,**/node_modules/**,**/.vs/**";
        RegisterSetting(s);
    }

    // Extension settings
    {
        SettingDefinition s;
        s.id = "extensions.autoUpdate";
        s.displayName = "Auto Update Extensions";
        s.description = "Automatically update extensions";
        s.type = SettingType::Boolean;
        s.category = "extensions";
        s.defaultValue = "true";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "extensions.ignoreRecommendations";
        s.displayName = "Ignore Recommendations";
        s.description = "Ignore extension recommendations";
        s.type = SettingType::Boolean;
        s.category = "extensions";
        s.defaultValue = "false";
        RegisterSetting(s);
    }

    // Theme settings
    {
        SettingDefinition s;
        s.id = "workbench.colorTheme";
        s.displayName = "Color Theme";
        s.description = "Specifies the color theme used in the workbench";
        s.type = SettingType::Enum;
        s.category = "themes";
        s.defaultValue = "dark-default";
        s.enumValues = {"dark-default", "light-default", "high-contrast"};
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "workbench.iconTheme";
        s.displayName = "Icon Theme";
        s.description = "Specifies the icon theme used";
        s.type = SettingType::String;
        s.category = "themes";
        s.defaultValue = "default";
        RegisterSetting(s);
    }

    // Window settings
    {
        SettingDefinition s;
        s.id = "window.titleBarStyle";
        s.displayName = "Title Bar Style";
        s.description = "Controls the window title bar style";
        s.type = SettingType::Enum;
        s.category = "window";
        s.defaultValue = "native";
        s.enumValues = {"native", "custom"};
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "window.zoomLevel";
        s.displayName = "Zoom Level";
        s.description = "The zoom level of the window";
        s.type = SettingType::Integer;
        s.category = "window";
        s.defaultValue = "0";
        s.minValue = "-5";
        s.maxValue = "5";
        RegisterSetting(s);
    }

    // AI settings
    {
        SettingDefinition s;
        s.id = "ai.model";
        s.displayName = "AI Model";
        s.description = "The default AI model to use";
        s.type = SettingType::String;
        s.category = "ai";
        s.defaultValue = "qwen2.5-coder:14b";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "ai.temperature";
        s.displayName = "AI Temperature";
        s.description = "Controls the randomness of AI responses";
        s.type = SettingType::Float;
        s.category = "ai";
        s.defaultValue = "0.7";
        s.minValue = "0.0";
        s.maxValue = "2.0";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "ai.maxTokens";
        s.displayName = "AI Max Tokens";
        s.description = "Maximum tokens per AI response";
        s.type = SettingType::Integer;
        s.category = "ai";
        s.defaultValue = "4096";
        s.minValue = "128";
        s.maxValue = "32768";
        RegisterSetting(s);
    }
    {
        SettingDefinition s;
        s.id = "ai.autoBuild";
        s.displayName = "Auto Build After Edit";
        s.description = "Automatically build after AI edits files";
        s.type = SettingType::Boolean;
        s.category = "ai";
        s.defaultValue = "true";
        RegisterSetting(s);
    }
}

} // namespace UX
} // namespace RawrXD
