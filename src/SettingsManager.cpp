// ============================================================================
// SettingsManager.cpp - Persistent Configuration Storage (Day 5)
// ============================================================================
// INI-based settings persistence with UTF-8 support.
// Uses Windows API for INI file operations.
//
// DAY 5 DELIVERABLES:
// - INI read/write implementation
// - Window state persistence
// - Editor preferences persistence
// - Model path history management
// - Thread-safe operations
// ============================================================================

#include "SettingsManager.h"
#include <shlobj.h>
#include <algorithm>
#include <sstream>

namespace RawrXD {

// ============================================================================
// Singleton
// ============================================================================

SettingsManager& SettingsManager::Instance() {
    static SettingsManager instance;
    return instance;
}

// ============================================================================
// Initialization
// ============================================================================

bool SettingsManager::Initialize(const std::string& configPath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        return true;
    }
    
    if (configPath.empty()) {
        m_configPath = GetDefaultConfigPath();
    } else {
        m_configPath = configPath;
    }
    
    EnsureConfigDirectoryExists();
    
    // Load existing settings or create defaults
    if (!Load()) {
        // First run - save defaults
        Save();
    }
    
    m_initialized = true;
    return true;
}

void SettingsManager::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_dirty) {
        Save();
    }
    
    m_initialized = false;
}

// ============================================================================
// Path Management
// ============================================================================

std::string SettingsManager::GetDefaultConfigPath() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        std::string configDir = std::string(path) + "\\RawrXD";
        return configDir + "\\settings.ini";
    }
    // Fallback to executable directory
    return "settings.ini";
}

void SettingsManager::EnsureConfigDirectoryExists() {
    size_t lastSlash = m_configPath.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        std::string dir = m_configPath.substr(0, lastSlash);
        CreateDirectoryA(dir.c_str(), nullptr);
    }
}

// ============================================================================
// Save/Load
// ============================================================================

bool SettingsManager::Save() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Window State
    SetInt("Window", "X", m_windowState.x);
    SetInt("Window", "Y", m_windowState.y);
    SetInt("Window", "Width", m_windowState.width);
    SetInt("Window", "Height", m_windowState.height);
    SetBool("Window", "Maximized", m_windowState.maximized);
    SetBool("Window", "Fullscreen", m_windowState.fullscreen);
    
    // Editor Preferences
    SetString("Editor", "FontName", m_editorPrefs.fontName);
    SetInt("Editor", "FontSize", m_editorPrefs.fontSize);
    SetBool("Editor", "WordWrap", m_editorPrefs.wordWrap);
    SetBool("Editor", "ShowLineNumbers", m_editorPrefs.showLineNumbers);
    SetBool("Editor", "ShowWhitespace", m_editorPrefs.showWhitespace);
    SetInt("Editor", "TabSize", m_editorPrefs.tabSize);
    SetBool("Editor", "UseSpaces", m_editorPrefs.useSpaces);
    SetInt("Editor", "BackgroundColor", static_cast<int>(m_editorPrefs.backgroundColor));
    SetInt("Editor", "TextColor", static_cast<int>(m_editorPrefs.textColor));
    SetInt("Editor", "SelectionColor", static_cast<int>(m_editorPrefs.selectionColor));
    SetInt("Editor", "GhostTextColor", static_cast<int>(m_editorPrefs.ghostTextColor));
    
    // Model Configuration
    SetString("Model", "LastModelPath", m_modelConfig.lastModelPath);
    SetBool("Model", "AutoDetectGPUs", m_modelConfig.autoDetectGPUs);
    SetString("Model", "VisibleDevices", m_modelConfig.visibleDevices);
    SetInt("Model", "DefaultMaxTokens", m_modelConfig.defaultMaxTokens);
    SetInt("Model", "DefaultTemperature", static_cast<int>(m_modelConfig.defaultTemperature * 100));
    SetInt("Model", "DefaultContextLength", m_modelConfig.defaultContextLength);
    
    // Recent models (comma-separated)
    std::string recentModels;
    for (size_t i = 0; i < m_modelConfig.recentModels.size(); ++i) {
        if (i > 0) recentModels += ";";
        recentModels += m_modelConfig.recentModels[i];
    }
    SetString("Model", "RecentModels", recentModels);
    
    // UI Preferences
    SetBool("UI", "DarkTheme", m_uiPrefs.darkTheme);
    SetBool("UI", "ShowStatusBar", m_uiPrefs.showStatusBar);
    SetBool("UI", "ShowToolbar", m_uiPrefs.showToolbar);
    SetInt("UI", "SidebarWidth", m_uiPrefs.sidebarWidth);
    SetInt("UI", "BottomPanelHeight", m_uiPrefs.bottomPanelHeight);
    SetBool("UI", "ShowFileBrowser", m_uiPrefs.showFileBrowser);
    SetBool("UI", "ShowOutline", m_uiPrefs.showOutline);
    SetBool("UI", "ShowTerminal", m_uiPrefs.showTerminal);
    SetBool("UI", "ShowChatPanel", m_uiPrefs.showChatPanel);
    
    m_dirty = false;
    return true;
}

bool SettingsManager::Load() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check if file exists
    if (GetFileAttributesA(m_configPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return false; // File doesn't exist, will use defaults
    }
    
    // Window State
    m_windowState.x = GetInt("Window", "X", CW_USEDEFAULT);
    m_windowState.y = GetInt("Window", "Y", CW_USEDEFAULT);
    m_windowState.width = GetInt("Window", "Width", 1280);
    m_windowState.height = GetInt("Window", "Height", 720);
    m_windowState.maximized = GetBool("Window", "Maximized", false);
    m_windowState.fullscreen = GetBool("Window", "Fullscreen", false);
    
    // Editor Preferences
    m_editorPrefs.fontName = GetString("Editor", "FontName", "Consolas");
    m_editorPrefs.fontSize = GetInt("Editor", "FontSize", 11);
    m_editorPrefs.wordWrap = GetBool("Editor", "WordWrap", false);
    m_editorPrefs.showLineNumbers = GetBool("Editor", "ShowLineNumbers", true);
    m_editorPrefs.showWhitespace = GetBool("Editor", "ShowWhitespace", false);
    m_editorPrefs.tabSize = GetInt("Editor", "TabSize", 4);
    m_editorPrefs.useSpaces = GetBool("Editor", "UseSpaces", true);
    m_editorPrefs.backgroundColor = static_cast<COLORREF>(GetInt("Editor", "BackgroundColor", static_cast<int>(RGB(30, 30, 30))));
    m_editorPrefs.textColor = static_cast<COLORREF>(GetInt("Editor", "TextColor", static_cast<int>(RGB(220, 220, 220))));
    m_editorPrefs.selectionColor = static_cast<COLORREF>(GetInt("Editor", "SelectionColor", static_cast<int>(RGB(0, 120, 215))));
    m_editorPrefs.ghostTextColor = static_cast<COLORREF>(GetInt("Editor", "GhostTextColor", static_cast<int>(RGB(128, 128, 128))));
    
    // Model Configuration
    m_modelConfig.lastModelPath = GetString("Model", "LastModelPath", "");
    m_modelConfig.autoDetectGPUs = GetBool("Model", "AutoDetectGPUs", true);
    m_modelConfig.visibleDevices = GetString("Model", "VisibleDevices", "");
    m_modelConfig.defaultMaxTokens = GetInt("Model", "DefaultMaxTokens", 2048);
    m_modelConfig.defaultTemperature = GetInt("Model", "DefaultTemperature", 70) / 100.0f;
    m_modelConfig.defaultContextLength = GetInt("Model", "DefaultContextLength", 4096);
    
    // Recent models
    std::string recentModels = GetString("Model", "RecentModels", "");
    m_modelConfig.recentModels.clear();
    if (!recentModels.empty()) {
        std::stringstream ss(recentModels);
        std::string model;
        while (std::getline(ss, model, ';')) {
            if (!model.empty() && m_modelConfig.recentModels.size() < static_cast<size_t>(m_modelConfig.maxRecentModels)) {
                m_modelConfig.recentModels.push_back(model);
            }
        }
    }
    
    // UI Preferences
    m_uiPrefs.darkTheme = GetBool("UI", "DarkTheme", true);
    m_uiPrefs.showStatusBar = GetBool("UI", "ShowStatusBar", true);
    m_uiPrefs.showToolbar = GetBool("UI", "ShowToolbar", true);
    m_uiPrefs.sidebarWidth = GetInt("UI", "SidebarWidth", 250);
    m_uiPrefs.bottomPanelHeight = GetInt("UI", "BottomPanelHeight", 200);
    m_uiPrefs.showFileBrowser = GetBool("UI", "ShowFileBrowser", true);
    m_uiPrefs.showOutline = GetBool("UI", "ShowOutline", false);
    m_uiPrefs.showTerminal = GetBool("UI", "ShowTerminal", true);
    m_uiPrefs.showChatPanel = GetBool("UI", "ShowChatPanel", true);
    
    return true;
}

// ============================================================================
// Getters
// ============================================================================

WindowState SettingsManager::GetWindowState() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_windowState;
}

EditorPreferences SettingsManager::GetEditorPreferences() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_editorPrefs;
}

ModelConfiguration SettingsManager::GetModelConfiguration() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_modelConfig;
}

UIPreferences SettingsManager::GetUIPreferences() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_uiPrefs;
}

// ============================================================================
// Setters
// ============================================================================

void SettingsManager::SetWindowState(const WindowState& state) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_windowState = state;
    m_dirty = true;
}

void SettingsManager::SetEditorPreferences(const EditorPreferences& prefs) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_editorPrefs = prefs;
    m_dirty = true;
}

void SettingsManager::SetModelConfiguration(const ModelConfiguration& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_modelConfig = config;
    m_dirty = true;
}

void SettingsManager::SetUIPreferences(const UIPreferences& prefs) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_uiPrefs = prefs;
    m_dirty = true;
}

// ============================================================================
// Helper Methods
// ============================================================================

void SettingsManager::AddRecentModel(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Remove if already exists
    auto it = std::find(m_modelConfig.recentModels.begin(), m_modelConfig.recentModels.end(), path);
    if (it != m_modelConfig.recentModels.end()) {
        m_modelConfig.recentModels.erase(it);
    }
    
    // Add to front
    m_modelConfig.recentModels.insert(m_modelConfig.recentModels.begin(), path);
    
    // Trim to max
    if (m_modelConfig.recentModels.size() > static_cast<size_t>(m_modelConfig.maxRecentModels)) {
        m_modelConfig.recentModels.resize(m_modelConfig.maxRecentModels);
    }
    
    m_modelConfig.lastModelPath = path;
    m_dirty = true;
}

std::optional<std::string> SettingsManager::GetLastModelPath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_modelConfig.lastModelPath.empty()) {
        return m_modelConfig.lastModelPath;
    }
    if (!m_modelConfig.recentModels.empty()) {
        return m_modelConfig.recentModels[0];
    }
    return std::nullopt;
}

// ============================================================================
// Raw INI Access
// ============================================================================

std::string SettingsManager::GetString(const std::string& section, const std::string& key, 
                                       const std::string& defaultValue) {
    char buffer[1024];
    DWORD result = GetPrivateProfileStringA(section.c_str(), key.c_str(), defaultValue.c_str(),
                                              buffer, sizeof(buffer), m_configPath.c_str());
    return std::string(buffer, result);
}

int SettingsManager::GetInt(const std::string& section, const std::string& key, int defaultValue) {
    return GetPrivateProfileIntA(section.c_str(), key.c_str(), defaultValue, m_configPath.c_str());
}

bool SettingsManager::GetBool(const std::string& section, const std::string& key, bool defaultValue) {
    return GetInt(section, key, defaultValue ? 1 : 0) != 0;
}

void SettingsManager::SetString(const std::string& section, const std::string& key, 
                                const std::string& value) {
    WritePrivateProfileStringA(section.c_str(), key.c_str(), value.c_str(), m_configPath.c_str());
}

void SettingsManager::SetInt(const std::string& section, const std::string& key, int value) {
    SetString(section, key, std::to_string(value));
}

void SettingsManager::SetBool(const std::string& section, const std::string& key, bool value) {
    SetInt(section, key, value ? 1 : 0);
}

} // namespace RawrXD
