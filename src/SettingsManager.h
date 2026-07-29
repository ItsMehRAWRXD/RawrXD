// ============================================================================
// SettingsManager.h - Persistent Configuration Storage (Day 5)
// ============================================================================
// INI-based settings persistence for window state, editor preferences,
// model paths, and user configuration.
//
// DAY 5 DELIVERABLES:
// - INI file read/write with UTF-8 support
// - Window position/size persistence
// - Editor font/size preferences
// - Model path history
// - Thread-safe singleton access
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <optional>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace RawrXD {

// ============================================================================
// Window State
// ============================================================================
struct WindowState {
    int x = CW_USEDEFAULT;
    int y = CW_USEDEFAULT;
    int width = 1280;
    int height = 720;
    bool maximized = false;
    bool fullscreen = false;
    
    bool IsValid() const {
        return width > 0 && height > 0;
    }
};

// ============================================================================
// Editor Preferences
// ============================================================================
struct EditorPreferences {
    std::string fontName = "Consolas";
    int fontSize = 11;
    bool wordWrap = false;
    bool showLineNumbers = true;
    bool showWhitespace = false;
    int tabSize = 4;
    bool useSpaces = true;  // true = spaces, false = tabs
    
    // Colors (RGB)
    COLORREF backgroundColor = RGB(30, 30, 30);      // Dark theme
    COLORREF textColor = RGB(220, 220, 220);         // Light text
    COLORREF selectionColor = RGB(0, 120, 215);      // Blue selection
    COLORREF ghostTextColor = RGB(128, 128, 128);   // Gray ghost text
};

// ============================================================================
// Model Configuration
// ============================================================================
struct ModelConfiguration {
    std::string lastModelPath;
    std::vector<std::string> recentModels;  // Last 10 models
    int maxRecentModels = 10;
    
    // GPU settings
    bool autoDetectGPUs = true;
    std::string visibleDevices;  // e.g., "0,2"
    float tensorSplit = 0.0f;    // 0 = auto, otherwise manual split ratio
    
    // Inference settings
    int defaultMaxTokens = 2048;
    float defaultTemperature = 0.7f;
    int defaultContextLength = 4096;
};

// ============================================================================
// UI Preferences
// ============================================================================
struct UIPreferences {
    bool darkTheme = true;
    bool showStatusBar = true;
    bool showToolbar = true;
    bool showLineNumbers = true;
    int sidebarWidth = 250;
    int bottomPanelHeight = 200;
    
    // Panel visibility
    bool showFileBrowser = true;
    bool showOutline = false;
    bool showTerminal = true;
    bool showChatPanel = true;
};

// ============================================================================
// Settings Manager
// ============================================================================
class SettingsManager {
public:
    static SettingsManager& Instance();
    
    // Initialize with config file path
    // If path is empty, uses %APPDATA%/RawrXD/settings.ini
    bool Initialize(const std::string& configPath = "");
    
    // Shutdown and save settings
    void Shutdown();
    
    // Explicit save/load
    bool Save();
    bool Load();
    
    // Getters
    WindowState GetWindowState() const;
    EditorPreferences GetEditorPreferences() const;
    ModelConfiguration GetModelConfiguration() const;
    UIPreferences GetUIPreferences() const;
    
    // Setters (marks dirty, auto-save on shutdown)
    void SetWindowState(const WindowState& state);
    void SetEditorPreferences(const EditorPreferences& prefs);
    void SetModelConfiguration(const ModelConfiguration& config);
    void SetUIPreferences(const UIPreferences& prefs);
    
    // Specific helpers
    void AddRecentModel(const std::string& path);
    std::optional<std::string> GetLastModelPath() const;
    
    // Raw INI access
    std::string GetString(const std::string& section, const std::string& key, 
                          const std::string& defaultValue = "");
    int GetInt(const std::string& section, const std::string& key, 
               int defaultValue = 0);
    bool GetBool(const std::string& section, const std::string& key, 
                 bool defaultValue = false);
    
    void SetString(const std::string& section, const std::string& key, 
                   const std::string& value);
    void SetInt(const std::string& section, const std::string& key, int value);
    void SetBool(const std::string& section, const std::string& key, bool value);

private:
    SettingsManager() = default;
    ~SettingsManager() = default;
    SettingsManager(const SettingsManager&) = delete;
    SettingsManager& operator=(const SettingsManager&) = delete;
    
    mutable std::mutex m_mutex;
    std::string m_configPath;
    bool m_initialized = false;
    bool m_dirty = false;
    
    // Cached settings
    WindowState m_windowState;
    EditorPreferences m_editorPrefs;
    ModelConfiguration m_modelConfig;
    UIPreferences m_uiPrefs;
    
    std::string GetDefaultConfigPath();
    void EnsureConfigDirectoryExists();
};

// Convenience accessors
inline SettingsManager& GetSettings() { return SettingsManager::Instance(); }

} // namespace RawrXD
