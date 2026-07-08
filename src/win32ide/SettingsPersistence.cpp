// SettingsPersistence.cpp
// ACTUAL settings persistence implementation
// NO SHINE BOX - Real config file read/write

#include "Integration_Wiring.h"
#include <windows.h>
#include <shlobj.h>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <sstream>

// Settings file format (JSON-like but simplified)
// Uses Windows INI format for simplicity and native Windows API support

namespace RawrXD {
namespace Integration {

// Settings storage
class SettingsStore {
public:
    std::wstring configPath;
    std::map<std::wstring, std::map<std::wstring, std::wstring>> sections;
    bool isDirty = false;
    
    SettingsStore() {
        // Get config path in AppData
        wchar_t appDataPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath))) {
            configPath = std::wstring(appDataPath) + L"\\RawrXD\\settings.ini";
            
            // Ensure directory exists
            std::wstring dir = std::wstring(appDataPath) + L"\\RawrXD";
            CreateDirectoryW(dir.c_str(), nullptr);
        }
    }
    
    void Load() {
        sections.clear();
        
        // Read INI file
        std::wifstream file(configPath);
        if (!file.is_open()) {
            // Create default settings
            SetDefaults();
            Save();
            return;
        }
        
        std::wstring currentSection;
        std::wstring line;
        
        while (std::getline(file, line)) {
            // Trim whitespace
            size_t start = line.find_first_not_of(L" \t\r\n");
            if (start == std::wstring::npos) continue;
            size_t end = line.find_last_not_of(L" \t\r\n");
            line = line.substr(start, end - start + 1);
            
            // Skip comments
            if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
            
            // Section header
            if (line[0] == L'[' && line[line.length() - 1] == L']') {
                currentSection = line.substr(1, line.length() - 2);
                continue;
            }
            
            // Key-value pair
            size_t eqPos = line.find(L'=');
            if (eqPos != std::wstring::npos) {
                std::wstring key = line.substr(0, eqPos);
                std::wstring value = line.substr(eqPos + 1);
                
                // Trim key and value
                key = Trim(key);
                value = Trim(value);
                
                if (!currentSection.empty()) {
                    sections[currentSection][key] = value;
                }
            }
        }
        
        file.close();
        
        // Set defaults for missing sections
        SetDefaults();
    }
    
    void Save() {
        std::wofstream file(configPath);
        if (!file.is_open()) return;
        
        // Write header
        file << L"; RawrXD Settings File" << std::endl;
        file << L"; Generated: " << GetTimestamp() << std::endl;
        file << std::endl;
        
        // Write sections
        for (const auto& section : sections) {
            file << L"[" << section.first << L"]" << std::endl;
            
            for (const auto& kv : section.second) {
                file << kv.first << L"=" << kv.second << std::endl;
            }
            
            file << std::endl;
        }
        
        file.close();
        isDirty = false;
    }
    
    std::wstring Get(const std::wstring& section, const std::wstring& key, const std::wstring& defaultValue = L"") {
        auto secIt = sections.find(section);
        if (secIt != sections.end()) {
            auto keyIt = secIt->second.find(key);
            if (keyIt != secIt->second.end()) {
                return keyIt->second;
            }
        }
        return defaultValue;
    }
    
    void Set(const std::wstring& section, const std::wstring& key, const std::wstring& value) {
        sections[section][key] = value;
        isDirty = true;
    }
    
    int GetInt(const std::wstring& section, const std::wstring& key, int defaultValue = 0) {
        std::wstring value = Get(section, key);
        if (value.empty()) return defaultValue;
        try {
            return std::stoi(value);
        } catch (...) {
            return defaultValue;
        }
    }
    
    void SetInt(const std::wstring& section, const std::wstring& key, int value) {
        Set(section, key, std::to_wstring(value));
    }
    
    bool GetBool(const std::wstring& section, const std::wstring& key, bool defaultValue = false) {
        std::wstring value = Get(section, key);
        if (value.empty()) return defaultValue;
        return (value == L"true" || value == L"1" || value == L"yes");
    }
    
    void SetBool(const std::wstring& section, const std::wstring& key, bool value) {
        Set(section, key, value ? L"true" : L"false");
    }
    
private:
    std::wstring Trim(const std::wstring& str) {
        size_t start = str.find_first_not_of(L" \t");
        if (start == std::wstring::npos) return L"";
        size_t end = str.find_last_not_of(L" \t");
        return str.substr(start, end - start + 1);
    }
    
    std::wstring GetTimestamp() {
        SYSTEMTIME st;
        GetSystemTime(&st);
        wchar_t buffer[64];
        swprintf_s(buffer, L"%04d-%02d-%02d %02d:%02d:%02d",
                   st.wYear, st.wMonth, st.wDay,
                   st.wHour, st.wMinute, st.wSecond);
        return buffer;
    }
    
    void SetDefaults() {
        // General settings
        if (sections[L"General"].empty()) {
            Set(L"General", L"Theme", L"dark");
            Set(L"General", L"Language", L"en");
            Set(L"General", L"AutoSave", L"true");
            Set(L"General", L"AutoSaveInterval", L"30");
        }
        
        // Editor settings
        if (sections[L"Editor"].empty()) {
            Set(L"Editor", L"FontName", L"Consolas");
            Set(L"Editor", L"FontSize", L"11");
            Set(L"Editor", L"TabSize", L"4");
            Set(L"Editor", L"UseSpaces", L"true");
            Set(L"Editor", L"WordWrap", L"false");
            Set(L"Editor", L"LineNumbers", L"true");
            Set(L"Editor", L"HighlightCurrentLine", L"true");
        }
        
        // Build settings
        if (sections[L"Build"].empty()) {
            Set(L"Build", L"CompilerPath", L"d:\\rawrxd\\native_toolchain\\universal_compiler.exe");
            Set(L"Build", L"AssemblerPath", L"d:\\rawrxd\\native_toolchain\\minimal_assembler_v7.exe");
            Set(L"Build", L"LinkerPath", L"d:\\rawrxd\\native_toolchain\\linker_fixed.exe");
            Set(L"Build", L"ShowBuildOutput", L"true");
            Set(L"Build", L"AutoBuildOnSave", L"false");
        }
        
        // Debug settings
        if (sections[L"Debug"].empty()) {
            Set(L"Debug", L"ShowDebugOutput", L"true");
            Set(L"Debug", L"BreakOnException", L"true");
            Set(L"Debug", L"ShowDisassembly", L"false");
        }
        
        // AI settings
        if (sections[L"AI"].empty()) {
            Set(L"AI", L"Enabled", L"true");
            Set(L"AI", L"ModelEndpoint", L"http://localhost:11434");
            Set(L"AI", L"DefaultModel", L"codestral");
            Set(L"AI", L"MaxTokens", L"128");
            Set(L"AI", L"Temperature", L"0.2");
        }
        
        // Window settings
        if (sections[L"Window"].empty()) {
            Set(L"Window", L"Width", L"1280");
            Set(L"Window", L"Height", L"720");
            Set(L"Window", L"Maximized", L"false");
            Set(L"Window", L"SidebarVisible", L"true");
            Set(L"Window", L"OutputPanelVisible", L"true");
        }
        
        // Recent files
        if (sections[L"Recent"].empty()) {
            Set(L"Recent", L"FileCount", L"0");
        }
    }
};

// Global settings store
static SettingsStore g_settings;
static bool g_settingsInitialized = false;

} // namespace Integration
} // namespace RawrXD

// =============================================================================
// SETTINGS API IMPLEMENTATION
// =============================================================================

namespace RawrXD {
namespace Integration {

bool Settings::Initialize() {
    if (g_settingsInitialized) return true;
    
    g_settings.Load();
    g_settingsInitialized = true;
    return true;
}

bool Settings::Save() {
    if (!g_settingsInitialized) return false;
    
    g_settings.Save();
    return true;
}

bool Settings::GetString(const wchar_t* section, const wchar_t* key, wchar_t* value, size_t valueSize) {
    if (!g_settingsInitialized || !section || !key || !value) return false;
    
    std::wstring result = g_settings.Get(section, key);
    if (result.empty()) return false;
    
    wcsncpy_s(value, valueSize, result.c_str(), _TRUNCATE);
    return true;
}

bool Settings::SetString(const wchar_t* section, const wchar_t* key, const wchar_t* value) {
    if (!g_settingsInitialized || !section || !key || !value) return false;
    
    g_settings.Set(section, key, value);
    return true;
}

int Settings::GetInt(const wchar_t* section, const wchar_t* key, int defaultValue) {
    if (!g_settingsInitialized || !section || !key) return defaultValue;
    
    return g_settings.GetInt(section, key, defaultValue);
}

bool Settings::SetInt(const wchar_t* section, const wchar_t* key, int value) {
    if (!g_settingsInitialized || !section || !key) return false;
    
    g_settings.SetInt(section, key, value);
    return true;
}

bool Settings::GetBool(const wchar_t* section, const wchar_t* key, bool defaultValue) {
    if (!g_settingsInitialized || !section || !key) return defaultValue;
    
    return g_settings.GetBool(section, key, defaultValue);
}

bool Settings::SetBool(const wchar_t* section, const wchar_t* key, bool value) {
    if (!g_settingsInitialized || !section || !key) return false;
    
    g_settings.SetBool(section, key, value);
    return true;
}

// =============================================================================
// UI SETTINGS HELPERS
// =============================================================================

std::wstring Settings::GetEditorFont() {
    wchar_t fontName[256];
    if (GetString(L"Editor", L"FontName", fontName, 256)) {
        return fontName;
    }
    return L"Consolas";
}

int Settings::GetEditorFontSize() {
    return GetInt(L"Editor", L"FontSize", 11);
}

int Settings::GetTabSize() {
    return GetInt(L"Editor", L"TabSize", 4);
}

bool Settings::UseSpacesForTabs() {
    return GetBool(L"Editor", L"UseSpaces", true);
}

bool Settings::GetWordWrap() {
    return GetBool(L"Editor", L"WordWrap", false);
}

void Settings::SetWordWrap(bool wrap) {
    SetBool(L"Editor", L"WordWrap", wrap);
}

// =============================================================================
// WINDOW SETTINGS
// =============================================================================

void Settings::GetWindowSize(int& width, int& height) {
    width = GetInt(L"Window", L"Width", 1280);
    height = GetInt(L"Window", L"Height", 720);
}

void Settings::SetWindowSize(int width, int height) {
    SetInt(L"Window", L"Width", width);
    SetInt(L"Window", L"Height", height);
}

bool Settings::GetWindowMaximized() {
    return GetBool(L"Window", L"Maximized", false);
}

void Settings::SetWindowMaximized(bool maximized) {
    SetBool(L"Window", L"Maximized", maximized);
}

// =============================================================================
// RECENT FILES
// =============================================================================

void Settings::AddRecentFile(const wchar_t* filePath) {
    if (!filePath) return;
    
    // Get current list
    std::vector<std::wstring> recentFiles;
    int count = GetInt(L"Recent", L"FileCount", 0);
    
    for (int i = 0; i < count; i++) {
        wchar_t key[32];
        swprintf_s(key, L"File%d", i);
        wchar_t value[MAX_PATH];
        if (GetString(L"Recent", key, value, MAX_PATH)) {
            // Skip if same as new file
            if (wcscmp(value, filePath) != 0) {
                recentFiles.push_back(value);
            }
        }
    }
    
    // Add new file at beginning
    recentFiles.insert(recentFiles.begin(), filePath);
    
    // Keep only last 10
    if (recentFiles.size() > 10) {
        recentFiles.resize(10);
    }
    
    // Save back
    SetInt(L"Recent", L"FileCount", (int)recentFiles.size());
    for (size_t i = 0; i < recentFiles.size(); i++) {
        wchar_t key[32];
        swprintf_s(key, L"File%d", (int)i);
        SetString(L"Recent", key, recentFiles[i].c_str());
    }
    
    Save();
}

int Settings::GetRecentFileCount() {
    return GetInt(L"Recent", L"FileCount", 0);
}

bool Settings::GetRecentFile(int index, wchar_t* filePath, size_t pathSize) {
    if (index < 0 || index >= GetRecentFileCount()) return false;
    
    wchar_t key[32];
    swprintf_s(key, L"File%d", index);
    return GetString(L"Recent", key, filePath, pathSize);
}

// =============================================================================
// THEME SETTINGS
// =============================================================================

std::wstring Settings::GetTheme() {
    wchar_t theme[64];
    if (GetString(L"General", L"Theme", theme, 64)) {
        return theme;
    }
    return L"dark";
}

void Settings::SetTheme(const wchar_t* theme) {
    SetString(L"General", L"Theme", theme);
}

// =============================================================================
// BUILD SETTINGS
// =============================================================================

std::wstring Settings::GetCompilerPath() {
    wchar_t path[MAX_PATH];
    if (GetString(L"Build", L"CompilerPath", path, MAX_PATH)) {
        return path;
    }
    return L"d:\\rawrxd\\native_toolchain\\universal_compiler.exe";
}

std::wstring Settings::GetAssemblerPath() {
    wchar_t path[MAX_PATH];
    if (GetString(L"Build", L"AssemblerPath", path, MAX_PATH)) {
        return path;
    }
    return L"d:\\rawrxd\\native_toolchain\\minimal_assembler_v7.exe";
}

std::wstring Settings::GetLinkerPath() {
    wchar_t path[MAX_PATH];
    if (GetString(L"Build", L"LinkerPath", path, MAX_PATH)) {
        return path;
    }
    return L"d:\\rawrxd\\native_toolchain\\linker_fixed.exe";
}

} // namespace Integration
} // namespace RawrXD
