/*===========================================================================
 * SettingsManager.cpp - RawrXD IDE Settings Persistence Implementation
 *===========================================================================*/

#include "SettingsManager.hpp"
#include <shlobj.h>
#include <strsafe.h>
#include <fstream>

namespace RawrXD {
namespace IDE {

// Maximum path length for settings
constexpr size_t MAX_SETTINGS_PATH = 512;

/*===========================================================================
 * Path Helpers
 *=========================================================================*/

std::wstring GetSettingsPath() {
    wchar_t appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath))) {
        std::wstring path = appDataPath;
        path += L"\\RawrXD\\settings.ini";
        return path;
    }
    // Fallback to executable directory
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring path = exePath;
    size_t lastSlash = path.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        path = path.substr(0, lastSlash);
    }
    path += L"\\settings.ini";
    return path;
}

std::wstring GetSettingsDirectory() {
    wchar_t appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath))) {
        std::wstring path = appDataPath;
        path += L"\\RawrXD";
        return path;
    }
    return L".";
}

bool EnsureSettingsDirectory() {
    std::wstring dir = GetSettingsDirectory();
    return CreateDirectoryW(dir.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}

/*===========================================================================
 * INI Helpers
 *=========================================================================*/

std::wstring GetIniString(const wchar_t* section, const wchar_t* key, const wchar_t* defaultValue) {
    std::wstring path = GetSettingsPath();
    wchar_t buffer[256];
    GetPrivateProfileStringW(section, key, defaultValue, buffer, 256, path.c_str());
    return std::wstring(buffer);
}

int GetIniInt(const wchar_t* section, const wchar_t* key, int defaultValue) {
    std::wstring path = GetSettingsPath();
    return GetPrivateProfileIntW(section, key, defaultValue, path.c_str());
}

bool GetIniBool(const wchar_t* section, const wchar_t* key, bool defaultValue) {
    return GetIniInt(section, key, defaultValue ? 1 : 0) != 0;
}

void WriteIniString(const wchar_t* section, const wchar_t* key, const wchar_t* value) {
    std::wstring path = GetSettingsPath();
    WritePrivateProfileStringW(section, key, value, path.c_str());
}

void WriteIniInt(const wchar_t* section, const wchar_t* key, int value) {
    wchar_t buffer[32];
    StringCchPrintfW(buffer, 32, L"%d", value);
    WriteIniString(section, key, buffer);
}

void WriteIniBool(const wchar_t* section, const wchar_t* key, bool value) {
    WriteIniString(section, key, value ? L"1" : L"0");
}

/*===========================================================================
 * Load Settings
 *=========================================================================*/

bool LoadSettings(RawrXD_IDE* ide) {
    if (!ide) return false;
    
    // Ensure directory exists (but don't fail if it doesn't)
    EnsureSettingsDirectory();
    
    // Check if settings file exists
    std::wstring path = GetSettingsPath();
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        // No settings file yet - use defaults
        return true;
    }
    
    bool success = true;
    success &= LoadWindowPosition(ide);
    success &= LoadEditorSettings(ide);
    success &= LoadThemeSettings(ide);
    success &= LoadModelPath(ide);
    success &= LoadRecentFiles(ide);
    
    return success;
}

bool LoadWindowPosition(RawrXD_IDE* ide) {
    // Window position and size
    int x = GetIniInt(L"Window", L"PosX", CW_USEDEFAULT);
    int y = GetIniInt(L"Window", L"PosY", CW_USEDEFAULT);
    int width = GetIniInt(L"Window", L"Width", RAWRXD_IDE_DEFAULT_WIDTH);
    int height = GetIniInt(L"Window", L"Height", RAWRXD_IDE_DEFAULT_HEIGHT);
    
    // Ensure reasonable defaults if values are invalid
    if (width < 400) width = RAWRXD_IDE_DEFAULT_WIDTH;
    if (height < 300) height = RAWRXD_IDE_DEFAULT_HEIGHT;
    
    // Store for use during window creation
    ide->restoreRect.left = x;
    ide->restoreRect.top = y;
    ide->restoreRect.right = x + width;
    ide->restoreRect.bottom = y + height;
    
    // Panel visibility
    ide->showFileTree = GetIniBool(L"Window", L"ShowFileTree", TRUE);
    ide->showOutput = GetIniBool(L"Window", L"ShowOutput", TRUE);
    ide->showWidget = GetIniBool(L"Window", L"ShowWidget", TRUE);
    
    // Panel sizes
    ide->fileTreeWidth = GetIniInt(L"Window", L"FileTreeWidth", 250);
    ide->outputHeight = GetIniInt(L"Window", L"OutputHeight", 200);
    ide->widgetWidth = GetIniInt(L"Window", L"WidgetWidth", 300);
    
    return true;
}

bool LoadEditorSettings(RawrXD_IDE* ide) {
    // Font settings
    ide->showLineNumbers = GetIniBool(L"Editor", L"ShowLineNumbers", TRUE);
    ide->wordWrapEnabled = GetIniBool(L"Editor", L"WordWrap", FALSE);
    
    // Font size (for future use with configurable fonts)
    int fontSize = GetIniInt(L"Editor", L"FontSize", 11);
    if (fontSize < 6) fontSize = 11;
    if (fontSize > 72) fontSize = 11;
    // Note: Font size would be applied when creating fonts
    
    return true;
}

bool LoadThemeSettings(RawrXD_IDE* ide) {
    ide->isDarkTheme = GetIniBool(L"Theme", L"IsDarkTheme", TRUE);
    // Theme will be applied in initialization
    return true;
}

bool LoadModelPath(RawrXD_IDE* ide) {
    std::wstring modelPath = GetIniString(L"Model", L"LastPath", L"");
    if (!modelPath.empty() && modelPath.length() < MAX_PATH) {
        // Store in MoE info for later loading
        StringCchCopyW(ide->moeInfo.modelPath, MAX_PATH, modelPath.c_str());
    }
    return true;
}

bool LoadRecentFiles(RawrXD_IDE* ide) {
    ide->recentFilesCount = GetIniInt(L"RecentFiles", L"Count", 0);
    if (ide->recentFilesCount > 10) ide->recentFilesCount = 10;
    if (ide->recentFilesCount < 0) ide->recentFilesCount = 0;
    
    for (int i = 0; i < ide->recentFilesCount; i++) {
        wchar_t key[32];
        StringCchPrintfW(key, 32, L"File%d", i);
        std::wstring filePath = GetIniString(L"RecentFiles", key, L"");
        if (!filePath.empty() && filePath.length() < MAX_PATH) {
            StringCchCopyW(ide->recentFiles[i], MAX_PATH, filePath.c_str());
        }
    }
    return true;
}

/*===========================================================================
 * Save Settings
 *=========================================================================*/

bool SaveSettings(const RawrXD_IDE* ide) {
    if (!ide) return false;
    
    if (!EnsureSettingsDirectory()) {
        return false;
    }
    
    bool success = true;
    success &= SaveWindowPosition(ide);
    success &= SaveEditorSettings(ide);
    success &= SaveThemeSettings(ide);
    success &= SaveModelPath(ide);
    success &= SaveRecentFiles(ide);
    
    return success;
}

bool SaveWindowPosition(const RawrXD_IDE* ide) {
    // Get current window position
    WINDOWPLACEMENT wp = { sizeof(wp) };
    if (GetWindowPlacement(ide->hWndMain, &wp)) {
        WriteIniInt(L"Window", L"PosX", wp.rcNormalPosition.left);
        WriteIniInt(L"Window", L"PosY", wp.rcNormalPosition.top);
        WriteIniInt(L"Window", L"Width", wp.rcNormalPosition.right - wp.rcNormalPosition.left);
        WriteIniInt(L"Window", L"Height", wp.rcNormalPosition.bottom - wp.rcNormalPosition.top);
    }
    
    WriteIniBool(L"Window", L"ShowFileTree", ide->showFileTree);
    WriteIniBool(L"Window", L"ShowOutput", ide->showOutput);
    WriteIniBool(L"Window", L"ShowWidget", ide->showWidget);
    WriteIniInt(L"Window", L"FileTreeWidth", ide->fileTreeWidth);
    WriteIniInt(L"Window", L"OutputHeight", ide->outputHeight);
    WriteIniInt(L"Window", L"WidgetWidth", ide->widgetWidth);
    
    return true;
}

bool SaveEditorSettings(const RawrXD_IDE* ide) {
    WriteIniBool(L"Editor", L"ShowLineNumbers", ide->showLineNumbers);
    WriteIniBool(L"Editor", L"WordWrap", ide->wordWrapEnabled);
    return true;
}

bool SaveThemeSettings(const RawrXD_IDE* ide) {
    WriteIniBool(L"Theme", L"IsDarkTheme", ide->isDarkTheme);
    return true;
}

bool SaveModelPath(const RawrXD_IDE* ide) {
    if (ide->moeInfo.modelPath[0]) {
        WriteIniString(L"Model", L"LastPath", ide->moeInfo.modelPath);
    }
    return true;
}

bool SaveRecentFiles(const RawrXD_IDE* ide) {
    WriteIniInt(L"RecentFiles", L"Count", ide->recentFilesCount);
    
    for (int i = 0; i < ide->recentFilesCount && i < 10; i++) {
        wchar_t key[32];
        StringCchPrintfW(key, 32, L"File%d", i);
        WriteIniString(L"RecentFiles", key, ide->recentFiles[i]);
    }
    return true;
}

} // namespace IDE
} // namespace RawrXD
