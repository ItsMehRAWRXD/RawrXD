/*===========================================================================
 * SettingsManager.hpp - RawrXD IDE Settings Persistence
 * 
 * Simple INI-based settings storage in %APPDATA%/RawrXD/settings.ini
 * Saves: window position, model path, font size, theme, recent files
 *===========================================================================*/

#pragma once

#include "RawrXD_IDE_Win32.h"
#include <windows.h>
#include <string>

namespace RawrXD {
namespace IDE {

// Settings file path: %APPDATA%/RawrXD/settings.ini
std::wstring GetSettingsPath();

// Ensure settings directory exists
bool EnsureSettingsDirectory();

// Load all settings from INI file
bool LoadSettings(RawrXD_IDE* ide);

// Save all settings to INI file
bool SaveSettings(const RawrXD_IDE* ide);

// Individual setting loaders
bool LoadWindowPosition(RawrXD_IDE* ide);
bool LoadEditorSettings(RawrXD_IDE* ide);
bool LoadThemeSettings(RawrXD_IDE* ide);
bool LoadModelPath(RawrXD_IDE* ide);
bool LoadRecentFiles(RawrXD_IDE* ide);

// Individual setting savers
bool SaveWindowPosition(const RawrXD_IDE* ide);
bool SaveEditorSettings(const RawrXD_IDE* ide);
bool SaveThemeSettings(const RawrXD_IDE* ide);
bool SaveModelPath(const RawrXD_IDE* ide);
bool SaveRecentFiles(const RawrXD_IDE* ide);

// Helper functions
std::wstring GetIniString(const wchar_t* section, const wchar_t* key, const wchar_t* defaultValue);
int GetIniInt(const wchar_t* section, const wchar_t* key, int defaultValue);
bool GetIniBool(const wchar_t* section, const wchar_t* key, bool defaultValue);
void WriteIniString(const wchar_t* section, const wchar_t* key, const wchar_t* value);
void WriteIniInt(const wchar_t* section, const wchar_t* key, int value);
void WriteIniBool(const wchar_t* section, const wchar_t* key, bool value);

} // namespace IDE
} // namespace RawrXD
