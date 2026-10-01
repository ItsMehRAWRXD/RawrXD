// Win32IDE_Settings.h — canonical settings authority surface for the Win32 IDE
//
// RAWRXD_SETTINGS_PERSISTENCE_001
//
// One canonical model, one load path, one save path, one diagnostics surface.
// See Win32IDE_Settings.cpp for path resolution order and malformed-input
// recovery policy.
//
// Prior to this pass Settings_Load() had no caller anywhere in the tree, so
// g_settingsPath was never assigned and Settings_Save() returned at its first
// line. Any gate that depended on a setting was reading defaults that could
// never be changed by the user.

#pragma once
#include <string>
#include <cstddef>

namespace RawrXD::IDE {

// Every field is measured at runtime. Nothing here is defaulted to a healthy
// value by construction: loadCalled/pathResolved/fileExisted start false,
// recovered starts false, and the counters start at zero.
struct SettingsDiagnostics {
    bool        loadCalled = false;
    bool        pathResolved = false;
    bool        fileExisted = false;
    bool        recovered = false;
    bool        quarantineAttempted = false;
    std::size_t keysLoaded = 0;
    std::size_t linesRejected = 0;
    std::size_t saveCalled = 0;
    std::size_t saveBytesWritten = 0;
    bool        saveWroteFile = false;
    std::string quarantinePath;
    std::string lastError;
};

const SettingsDiagnostics& Settings_Diagnostics();
bool Settings_GetResolvedPath(std::string& out);
bool Settings_EnsureLoaded();

// Original entry points, unchanged signatures. SettingsGUI and CICD declare
// these locally; they remain source-compatible.
void Settings_Load(const std::string& path);
void Settings_Save();
void Settings_Set(const std::string& key, const std::string& value);
std::string Settings_Get(const std::string& key, const std::string& def);
int Settings_GetInt(const std::string& key, int def);
bool Settings_GetBool(const std::string& key, bool def);
void Settings_SetInt(const std::string& key, int v);
void Settings_SetBool(const std::string& key, bool v);

// Boolean form used by the runtime receipt.
bool Settings_Persist();
std::size_t Settings_Count();

} // namespace RawrXD::IDE