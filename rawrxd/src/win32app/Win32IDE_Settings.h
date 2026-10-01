// Win32IDE_Settings.h — canonical settings authority for the Win32 IDE
//
// RAWRXD_SETTINGS_PERSISTENCE_001  (persistence)
// RAWRXD_SETTINGS_AUTHORITY_001    (consolidation + schema + migration)
//
// One canonical model, one load path, one save path, one schema, one migration
// hook. See Win32IDE_Settings.cpp for the schema table, the migration ladder,
// and the malformed-input recovery policy.
//
// History that this file exists to prevent: Settings_Load() originally had no
// caller anywhere in the tree, so g_settingsPath was never assigned and
// Settings_Save() returned at its first line. Any gate that read a setting read a
// value no user could change.

#pragma once
#include <string>
#include <cstddef>
#include <vector>

namespace RawrXD::IDE {

// The settings schema version this build writes and expects. Migration runs
// every older version forward to this number on load.
constexpr int kSettingsSchemaVersion = 1;

// Every field is measured at runtime. Nothing here defaults to a healthy value
// by construction: the booleans start false and the counters start at zero, so
// a receipt cannot report PASS without the operation actually having run.
struct SettingsDiagnostics {
    // --- load ---
    bool        loadCalled = false;
    bool        pathResolved = false;
    bool        fileExisted = false;
    bool        recovered = false;
    bool        quarantineAttempted = false;
    std::size_t keysLoaded = 0;
    std::size_t linesRejected = 0;
    std::string quarantinePath;
    std::string lastError;

    // --- schema validation (RawrXD::Core::ConfigurationValidator) ---
    bool              validationRan = false;
    bool              validationValid = false;
    std::size_t       validationErrors = 0;
    std::size_t       validationWarnings = 0;
    std::size_t       unknownKeys = 0;
    std::vector<std::string> rejectedKeys;   // present in file, not in schema
    std::vector<std::string> validationMessages;

    // --- migration ---
    int         versionFound = -1;          // -1 = key absent (pre-versioned)
    int         versionWritten = 0;
    bool        migrationRan = false;
    bool        migrationChangedKeys = false;
    std::vector<std::string> migratedKeys;  // "old -> new"

    // --- save ---
    std::size_t saveCalled = 0;
    std::size_t saveBytesWritten = 0;
    bool        saveWroteFile = false;
    bool        saveBlockedByValidation = false;
};

const SettingsDiagnostics& Settings_Diagnostics();
bool Settings_GetResolvedPath(std::string& out);
bool Settings_EnsureLoaded();

// Original entry points, unchanged signatures. Win32IDE_SettingsGUI.cpp and
// CICDSettings.cpp declare these locally; they remain source-compatible.
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

// --- schema surface -------------------------------------------------------
// Registers the canonical schema into RawrXD::Core::ConfigurationValidator.
// Idempotent; called automatically by Settings_Load.
void Settings_RegisterSchema();

// Validates the in-memory map. On failure in strict mode the offending key is
// dropped so a bad value cannot be persisted back over a good file.
bool Settings_Validate();

// Runs every migration step between the file's version and kSettingsSchemaVersion.
bool Settings_Migrate();

} // namespace RawrXD::IDE