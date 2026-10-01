// Win32IDE_Settings.cpp — canonical settings authority for the Win32 IDE
//
// RAWRXD_SETTINGS_PERSISTENCE_001  (persistence, closed PASS)
// RAWRXD_SETTINGS_AUTHORITY_001    (consolidation + schema + migration)
//
// Path resolution order (first hit wins):
//   1. RAWRXD_SETTINGS_PATH environment variable (exact file; enterprise policy
//      override and the automation seam used by the runtime gate)
//   2. %LOCALAPPDATA%\RawrXD\settings.ini   (per-user, survives exe relocation)
//   3. <exe dir>\settings.ini                (last-resort fallback)
//
// Malformed input is never silently half-loaded. A file that exists but yields
// no usable keys while containing rejected lines is quarantined to <path>.bad
// and the authority restarts from defaults, so the next save cannot be an empty
// file that destroys whatever the operator had configured.

#include <windows.h>
#include <shlobj.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <algorithm>

#include "Win32IDE_Settings.h"
#include "core/ConfigurationValidator.h"

namespace RawrXD::IDE {

static std::unordered_map<std::string, std::string> g_settings;
static std::string g_settingsPath;
static SettingsDiagnostics g_diag;
static bool g_schemaRegistered = false;

const SettingsDiagnostics& Settings_Diagnostics() { return g_diag; }

bool Settings_GetResolvedPath(std::string& out) {
    if (g_settingsPath.empty()) return false;
    out = g_settingsPath;
    return true;
}

// ---------------------------------------------------------------------------
// Canonical schema
//
// This is the single list of settings the product understands. Anything in a
// settings file that is not in this table is reported as an unknown key rather
// than being read as if the product had honoured it. The table is the reason
// the four previously-competing implementations can be collapsed: the schema is
// declared once, here.
// ---------------------------------------------------------------------------

namespace {

enum class Kind { PositiveInt, Boolean, NonEmpty, RootedPath, Version };

struct SchemaEntry {
    const char* key;
    Kind        kind;
    const char* error;
};

const SchemaEntry kSchema[] = {
    { "editor.fontSize",         Kind::PositiveInt, "font size must be a positive integer" },
    { "editor.tabSize",          Kind::PositiveInt, "tab size must be a positive integer" },
    { "editor.theme",            Kind::NonEmpty,     "theme must not be empty" },
    { "editor.wordWrap",         Kind::Boolean,      "word wrap must be true/false/1/0" },
    { "editor.minimap",          Kind::Boolean,      "minimap must be true/false/1/0" },
    { "editor.autoSave",         Kind::Boolean,      "auto save must be true/false/1/0" },
    { "lsp.serverPath",          Kind::RootedPath,   "lsp server path must be an absolute path" },
    { "lsp.enabled",             Kind::Boolean,      "lsp enabled must be true/false/1/0" },
    { "mcp.serverCmd",           Kind::NonEmpty,     "mcp server command must not be empty" },
    { "mcp.enabled",             Kind::Boolean,      "mcp enabled must be true/false/1/0" },
    { "terminal.fontSize",       Kind::PositiveInt,  "terminal font size must be a positive integer" },
    { "terminal.shell",          Kind::NonEmpty,     "terminal shell must not be empty" },
    { "search.maxResults",       Kind::PositiveInt,  "search max results must be a positive integer" },
    { "agent.maxSteps",          Kind::PositiveInt,  "agent max steps must be a positive integer" },
    { "telemetry.enabled",       Kind::Boolean,      "telemetry enabled must be true/false/1/0" },
    { "settings.schemaVersion",  Kind::Version,      "schema version must be a positive integer" },
};

const std::unordered_set<std::string>& knownKeys() {
    static const std::unordered_set<std::string> s = [] {
        std::unordered_set<std::string> t;
        for (const auto& e : kSchema) t.insert(e.key);
        return t;
    }();
    return s;
}

const SchemaEntry* findSchema(const std::string& key) {
    for (const auto& e : kSchema) {
        if (key == e.key) return &e;
    }
    return nullptr;
}

bool isStrictMode() {
    const char* v = std::getenv("RAWRXD_SETTINGS_STRICT");
    return v && (v[0] == '1' || v[0] == 't' || v[0] == 'T');
}

// Wraps a private validator so it matches the std::function signature the
// ConfigurationValidator expects, while the truth of the check stays here where
// the schema table is.
struct SchemaRuleAdapter {
    static bool check(const SchemaEntry& e, const std::string& v) {
        switch (e.kind) {
        case Kind::PositiveInt:
        case Kind::Version: {
            try {
                int n = std::stoi(v);
                return n > 0;
            } catch (...) { return false; }
        }
        case Kind::Boolean: {
            std::string l = v;
            std::transform(l.begin(), l.end(), l.begin(), ::tolower);
            return l == "true" || l == "false" || l == "1" || l == "0";
        }
        case Kind::NonEmpty:
            return !v.empty();
        case Kind::RootedPath:
            return !v.empty() && (v.size() > 1 && (v[1] == ':' || v[0] == '\\' || v[0] == '/'));
        }
        return true;
    }
};

} // namespace

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

static std::string exeDirPath() {
    wchar_t buf[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, buf, MAX_PATH) == 0) return "";
    std::wstring wpath(buf);
    size_t lastSlash = wpath.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) wpath.resize(lastSlash);
    int len = WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string result(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, &result[0], len, nullptr, nullptr);
    while (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

// shell32 only: no COM apartment required, unlike SHGetKnownFolderPath.
static std::string resolveDefaultSettingsPath() {
    if (const char* env = std::getenv("RAWRXD_SETTINGS_PATH")) {
        if (env[0] != '\0') return std::string(env);
    }

    char localAppData[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData))) {
        std::string base(localAppData);
        if (!base.empty()) {
            CreateDirectoryA((base + "\\RawrXD").c_str(), nullptr);
            return base + "\\RawrXD\\settings.ini";
        }
    }

    std::string dir = exeDirPath();
    if (!dir.empty()) return dir + "\\settings.ini";
    return "settings.ini";
}

// ---------------------------------------------------------------------------
// Schema registration — makes the real ConfigurationValidator reachable
// ---------------------------------------------------------------------------

void Settings_RegisterSchema() {
    if (g_schemaRegistered) return;
    g_schemaRegistered = true;

    auto& validator = RawrXD::Core::ConfigurationValidator::instance();
    validator.setStrictMode(isStrictMode());

    for (const auto& e : kSchema) {
        // The predicate is bound to this schema entry, so the validator needs no
        // knowledge of the schema table itself.
        const SchemaEntry* entry = &e;
        RawrXD::Core::ValidationRule rule;
        rule.name = e.key;
        rule.errorMessage = e.error;
        // Nothing is "required": an absent key means "use the built-in default",
        // and demanding every key would make an empty first-run file invalid.
        rule.required = false;
        rule.validator = [entry](const std::string& v) { return SchemaRuleAdapter::check(*entry, v); };
        validator.addRule("settings", rule);
    }
}

// ---------------------------------------------------------------------------
// Migration
//
// A real, observable ladder rather than a TODO. Version 0 means the file predates
// versioning and its keys were unscoped; version 1 scopes them. The legacy
// names below are the flat keys the original settings dialog and the pre-scoped
// config files used.
// ---------------------------------------------------------------------------

namespace {

struct MigrationStep {
    int from;
    int to;
    const char* legacyKey;
    const char* scopedKey;
};

const MigrationStep kMigrations[] = {
    { 0, 1, "fontSize",    "editor.fontSize"    },
    { 0, 1, "theme",       "editor.theme"       },
    { 0, 1, "tabSize",     "editor.tabSize"     },
    { 0, 1, "wordWrap",    "editor.wordWrap"    },
    { 0, 1, "minimap",     "editor.minimap"     },
    { 0, 1, "autoSave",    "editor.autoSave"    },
    { 0, 1, "serverPath",  "lsp.serverPath"     },
    { 0, 1, "serverCmd",   "mcp.serverCmd"      },
    { 0, 1, "shell",       "terminal.shell"     },
    { 0, 1, "maxResults",  "search.maxResults"  },
    { 0, 1, "maxSteps",    "agent.maxSteps"     },
};

} // namespace

bool Settings_Migrate() {
    int version = -1;
    auto it = g_settings.find("settings.schemaVersion");
    if (it != g_settings.end()) {
        try { version = std::stoi(it->second); } catch (...) { version = -1; }
    }
    g_diag.versionFound = version;
    g_diag.migrationRan = true;

    if (version > kSettingsSchemaVersion) {
        // A newer build wrote this file. Do not silently downgrade its data.
        g_diag.lastError = "settings schema version " + std::to_string(version) +
                           " is newer than this build supports (" +
                           std::to_string(kSettingsSchemaVersion) + ")";
        return false;
    }

    if (version < 0) version = 0;   // pre-versioned file

    while (version < kSettingsSchemaVersion) {
        for (const auto& step : kMigrations) {
            if (step.from != version) continue;
            auto legacy = g_settings.find(step.legacyKey);
            if (legacy == g_settings.end()) continue;
            const std::string value = legacy->second;
            // A scoped value already present wins; never clobber newer config
            // with a legacy duplicate.
            if (g_settings.find(step.scopedKey) == g_settings.end()) {
                g_settings[step.scopedKey] = value;
                g_settings.erase(legacy);
                g_diag.migratedKeys.push_back(std::string(step.legacyKey) + " -> " + step.scopedKey);
                g_diag.migrationChangedKeys = true;
            } else {
                g_settings.erase(legacy);
                g_diag.migratedKeys.push_back(std::string(step.legacyKey) + " -> " +
                                              step.scopedKey + " (dropped: scoped value already set)");
                g_diag.migrationChangedKeys = true;
            }
        }
        ++version;
    }

    g_diag.versionWritten = kSettingsSchemaVersion;
    g_settings["settings.schemaVersion"] = std::to_string(kSettingsSchemaVersion);
    return true;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

bool Settings_Validate() {
    Settings_RegisterSchema();
    auto& validator = RawrXD::Core::ConfigurationValidator::instance();
    validator.setStrictMode(isStrictMode());

    // Unknown-key census happens regardless of strict mode. An unknown key is
    // not an error, but reading one as if the product honoured it is a lie, so
    // it is always counted and named.
    g_diag.unknownKeys = 0;
    g_diag.rejectedKeys.clear();
    for (const auto& [k, v] : g_settings) {
        (void)v;
        if (knownKeys().find(k) == knownKeys().end()) {
            ++g_diag.unknownKeys;
            g_diag.rejectedKeys.push_back(k);
        }
    }

    const auto result = validator.validateSection("settings", g_settings);
    g_diag.validationRan = true;
    g_diag.validationValid = result.valid;
    g_diag.validationErrors = result.errors.size();
    g_diag.validationWarnings = result.warnings.size();
    g_diag.validationMessages = result.errors;
    g_diag.validationMessages.insert(g_diag.validationMessages.end(),
                                     result.warnings.begin(), result.warnings.end());

    if (!result.valid && isStrictMode()) {
        // Fail closed: re-check each schema-typed key directly and drop only the
        // ones the schema itself rejects. This deliberately does not parse the
        // validator's error strings — the schema table is the authority, and
        // message text is a rendering of it, not the thing to act on.
        std::vector<std::string> dropped;
        for (const auto& [k, v] : g_settings) {
            const SchemaEntry* e = findSchema(k);
            if (!e) continue;                       // unknown keys are handled above
            if (SchemaRuleAdapter::check(*e, v)) continue;
            dropped.push_back(k);
        }
        for (const auto& k : dropped) g_settings.erase(k);
        g_diag.validationMessages.push_back(
            "strict mode: dropped " + std::to_string(dropped.size()) + " schema-invalid key(s)");
    }

    return result.valid;
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

void Settings_Load(const std::string& path)
{
    g_diag = SettingsDiagnostics{};
    g_diag.loadCalled = true;
    g_settingsPath = path.empty() ? resolveDefaultSettingsPath() : path;
    g_diag.pathResolved = !g_settingsPath.empty();
    g_settings.clear();

    if (g_settingsPath.empty()) {
        g_diag.lastError = "settings path could not be resolved";
        return;
    }

    Settings_RegisterSchema();

    std::ifstream f(g_settingsPath);
    if (!f) {
        g_diag.lastError = "settings file absent (first run)";
    } else {
        g_diag.fileExisted = true;

        std::size_t rejected = 0;
        std::string line;
        while (std::getline(f, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            if (line[0] == '#' || line[0] == ';') continue;
            if (line[0] == '[') continue;               // section header, not a key
            auto eq = line.find('=');
            if (eq == std::string::npos) { ++rejected; continue; }

            std::string k = line.substr(0, eq);
            std::string v = line.substr(eq + 1);
            while (!k.empty() && (k.back() == ' ' || k.back() == '\t')) k.pop_back();
            while (!k.empty() && (k.front() == ' ' || k.front() == '\t')) k.erase(k.begin());
            while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.erase(v.begin());
            while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.pop_back();
            if (k.empty()) { ++rejected; continue; }
            g_settings[k] = v;
        }
        f.close();

        g_diag.keysLoaded = g_settings.size();
        g_diag.linesRejected = rejected;

        // Recover-safe: an existing file that yielded nothing usable while
        // containing rejected lines is quarantined rather than trusted.
        if (g_diag.keysLoaded == 0 && g_diag.linesRejected > 0) {
            std::string bad = g_settingsPath + ".bad";
            g_diag.quarantineAttempted = true;
            if (MoveFileA(g_settingsPath.c_str(), bad.c_str())) {
                g_diag.quarantinePath = bad;
                g_diag.recovered = true;
                g_settings.clear();
            } else {
                g_diag.lastError = "malformed settings file could not be quarantined";
                g_diag.recovered = false;
            }
        }
    }

    // Migration runs before validation so a legacy file is brought onto the
    // current schema and then checked, rather than being reported as a wall of
    // unknown keys.
    (void)Settings_Migrate();
    (void)Settings_Validate();
}

// Idempotent startup entry point. Safe to call from WM_CREATE.
bool Settings_EnsureLoaded() {
    if (!g_diag.loadCalled || g_settingsPath.empty()) {
        Settings_Load(g_diag.loadCalled ? g_settingsPath : std::string());
        return g_diag.pathResolved;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Save
// ---------------------------------------------------------------------------

static bool persistToDisk() {
    if (g_settingsPath.empty()) {
        g_diag.lastError = "settings path unset; refusing to write";
        return false;
    }

    // Stamp the version on every write so a file that somehow lost it is
    // re-stamped rather than staying pre-versioned forever.
    g_diag.versionWritten = kSettingsSchemaVersion;
    g_settings["settings.schemaVersion"] = std::to_string(kSettingsSchemaVersion);

    std::string body;
    body += "# RawrXD Settings\n";
    body += "# RAWRXD_SETTINGS_PERSISTENCE_001\n";
    body += "# RAWRXD_SETTINGS_AUTHORITY_001 schemaVersion=" +
            std::to_string(kSettingsSchemaVersion) + "\n";
    for (const auto& [k, v] : g_settings) body += k + " = " + v + "\n";

    // Atomic replace: write a sibling temp, then swap. A crash mid-write must
    // not leave a truncated configuration behind.
    const std::string tmp = g_settingsPath + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            g_diag.lastError = "settings temp file could not be opened for write";
            return false;
        }
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
        out.flush();
        if (!out.good()) {
            out.close();
            DeleteFileA(tmp.c_str());
            g_diag.lastError = "settings write failed";
            return false;
        }
    }

    if (!ReplaceFileA(g_settingsPath.c_str(), tmp.c_str(), nullptr, 0, nullptr, nullptr)) {
        // ReplaceFileA fails when the destination does not exist yet (first run)
        // and on filesystems without ReplaceFile support.
        if (MoveFileExA(tmp.c_str(), g_settingsPath.c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            g_diag.saveBytesWritten = body.size();
            g_diag.saveWroteFile = true;
            return true;
        }
        DWORD err = GetLastError();
        DeleteFileA(tmp.c_str());
        char msg[128] = {};
        snprintf(msg, sizeof(msg), "settings atomic replace failed (winerr=%lu)",
                 static_cast<unsigned long>(err));
        g_diag.lastError = msg;
        return false;
    }

    g_diag.saveBytesWritten = body.size();
    g_diag.saveWroteFile = true;
    return true;
}

// Returns whether a real file was written. Settings_Save() keeps its original
// void signature because CICDSettings.cpp and Win32IDE_SettingsGUI.cpp declare
// it that way; the boolean form is for the runtime receipt.
bool Settings_Persist() {
    ++g_diag.saveCalled;
    if (!Settings_Validate() && isStrictMode()) {
        g_diag.saveBlockedByValidation = true;
        g_diag.lastError = "save blocked: schema validation failed in strict mode";
        return false;
    }
    return persistToDisk();
}

void Settings_Save()
{
    (void)Settings_Persist();
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

void Settings_Set(const std::string& key, const std::string& value)
{
    g_settings[key] = value;
}

std::string Settings_Get(const std::string& key, const std::string& def)
{
    auto it = g_settings.find(key);
    return it != g_settings.end() ? it->second : def;
}

int Settings_GetInt(const std::string& key, int def)
{
    auto it = g_settings.find(key);
    if (it == g_settings.end()) return def;
    try { return std::stoi(it->second); } catch (...) { return def; }
}

bool Settings_GetBool(const std::string& key, bool def)
{
    auto it = g_settings.find(key);
    if (it == g_settings.end()) return def;
    return it->second == "1" || it->second == "true" || it->second == "yes";
}

void Settings_SetInt (const std::string& k, int  v) { g_settings[k] = std::to_string(v); }
void Settings_SetBool(const std::string& k, bool v) { g_settings[k] = v ? "1" : "0"; }

std::size_t Settings_Count() { return g_settings.size(); }

} // namespace RawrXD::IDE