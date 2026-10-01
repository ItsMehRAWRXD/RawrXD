// Win32IDE_Settings.cpp — persistent settings backed by ini file
//
// RAWRXD_SETTINGS_PERSISTENCE_001
//
// Before this pass Settings_Load() had zero callers anywhere in the tree, so
// g_settingsPath was never assigned and Settings_Save() returned at its first
// line. The settings dialog was reachable from the File menu and every edit was
// discarded on exit. This file is now the single canonical settings authority
// for the Win32 IDE: one resolved path, one load path, one save path.
//
// Path resolution order (first hit wins):
//   1. RAWRXD_SETTINGS_PATH environment variable (exact file, enterprise policy
//      override and the automation seam used by the runtime gate)
//   2. %LOCALAPPDATA%\RawrXD\settings.ini   (per-user, survives exe relocation)
//   3. <exe dir>\settings.ini                (last-resort fallback)
//
// Malformed input is never silently half-loaded. A file that exists but
// yields no usable keys while containing rejected lines is quarantined to
// <path>.bad and the authority restarts from defaults, so the next save cannot
// be an empty file that destroys whatever the operator had configured.

#include <windows.h>
#include <shlobj.h>
#include <string>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdio>
#include <cstdlib>

#include "Win32IDE_Settings.h"

namespace RawrXD::IDE {

static std::unordered_map<std::string, std::string> g_settings;
static std::string g_settingsPath;

static SettingsDiagnostics g_diag;

const SettingsDiagnostics& Settings_Diagnostics() { return g_diag; }

bool Settings_GetResolvedPath(std::string& out) {
    if (g_settingsPath.empty()) return false;
    out = g_settingsPath;
    return true;
}

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

// Deterministic settings file location. See header comment for the order.
static std::string resolveDefaultSettingsPath() {
    if (const char* env = std::getenv("RAWRXD_SETTINGS_PATH")) {
        if (env[0] != '\0') return std::string(env);
    }

    // shell32 only: no COM apartment required, unlike SHGetKnownFolderPath.
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

    std::ifstream f(g_settingsPath);
    if (!f) {
        g_diag.lastError = "settings file absent (first run)";
        return;
    }
    g_diag.fileExisted = true;

    std::vector<std::string> rejected;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line[0] == '#' || line[0] == ';') continue;
        if (line[0] == '[') continue;               // section header, not a key
        auto eq = line.find('=');
        if (eq == std::string::npos) { rejected.push_back(line); continue; }

        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        while (!k.empty() && (k.back() == ' ' || k.back() == '\t')) k.pop_back();
        while (!k.empty() && (k.front() == ' ' || k.front() == '\t')) k.erase(k.begin());
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.erase(v.begin());
        while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.pop_back();
        if (k.empty()) { rejected.push_back(line); continue; }
        g_settings[k] = v;
    }
    f.close();

    g_diag.keysLoaded = g_settings.size();
    g_diag.linesRejected = rejected.size();

    // Recover-safe: an existing file that yielded nothing usable while
    // containing rejected lines is quarantined rather than trusted. Starting
    // from defaults and overwriting would destroy the operator's configuration.
    if (g_diag.keysLoaded == 0 && g_diag.linesRejected > 0) {
        std::string bad = g_settingsPath + ".bad";
        g_diag.quarantineAttempted = true;
        if (MoveFileA(g_settingsPath.c_str(), bad.c_str())) {
            g_diag.quarantinePath = bad;
            g_diag.recovered = true;
            g_settings.clear();
        } else {
            g_diag.lastError = "malformed settings file could not be quarantined";
            // Keep the parsed state authoritative; do not report a clean start.
            g_diag.recovered = false;
        }
    }
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

    std::string body;
    body += "# RawrXD Settings\n";
    body += "# RAWRXD_SETTINGS_PERSISTENCE_001\n";
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
        // ReplaceFileA fails when the destination does not exist yet (first
        // run) and on filesystems without ReplaceFile support.
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

size_t Settings_Count() { return g_settings.size(); }

} // namespace RawrXD::IDE