// backend_preferences.h - shared chat-backend preference resolver (CLI + IDE).
//
// Single source of truth for the persisted chat backend so `rawr backend
// select` and the native IDE cannot disagree. Header-only (all inline) so no
// build-system change is required.
//
// Precedence (highest first):
//   1. explicit request / command-line override
//   2. RAWRXD_BACKEND environment variable
//   3. persisted preference (this file)
//   4. registered default ("auto")
// Legacy RAWRXD_CHAT_BACKEND is consulted only as a migration fallback.
//
// The persisted store lives in a portable, writable application-state directory
// (%LOCALAPPDATA%\RawrXD). The old hardcoded F:\rawrxd\.rawrxd location is read
// once for migration only. Saves are atomic (temp file + rename) so a concurrent
// reader never observes a truncated file.
#pragma once

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <utility>

namespace rawrxd {
namespace prefs {

// Canonical backend ids: native | deep2 | strata | ollama | auto.
// Returns "" for an unrecognized value.
inline std::string normalize(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    while (!s.empty() && static_cast<unsigned char>(s.back()) <= ' ') s.pop_back();
    if (s == "native" || s == "deep2-native" || s == "gguf") return "native";
    if (s == "deep2" || s == "local") return "deep2";
    if (s == "strata") return "strata";
    if (s == "ollama" || s == "http") return "ollama";
    if (s == "auto" || s == "default" || s.empty()) return "auto";
    return {};
}

// Portable, writable application-state directory.
inline std::filesystem::path stateDir() {
    if (const char* la = std::getenv("LOCALAPPDATA"); la && *la)
        return std::filesystem::path(la) / "RawrXD";
    if (const char* up = std::getenv("USERPROFILE"); up && *up)
        return std::filesystem::path(up) / "AppData" / "Local" / "RawrXD";
    std::error_code ec;
    return std::filesystem::current_path(ec) / ".rawrxd";
}

inline std::filesystem::path prefPath() { return stateDir() / "backend_pref.txt"; }

// Legacy location, read only for one-time migration.
inline std::filesystem::path legacyPrefPath() {
    return std::filesystem::path(R"(F:\rawrxd\.rawrxd\cli_backend_pref.txt)");
}

inline std::string readFirst(const std::filesystem::path& p) {
    std::ifstream in(p);
    if (!in) return {};
    std::string s;
    std::getline(in, s);
    return normalize(s);
}

// Persist atomically (temp file + rename).
inline bool savePersisted(const std::string& pref) {
    const std::string store = normalize(pref);
    if (store.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(stateDir(), ec);
    const std::filesystem::path target = prefPath();
    const std::filesystem::path tmp =
        std::filesystem::path(std::string(target.string()) + ".tmp");
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) return false;
        out << store << "\n";
        if (!out) return false;
    }
    std::filesystem::rename(tmp, target, ec);
    if (ec) {
        std::filesystem::remove(target, ec);
        std::filesystem::rename(tmp, target, ec);
    }
    return !ec;
}

// Persisted preference, migrating from the legacy location on first use.
inline std::string loadPersisted() {
    const std::string v = readFirst(prefPath());
    if (v == "auto") return "auto";
    if (!v.empty()) return v;
    const std::string legacy = readFirst(legacyPrefPath());
    if (!legacy.empty()) {
        savePersisted(legacy);
        return legacy;
    }
    return "auto";
}

// Resolve the effective backend. `explicitOrEmpty` is the command-line override.
inline std::string resolve(const std::string& explicitOrEmpty) {
    std::string e = normalize(explicitOrEmpty);
    if (!e.empty() && e != "auto") return e;
    if (const char* env = std::getenv("RAWRXD_BACKEND")) {
        std::string v = normalize(env);
        if (!v.empty() && v != "auto") return v;
    }
    std::string p = loadPersisted();
    if (!p.empty() && p != "auto") return p;
    if (const char* legacy = std::getenv("RAWRXD_CHAT_BACKEND")) {
        std::string v = normalize(legacy);
        if (!v.empty() && v != "auto") return v;
    }
    return "auto";
}

} // namespace prefs
} // namespace rawrxd