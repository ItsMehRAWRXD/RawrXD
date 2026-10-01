// settings_persistence.h — RAWRXD_CORE_HEADERS_PRESENT_001
//
// This header did not exist. src/core/settings_persistence.cpp and
// src/core/session_manager.cpp both include it, so neither could compile, and
// neither is in any build target — the same invisible-defect shape as
// file_watcher.h.
//
// The JSON-backed settings store here is superseded as the *product* authority
// by src/win32app/Win32IDE_Settings.h (one canonical model, one load, one save,
// one schema, one migration hook, and it is the only one linked into the IDE).
// This class is retained as the atomically-replacing JSON store for non-IDE
// consumers; it is deliberately NOT wired into the IDE a second time.
#pragma once

#include <mutex>
#include <string>

#include <nlohmann/json.hpp>

namespace RawrXD::Core {

class SettingsPersistence {
public:
    static SettingsPersistence& getInstance();

    // Reads `path` as JSON. On failure (absent or unparsable) the store is reset
    // to an empty object and false is returned; the caller decides whether that
    // is fatal. Never leaves a partially parsed document in place.
    bool load(const std::string& path);

    // Atomic: writes to <path>.tmp, then ReplaceFileA, with a delete+rename
    // fallback for filesystems without ReplaceFile support.
    bool save();

    nlohmann::json get(const std::string& key,
                       const nlohmann::json& defaultVal = nlohmann::json()) const;
    void   set(const std::string& key, const nlohmann::json& value);
    void   remove(const std::string& key);
    void   clear();

    const std::string& path() const { return m_path; }
    bool hasPath() const { return !m_path.empty(); }

private:
    SettingsPersistence() = default;

    mutable std::mutex      m_mutex;
    std::string             m_path;
    nlohmann::json          m_data = nlohmann::json::object();
};

} // namespace RawrXD::Core
