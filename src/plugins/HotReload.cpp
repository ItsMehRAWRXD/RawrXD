// ============================================================================
// HotReload.cpp — Hot Module Reload Manager Implementation
// ============================================================================

#include "HotReload.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <chrono>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {

HotReload& HotReload::Get() {
    static HotReload instance;
    return instance;
}

void HotReload::Initialize() {
    RawrRuntime::Get().Log(LogLevel::Info, "HotReload initialized");
}

void HotReload::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_watched.clear();
}

bool HotReload::Watch(const char* moduleId, const char* path) {
    if (!moduleId || !path) return false;
    std::lock_guard<std::mutex> lock(m_mutex);

    // Check if already watched
    auto it = std::find_if(m_watched.begin(), m_watched.end(),
        [moduleId](const WatchEntry& e) { return e.moduleId == moduleId; });
    if (it != m_watched.end()) return true;

    WatchEntry entry;
    entry.moduleId = moduleId;
    entry.path = path;
    entry.lastModified = 0;

    m_watched.push_back(entry);
    return true;
}

bool HotReload::Unwatch(const char* moduleId) {
    if (!moduleId) return false;
    std::lock_guard<std::mutex> lock(m_mutex);

    m_watched.erase(
        std::remove_if(m_watched.begin(), m_watched.end(),
            [moduleId](const WatchEntry& e) { return e.moduleId == moduleId; }),
        m_watched.end()
    );
    return true;
}

bool HotReload::Reload(const char* moduleId) {
    if (!moduleId) return false;

    if (m_onBeforeReload && !m_onBeforeReload(moduleId)) {
        return false;
    }

    m_reloadCount++;

    if (m_onAfterReload && !m_onAfterReload(moduleId)) {
        return false;
    }

    RawrRuntime::Get().Log(LogLevel::Info, "Module reloaded");
    return true;
}

bool HotReload::ReloadAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    bool allSuccess = true;
    for (const auto& entry : m_watched) {
        if (!Reload(entry.moduleId.c_str())) {
            allSuccess = false;
        }
    }
    return allSuccess;
}

} // namespace rawr
