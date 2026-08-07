// ============================================================================
// HotReload.hpp — Hot Module Reload Manager
// Safe runtime reload of plugins and modules
// ============================================================================

#ifndef HOT_RELOAD_HPP
#define HOT_RELOAD_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <mutex>

namespace rawr {

// ============================================================================
// HotReload — Manages runtime reload of components
// ============================================================================
class HotReload {
public:
    static HotReload& Get();

    void Initialize();
    void Shutdown();

    // Watch a module for changes
    bool Watch(const char* moduleId, const char* path);
    bool Unwatch(const char* moduleId);

    // Trigger reload
    bool Reload(const char* moduleId);
    bool ReloadAll();

    // Callbacks
    using ReloadCallback = std::function<bool(const char* moduleId)>;
    void SetOnBeforeReload(ReloadCallback cb) { m_onBeforeReload = std::move(cb); }
    void SetOnAfterReload(ReloadCallback cb) { m_onAfterReload = std::move(cb); }

    // Status
    uint32_t GetWatchedCount() const { return static_cast<uint32_t>(m_watched.size()); }
    uint32_t GetReloadCount() const { return m_reloadCount; }

private:
    HotReload() = default;
    ~HotReload() = default;
    HotReload(const HotReload&) = delete;
    HotReload& operator=(const HotReload&) = delete;

    struct WatchEntry {
        std::string moduleId;
        std::string path;
        uint64_t lastModified;
    };

    std::vector<WatchEntry> m_watched;
    uint32_t m_reloadCount = 0;
    ReloadCallback m_onBeforeReload;
    ReloadCallback m_onAfterReload;
    mutable std::mutex m_mutex;
};

} // namespace rawr

#endif // HOT_RELOAD_HPP
