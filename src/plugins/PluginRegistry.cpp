// ============================================================================
// PluginRegistry.cpp — Native Plugin Registry Implementation
// ============================================================================

#include "PluginRegistry.hpp"
#include "../runtime/RawrRuntime.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {

PluginRegistry& PluginRegistry::Get() {
    static PluginRegistry instance;
    return instance;
}

bool PluginRegistry::Initialize() {
    RawrRuntime::Get().Log(LogLevel::Info, "PluginRegistry initialized");
    return true;
}

void PluginRegistry::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [id, plugin] : m_plugins) {
        if (plugin.loaded) {
            UnloadPlugin(id.c_str());
        }
    }
    m_plugins.clear();
}

bool PluginRegistry::RegisterPlugin(const char* id, const char* name, const char* version) {
    if (!id) return false;
    std::lock_guard<std::mutex> lock(m_mutex);

    PluginInfo info;
    info.id = id;
    info.name = name ? name : id;
    info.version = version ? version : "0.0.0";
    info.handle = nullptr;
    info.loaded = false;
    info.enabled = false;

    m_plugins[id] = info;
    return true;
}

bool PluginRegistry::UnregisterPlugin(const char* id) {
    if (!id) return false;
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_plugins.find(id);
    if (it == m_plugins.end()) return false;

    if (it->second.loaded) {
        UnloadPlugin(id);
    }

    m_plugins.erase(it);
    return true;
}

bool PluginRegistry::LoadPlugin(const char* id, const char* path) {
    if (!id || !path) return false;
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_plugins.find(id);
    if (it == m_plugins.end()) return false;
    if (it->second.loaded) return true;

#ifdef _WIN32
    HMODULE hMod = LoadLibraryA(path);
    if (!hMod) {
        RawrRuntime::Get().Log(LogLevel::Error, "Failed to load plugin DLL");
        return false;
    }

    it->second.handle = hMod;
    it->second.loaded = true;
    it->second.enabled = true;

    RawrRuntime::Get().Log(LogLevel::Info, "Plugin loaded");
    return true;
#else
    RawrRuntime::Get().Log(LogLevel::Warn, "Plugin loading not supported on this platform");
    return false;
#endif
}

bool PluginRegistry::UnloadPlugin(const char* id) {
    if (!id) return false;
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_plugins.find(id);
    if (it == m_plugins.end() || !it->second.loaded) return false;

#ifdef _WIN32
    if (it->second.handle) {
        FreeLibrary((HMODULE)it->second.handle);
    }
#endif

    it->second.handle = nullptr;
    it->second.loaded = false;
    it->second.enabled = false;

    return true;
}

bool PluginRegistry::ReloadPlugin(const char* id) {
    if (!id) return false;
    // Would need to store the path for reload
    return UnloadPlugin(id);  // Simplified
}

PluginInfo* PluginRegistry::GetPlugin(const char* id) {
    if (!id) return nullptr;
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_plugins.find(id);
    return (it != m_plugins.end()) ? &it->second : nullptr;
}

std::vector<PluginInfo> PluginRegistry::ListPlugins() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<PluginInfo> result;
    for (const auto& [id, plugin] : m_plugins) {
        result.push_back(plugin);
    }
    return result;
}

uint32_t PluginRegistry::GetLoadedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    uint32_t count = 0;
    for (const auto& [id, plugin] : m_plugins) {
        if (plugin.loaded) count++;
    }
    return count;
}

bool PluginRegistry::ResolveDependencies(const char* id, std::vector<std::string>& resolved) {
    if (!id) return false;
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_plugins.find(id);
    if (it == m_plugins.end()) return false;

    // Simple topological sort
    std::vector<std::string> visited;
    std::function<bool(const std::string&)> visit = [&](const std::string& pluginId) -> bool {
        auto pit = m_plugins.find(pluginId);
        if (pit == m_plugins.end()) return false;

        for (const auto& dep : pit->second.dependencies) {
            if (std::find(visited.begin(), visited.end(), dep) == visited.end()) {
                if (!visit(dep)) return false;
            }
        }

        if (std::find(visited.begin(), visited.end(), pluginId) == visited.end()) {
            visited.push_back(pluginId);
        }
        return true;
    };

    if (!visit(id)) return false;
    resolved = visited;
    return true;
}

} // namespace rawr
