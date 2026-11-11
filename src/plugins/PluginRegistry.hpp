// ============================================================================
// PluginRegistry.hpp — Native Plugin Registry
// Safe load/unload, dependency resolution, version gating
// ============================================================================

#ifndef PLUGIN_REGISTRY_HPP
#define PLUGIN_REGISTRY_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <mutex>

namespace rawr {

// ============================================================================
// Plugin Info
// ============================================================================
struct PluginInfo {
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::vector<std::string> dependencies;
    void* handle;  // DLL handle
    bool loaded;
    bool enabled;
};

// ============================================================================
// PluginRegistry — Manages plugin lifecycle
// ============================================================================
class PluginRegistry {
public:
    static PluginRegistry& Get();

    bool Initialize();
    void Shutdown();

    // Registration
    bool RegisterPlugin(const char* id, const char* name, const char* version);
    bool UnregisterPlugin(const char* id);

    // Loading
    bool LoadPlugin(const char* id, const char* path);
    bool UnloadPlugin(const char* id);
    bool ReloadPlugin(const char* id);

    // Query
    PluginInfo* GetPlugin(const char* id);
    std::vector<PluginInfo> ListPlugins() const;
    uint32_t GetLoadedCount() const;
    uint32_t GetPluginCount() const { return static_cast<uint32_t>(m_plugins.size()); }

    // Dependency resolution
    bool ResolveDependencies(const char* id, std::vector<std::string>& resolved);

private:
    PluginRegistry() = default;
    ~PluginRegistry() = default;
    PluginRegistry(const PluginRegistry&) = delete;
    PluginRegistry& operator=(const PluginRegistry&) = delete;

    std::unordered_map<std::string, PluginInfo> m_plugins;
    mutable std::mutex m_mutex;
};

} // namespace rawr

#endif // PLUGIN_REGISTRY_HPP
