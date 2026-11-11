// NativePluginManager.cpp — Native Plugin Manager (Batch 5 X07)
#include "NativePluginManager.h"
#include <windows.h>

NativePluginManager& NativePluginManager::Instance() {
    static NativePluginManager inst;
    return inst;
}

bool NativePluginManager::LoadPlugin(const std::string& pluginPath) {
    HMODULE mod = LoadLibraryA(pluginPath.c_str());
    if (mod) {
        loadedPlugins_[pluginPath] = mod;
        return true;
    }
    return false;
}

bool NativePluginManager::UnloadPlugin(const std::string& pluginId) {
    auto it = loadedPlugins_.find(pluginId);
    if (it != loadedPlugins_.end()) {
        FreeLibrary(it->second);
        loadedPlugins_.erase(it);
        return true;
    }
    return false;
}

std::vector<std::string> NativePluginManager::ListPlugins() const {
    std::vector<std::string> result;
    for (const auto& [path, mod] : loadedPlugins_)
        result.push_back(path);
    return result;
}
