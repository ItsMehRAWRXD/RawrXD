// NativePluginManager.h — Native Plugin Manager (Batch 5 X07)
#pragma once

#include <string>
#include <vector>
#include <map>

class NativePluginManager {
public:
    static NativePluginManager& Instance();

    bool LoadPlugin(const std::string& pluginPath);
    bool UnloadPlugin(const std::string& pluginId);
    std::vector<std::string> ListPlugins() const;

private:
    NativePluginManager() = default;
    std::map<std::string, void*> loadedPlugins_;
};
