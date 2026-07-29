/**
 * @file plugin_loader.hpp
 * @brief Hot-injection loader for thermal dashboard plugin
<<<<<<< HEAD
 *
 * Allows loading/unloading thermal_dashboard.dll at runtime
 * without restarting the IDE. Pure Win32 LoadLibrary implementation.
=======
 * 
 * Allows loading/unloading thermal_dashboard.dll at runtime
 * without restarting the IDE.
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
 */

#pragma once

#include "thermal_dashboard_plugin.hpp"

<<<<<<< HEAD
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <memory>
#include <filesystem>
#include <mutex>
#include <cstdio>
=======

#include <memory>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

namespace rawrxd::thermal {

/**
<<<<<<< HEAD
 * @brief Runtime plugin loader for hot-injection (Win32 LoadLibrary)
=======
 * @brief Runtime plugin loader for hot-injection
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
 */
class ThermalPluginLoader {
public:
    static ThermalPluginLoader& instance() {
        static ThermalPluginLoader s_instance;
        return s_instance;
    }
<<<<<<< HEAD

=======
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    /**
     * @brief Load thermal dashboard plugin from DLL
     * @param pluginPath Path to thermal_dashboard.dll
     * @return true if loaded successfully
     */
    bool loadPlugin(const std::string& pluginPath = std::string()) {
<<<<<<< HEAD
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_plugin) {
            return true;  // Already loaded
        }

        std::string path = pluginPath;
        if (path.empty()) {
            path = getDefaultPluginPath();
        }

        // Load DLL via Win32
        m_hModule = LoadLibraryA(path.c_str());
        if (!m_hModule) {
            fprintf(stderr, "[ThermalPlugin] LoadLibrary failed: %s (error %lu)\n",
                    path.c_str(), GetLastError());
            return false;
        }

        // Get factory function
        auto createFunc = reinterpret_cast<CreateThermalPluginFunc>(
            GetProcAddress(m_hModule, "CreateThermalPlugin")
        );
        if (!createFunc) {
            fprintf(stderr, "[ThermalPlugin] CreateThermalPlugin export not found\n");
            FreeLibrary(m_hModule);
            m_hModule = nullptr;
            return false;
        }

        // Create plugin instance
        m_plugin = createFunc();
        if (!m_plugin) {
            fprintf(stderr, "[ThermalPlugin] CreateThermalPlugin returned null\n");
            FreeLibrary(m_hModule);
            m_hModule = nullptr;
            return false;
        }

        // Initialize plugin
        if (!m_plugin->initialize()) {
            fprintf(stderr, "[ThermalPlugin] Plugin initialization failed\n");
            m_plugin = nullptr;
            FreeLibrary(m_hModule);
            m_hModule = nullptr;
            return false;
        }

        m_currentPath = path;
        fprintf(stdout, "[ThermalPlugin] Loaded: %s v%s\n",
                m_plugin->pluginName().c_str(),
                m_plugin->pluginVersion().c_str());

        return true;
    }

=======
        if (m_plugin) {
            return true;
        }
        
        std::string path = pluginPath;
        if (path.empty()) {
            // Default: plugins directory next to executable
            path = std::filesystem::path(QCoreApplication::applicationDirPath())
                       .filePath("plugins/thermal_dashboard.dll");
        }


        m_loader = std::make_unique<QPluginLoader>(path);
        
        if (!m_loader->load()) {
            m_loader.reset();
            return false;
        }
        
        void* instance = m_loader->instance();
        if (!instance) {
            m_loader->unload();
            m_loader.reset();
            return false;
        }
        
// REMOVED_QT:         m_plugin = qobject_cast<IThermalDashboardPlugin*>(instance);
        if (!m_plugin) {
            m_loader->unload();
            m_loader.reset();
            return false;
        }
        
        // Initialize plugin
        if (!m_plugin->initialize()) {
            m_loader->unload();
            m_loader.reset();
            m_plugin = nullptr;
            return false;
        }
        
                 << m_plugin->pluginName() << "v" << m_plugin->pluginVersion();
        
        return true;
    }
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    /**
     * @brief Unload plugin (hot-unload)
     */
    void unloadPlugin() {
<<<<<<< HEAD
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_plugin) {
            m_plugin->shutdown();
            m_plugin = nullptr;
        }

        if (m_hModule) {
            FreeLibrary(m_hModule);
            m_hModule = nullptr;
        }

        m_currentPath.clear();
    }

=======
        if (!m_plugin) return;


        m_plugin->shutdown();
        m_plugin = nullptr;
        
        if (m_loader) {
            m_loader->unload();
            m_loader.reset();
        }
        
    }
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    /**
     * @brief Reload plugin (hot-swap)
     */
    bool reloadPlugin(const std::string& pluginPath = std::string()) {
<<<<<<< HEAD
        std::string savedPath;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            savedPath = m_currentPath;
        }
        unloadPlugin();
        Sleep(50);  // Brief delay to ensure DLL file handle is released
        return loadPlugin(pluginPath.empty() ? savedPath : pluginPath);
    }

=======
        unloadPlugin();
        return loadPlugin(pluginPath);
    }
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    /**
     * @brief Check if plugin is loaded
     */
    bool isLoaded() const {
<<<<<<< HEAD
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_plugin != nullptr;
    }

=======
        return m_plugin != nullptr;
    }
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    /**
     * @brief Get plugin interface
     */
    IThermalDashboardPlugin* plugin() {
<<<<<<< HEAD
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_plugin;
    }

    /**
     * @brief Create dashboard widget (convenience). Win32: parent is HWND.
     */
    void* createDashboard(void* parent = nullptr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_plugin) return nullptr;
        return m_plugin->createDashboardWidget(parent);
    }

    /**
     * @brief Create compact widget (convenience). Win32: parent is HWND.
     */
    void* createCompactWidget(void* parent = nullptr) {
        std::lock_guard<std::mutex> lock(m_mutex);
=======
        return m_plugin;
    }
    
    /**
     * @brief Create dashboard widget (convenience)
     */
    void* createDashboard(void* parent = nullptr) {
        if (!m_plugin) return nullptr;
        return m_plugin->createDashboardWidget(parent);
    }
    
    /**
     * @brief Create compact widget (convenience)
     */
    void* createCompactWidget(void* parent = nullptr) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        if (!m_plugin) return nullptr;
        return m_plugin->createCompactWidget(parent);
    }

private:
    ThermalPluginLoader() = default;
    ~ThermalPluginLoader() { unloadPlugin(); }
<<<<<<< HEAD

    ThermalPluginLoader(const ThermalPluginLoader&) = delete;
    ThermalPluginLoader& operator=(const ThermalPluginLoader&) = delete;

    std::string getDefaultPluginPath() const {
        // Get directory of current executable
        char exePath[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::filesystem::path exeDir = std::filesystem::path(exePath).parent_path();

        // Search common locations
        const std::filesystem::path candidates[] = {
            exeDir / "plugins" / "thermal_dashboard.dll",
            exeDir / "thermal_dashboard.dll",
            std::filesystem::path("D:/rawrxd/build/bin/thermal_dashboard.dll"),
            std::filesystem::path("D:/rawrxd/build/src/thermal/Release/thermal_dashboard.dll"),
        };

        for (const auto& p : candidates) {
            if (std::filesystem::exists(p)) {
                return p.string();
            }
        }

        // Fall back to default name (LoadLibrary will use system search)
        return "thermal_dashboard.dll";
    }

    HMODULE m_hModule = nullptr;
    IThermalDashboardPlugin* m_plugin = nullptr;
    std::string m_currentPath;
    mutable std::mutex m_mutex;
=======
    
    ThermalPluginLoader(const ThermalPluginLoader&) = delete;
    ThermalPluginLoader& operator=(const ThermalPluginLoader&) = delete;
    
    std::unique_ptr<QPluginLoader> m_loader;
    IThermalDashboardPlugin* m_plugin = nullptr;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};

/**
 * @brief Convenience macros for IDE integration
 */
<<<<<<< HEAD
#define THERMAL_LOAD()       rawrxd::thermal::ThermalPluginLoader::instance().loadPlugin()
#define THERMAL_UNLOAD()     rawrxd::thermal::ThermalPluginLoader::instance().unloadPlugin()
#define THERMAL_RELOAD()     rawrxd::thermal::ThermalPluginLoader::instance().reloadPlugin()
#define THERMAL_PLUGIN()     rawrxd::thermal::ThermalPluginLoader::instance().plugin()
=======
#define THERMAL_LOAD()      rawrxd::thermal::ThermalPluginLoader::instance().loadPlugin()
#define THERMAL_UNLOAD()    rawrxd::thermal::ThermalPluginLoader::instance().unloadPlugin()
#define THERMAL_RELOAD()    rawrxd::thermal::ThermalPluginLoader::instance().reloadPlugin()
#define THERMAL_PLUGIN()    rawrxd::thermal::ThermalPluginLoader::instance().plugin()
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#define THERMAL_DASHBOARD(p) rawrxd::thermal::ThermalPluginLoader::instance().createDashboard(p)
#define THERMAL_COMPACT(p)   rawrxd::thermal::ThermalPluginLoader::instance().createCompactWidget(p)

} // namespace rawrxd::thermal


