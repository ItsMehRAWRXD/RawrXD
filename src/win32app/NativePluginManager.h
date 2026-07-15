// ============================================================================
// NativePluginManager.h - RawrXD Native Plugin System
// ============================================================================
// Manages native DLL plugins using Windows Loader (LoadLibrary/GetProcAddress).
// 
// CRITICAL SAFETY FEATURES:
// - SEH Exception Wrapping: Plugin crashes don't bring down IDE
// - ABI Version Checking: Forward/backward compatibility
// - Memory Ownership: IDE manages all memory to prevent heap corruption
//
// USAGE:
//   auto& manager = NativePluginManager::GetInstance();
//   manager.LoadAllPlugins(L"plugins/");
//   
//   // Later...
//   manager.UnloadAllPlugins();
//
// THREAD SAFETY:
//   All methods are thread-safe (internally locked).
// ============================================================================

#ifndef RAWRXD_NATIVE_PLUGIN_MANAGER_H
#define RAWRXD_NATIVE_PLUGIN_MANAGER_H

#include "RawrXD_PluginAPI.h"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <windows.h>

namespace RawrXD::Plugins {

// ABI Version - increment on breaking changes
static const uint32_t RAWRXD_ABI_VERSION = 1;

// ============================================================================
// Plugin Information Structure
// ============================================================================
struct PluginInfo {
    std::string name;                      // Plugin name (from DLL filename)
    std::wstring path;                     // Full path to DLL
    HMODULE hModule = nullptr;             // Windows module handle
    RawrXD_PluginInitFunc initializeFunc = nullptr;    // Initialize export
    RawrXD_PluginShutdownFunc shutdownFunc = nullptr;  // Shutdown export (optional)
    void* context = nullptr;               // Plugin's private context
    bool loaded = false;                   // Successfully initialized?
    uint32_t pluginApiVersion = 0;       // Plugin's required API version
};

// ============================================================================
// Native Plugin Manager (Singleton)
// ============================================================================
class NativePluginManager {
public:
    // Singleton access
    static NativePluginManager& GetInstance();
    
    // Prevent copying
    NativePluginManager(const NativePluginManager&) = delete;
    NativePluginManager& operator=(const NativePluginManager&) = delete;
    
    // Lifecycle
    ~NativePluginManager();
    
    // Plugin Discovery and Loading
    // Scans directory for *.dll files and attempts to load each one
    bool LoadAllPlugins(const std::wstring& pluginDirectory);
    
    // Load a specific plugin DLL
    // Returns true on successful initialization
    bool LoadPlugin(const std::wstring& pluginPath);
    
    // Unload a specific plugin by name
    // Calls shutdown function if available, then FreeLibrary
    bool UnloadPlugin(const std::string& pluginName);
    
    // Unload all plugins (called on IDE shutdown)
    void UnloadAllPlugins();
    
    // Query
    std::vector<std::string> GetLoadedPluginNames() const;
    bool IsPluginLoaded(const std::string& pluginName) const;
    const PluginInfo* GetPluginInfo(const std::string& pluginName) const;
    
    // Event Broadcasting
    // Sends events to all plugins that have registered hooks
    void BroadcastEvent(const char* event_name, const char* event_data, 
                        RawrXD_DocumentHandle document = nullptr);
    
    // Get the API struct (for inspection/debugging)
    const RawrXD_API* GetAPI() const { return &m_api; }
    
    // Memory management (called by plugins via function pointers)
    static void* AllocateMemory(size_t size, uint32_t flags);
    static void FreeMemory(void* ptr);
    static void* ReallocateMemory(void* ptr, size_t new_size, uint32_t flags);
    static char* StringDuplicate(const char* str);

private:
    NativePluginManager();
    
    // Initialize the API function pointer table
    void InitializeAPI();
    
    // SEH-wrapped plugin calls (CRITICAL: prevents IDE crashes)
    int SafeInitializePlugin(PluginInfo& plugin);
    int SafeShutdownPlugin(PluginInfo& plugin);
    
    // Check ABI compatibility
    bool CheckABICompatibility(uint32_t pluginRequiredVersion, uint32_t pluginStructSize);
    
    RawrXD_API m_api;                      // Function pointer table passed to plugins
    std::map<std::string, std::unique_ptr<PluginInfo>> m_plugins;
    mutable std::mutex m_mutex;
};

} // namespace RawrXD::Plugins

#endif // RAWRXD_NATIVE_PLUGIN_MANAGER_H
