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
// Editor Callbacks (wired by IDE)
// ============================================================================
struct EditorCallbacks {
    std::function<int(const char* text, int64_t position, void* userData)> insertText;
    std::function<int(char* buffer, size_t bufferSize, int64_t startPos, int64_t endPos, void* userData)> getText;
    std::function<int(int64_t* startPos, int64_t* endPos, void* userData)> getSelection;
    std::function<int(int64_t startPos, int64_t endPos, void* userData)> setSelection;
    void* userData = nullptr;
};

// ============================================================================
// Document Callbacks (wired by IDE)
// ============================================================================
struct DocumentCallbacks {
    std::function<int(void* userData)> save;
    std::function<const char*(void* userData)> getPath;
    void* userData = nullptr;
};

// ============================================================================
// Registered Command
// ============================================================================
struct RegisteredCommand {
    std::string id;
    std::string displayName;
    std::string keybinding;
    RawrXD_CommandCallback callback = nullptr;
    void* pluginContext = nullptr;
};

// ============================================================================
// Event Hook
// ============================================================================
struct EventHook {
    std::string eventName;
    RawrXD_EventCallback callback = nullptr;
    void* pluginContext = nullptr;
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
    bool LoadAllPlugins(const std::wstring& pluginDirectory);
    bool LoadPlugin(const std::wstring& pluginPath);
    bool UnloadPlugin(const std::string& pluginName);
    void UnloadAllPlugins();
    
    // Query
    std::vector<std::string> GetLoadedPluginNames() const;
    bool IsPluginLoaded(const std::string& pluginName) const;
    const PluginInfo* GetPluginInfo(const std::string& pluginName) const;
    
    // Event Broadcasting
    void BroadcastEvent(const char* event_name, const char* event_data, 
                        RawrXD_DocumentHandle document = nullptr);
    
    // Get the API struct (for inspection/debugging)
    const RawrXD_API* GetAPI() const { return &m_api; }
    
    // Memory management (called by plugins via function pointers)
    static void* AllocateMemory(size_t size, uint32_t flags);
    static void FreeMemory(void* ptr);
    static void* ReallocateMemory(void* ptr, size_t new_size, uint32_t flags);
    static char* StringDuplicate(const char* str);
    
    // IDE callback registration (called by IDE to wire plugin API to real functions)
    void RegisterEditorCallbacks(size_t editorHandle, const EditorCallbacks& callbacks);
    void UnregisterEditorCallbacks(size_t editorHandle);
    void RegisterDocumentCallbacks(size_t docHandle, const DocumentCallbacks& callbacks);
    void UnregisterDocumentCallbacks(size_t docHandle);
    void SetDocumentOpenCallback(std::function<RawrXD_DocumentHandle(const char*, void*)> cb, void* userData);
    
    // Plugin thread tracking for event hook attribution
    void RegisterPluginThread(const std::string& pluginName, DWORD threadId);
    void UnregisterPluginThread(DWORD threadId);
    std::string FindPluginForCurrentThread() const;

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
    
    // Callback registries
    std::map<size_t, EditorCallbacks> m_editorCallbacks;
    std::map<size_t, DocumentCallbacks> m_documentCallbacks;
    std::function<RawrXD_DocumentHandle(const char*, void*)> m_documentOpenCallback;
    void* m_documentCallbackUserData = nullptr;
    
    // Command registry
    std::map<uint64_t, RegisteredCommand> m_commands;
    uint64_t m_nextCommandId = 1;
    mutable std::mutex m_commandsMutex;
    
    // Event hook registry: plugin name -> event name -> hook
    std::map<std::string, std::map<std::string, EventHook>> m_eventHooks;
    mutable std::mutex m_eventHooksMutex;
    
    // Settings storage
    std::map<std::string, std::string> m_settings;
    mutable std::mutex m_settingsMutex;
    
    // Thread-to-plugin mapping for event hook attribution
    std::map<DWORD, std::string> m_threadToPlugin;
    mutable std::mutex m_threadMutex;
};

} // namespace RawrXD::Plugins

#endif // RAWRXD_NATIVE_PLUGIN_MANAGER_H
