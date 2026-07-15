// ============================================================================
// NativePluginManager.cpp - RawrXD Native Plugin System
// ============================================================================
// Implements the "RawrXD Native Plugin Protocol" using Windows Loader.
// 
// CRITICAL SAFETY FEATURES:
// - SEH Exception Wrapping: All plugin entry points wrapped in __try/__except
// - ABI Version Checking: struct_size field enables forward compatibility
// - Memory Ownership: IDE manages all memory to prevent heap corruption
// - Safe Shutdown: Plugins that crash during shutdown don't hang the IDE
//
// ARCHITECTURE:
// - Scans /plugins/*.dll on startup
// - Uses LoadLibraryW/GetProcAddress for zero-overhead plugin loading
// - Passes RawrXD_API struct (function pointer table) to each plugin
// - Plugins call IDE services via function pointers (protected core)
// - Supports hot-reload via Unload/Reload cycle
//
// SECURITY:
// - Plugins run in-process (native speed, shared memory)
// - SEH blocks catch plugin exceptions to prevent IDE crashes
// - Optional: Run in separate process for isolation (future enhancement)
//
// MASM SUPPORT:
// - Pure C ABI (no name mangling)
// - Flat structs (no nested complexity)
// - Function pointer tables (easy to call from assembly)
// ============================================================================

#include "NativePluginManager.h"
#include <windows.h>
#include <shlwapi.h>
#include <iostream>
#include <filesystem>

#pragma comment(lib, "shlwapi.lib")

namespace RawrXD::Plugins {

// ============================================================================
// Singleton Instance
// ============================================================================
NativePluginManager& NativePluginManager::GetInstance() {
    static NativePluginManager instance;
    return instance;
}

// ============================================================================
// Constructor / Destructor
// ============================================================================
NativePluginManager::NativePluginManager() {
    InitializeAPI();
}

NativePluginManager::~NativePluginManager() {
    UnloadAllPlugins();
}

// ============================================================================
// Memory Management (CRITICAL: Prevents heap corruption)
// ============================================================================
void* NativePluginManager::AllocateMemory(size_t size, uint32_t flags) {
    if (size == 0) return nullptr;
    
    void* ptr = nullptr;
    
    if (flags & RAWRXD_MEM_ZERO_INIT) {
        ptr = calloc(1, size);
    } else {
        ptr = malloc(size);
    }
    
    // TODO: Handle RAWRXD_MEM_EXECUTABLE (VirtualAlloc) and RAWRXD_MEM_LARGE_PAGES
    
    return ptr;
}

void NativePluginManager::FreeMemory(void* ptr) {
    free(ptr);
}

void* NativePluginManager::ReallocateMemory(void* ptr, size_t new_size, uint32_t flags) {
    return realloc(ptr, new_size);
}

char* NativePluginManager::StringDuplicate(const char* str) {
    if (!str) return nullptr;
    
    size_t len = strlen(str) + 1;
    char* dup = (char*)AllocateMemory(len, RAWRXD_MEM_DEFAULT);
    if (dup) {
        memcpy(dup, str, len);
    }
    return dup;
}

// ============================================================================
// API Initialization (Build the function pointer table)
// ============================================================================
void NativePluginManager::InitializeAPI() {
    // CRITICAL: struct_size MUST be first field for ABI compatibility
    m_api.struct_size = sizeof(RawrXD_API);
    m_api.api_version = RAWRXD_API_VERSION;
    m_api.abi_version = RAWRXD_ABI_VERSION;
    
    // Memory management (CRITICAL: prevents heap corruption)
    m_api.AllocateMemory = AllocateMemory;
    m_api.FreeMemory = FreeMemory;
    m_api.ReallocateMemory = ReallocateMemory;
    m_api.StringDuplicate = StringDuplicate;
    
    // String operations
    m_api.StringLength = [](const char* str) -> size_t {
        return str ? strlen(str) : 0;
    };
    m_api.StringCompare = [](const char* a, const char* b, size_t max_len) -> int {
        return strncmp(a, b, max_len);
    };
    
    // Logging
    m_api.Log = [](int level, const char* plugin_name, const char* message) {
        const char* level_str = level == 0 ? "DEBUG" : level == 1 ? "INFO" : level == 2 ? "WARN" : "ERROR";
        std::cout << "[" << level_str << "][" << plugin_name << "] " << message << std::endl;
    };
    
    // Editor Operations (stubs - will be wired to actual IDE functions)
    m_api.EditorInsertText = [](RawrXD_EditorHandle editor, const char* text, int64_t position) -> int {
        // TODO: Wire to actual editor
        std::cout << "[PluginAPI] EditorInsertText: " << text << std::endl;
        return 0;
    };
    
    m_api.EditorGetText = [](RawrXD_EditorHandle editor, char* buffer, size_t buffer_size, 
                             int64_t start_pos, int64_t end_pos) -> int {
        // TODO: Wire to actual editor
        strncpy_s(buffer, buffer_size, "Sample text from editor", buffer_size - 1);
        return 0;
    };
    
    m_api.EditorGetSelection = [](RawrXD_EditorHandle editor, int64_t* start_pos, int64_t* end_pos) -> int {
        *start_pos = 0;
        *end_pos = 0;
        return 0;
    };
    
    m_api.EditorSetSelection = [](RawrXD_EditorHandle editor, int64_t start_pos, int64_t end_pos) -> int {
        return 0;
    };
    
    // Document Operations
    m_api.DocumentOpen = [](const char* file_path) -> RawrXD_DocumentHandle {
        std::cout << "[PluginAPI] DocumentOpen: " << file_path << std::endl;
        return nullptr; // TODO: Return actual document handle
    };
    
    m_api.DocumentSave = [](RawrXD_DocumentHandle document) -> int {
        std::cout << "[PluginAPI] DocumentSave" << std::endl;
        return 0;
    };
    
    m_api.DocumentGetPath = [](RawrXD_DocumentHandle document) -> const char* {
        return "C:\\sample\\path.txt"; // TODO: Return actual path
    };
    
    // Command Registration
    m_api.RegisterCommand = [](const char* command_id, const char* display_name, 
                               const char* keybinding, RawrXD_CommandCallback callback, 
                               void* plugin_context) -> RawrXD_CommandHandle {
        std::cout << "[PluginAPI] RegisterCommand: " << command_id << " (" << display_name << ")" << std::endl;
        // TODO: Register with IDE command system
        return reinterpret_cast<RawrXD_CommandHandle>(1); // Dummy handle
    };
    
    m_api.UnregisterCommand = [](RawrXD_CommandHandle command) -> int {
        return 0;
    };
    
    // Event Hooks
    m_api.HookEvent = [](const char* event_name, RawrXD_EventCallback callback, void* plugin_context) -> int {
        std::cout << "[PluginAPI] HookEvent: " << event_name << std::endl;
        // TODO: Register event hook
        return 0;
    };
    
    m_api.UnhookEvent = [](const char* event_name, RawrXD_EventCallback callback) -> int {
        return 0;
    };
    
    // UI Integration
    m_api.AddMenuItem = [](const char* menu_path, const char* item_name, const char* keybinding,
                           RawrXD_CommandCallback callback, void* plugin_context) -> RawrXD_MenuHandle {
        std::cout << "[PluginAPI] AddMenuItem: " << menu_path << "/" << item_name << std::endl;
        return reinterpret_cast<RawrXD_MenuHandle>(1);
    };
    
    m_api.SetStatusBarText = [](RawrXD_StatusBarHandle panel, const char* text) {
        std::cout << "[PluginAPI] SetStatusBarText: " << text << std::endl;
    };
    
    m_api.CreateStatusBarPanel = [](const char* panel_id, int width, int alignment) -> RawrXD_StatusBarHandle {
        return reinterpret_cast<RawrXD_StatusBarHandle>(1);
    };
    
    // Utility
    m_api.GetSetting = [](const char* key, char* buffer, size_t buffer_size) {
        // TODO: Read from settings
        strncpy_s(buffer, buffer_size, "default_value", buffer_size - 1);
    };
    
    m_api.SetSetting = [](const char* key, const char* value) {
        // TODO: Write to settings
    };
    
    m_api.ShowMessageBox = [](const char* title, const char* message, int type) {
        UINT msg_type = type == 0 ? MB_ICONINFORMATION : type == 1 ? MB_ICONWARNING : MB_ICONERROR;
        MessageBoxA(nullptr, message, title, MB_OK | msg_type);
    };
    
    m_api.ShowInputDialog = [](const char* title, const char* prompt, char* buffer, size_t buffer_size) -> int {
        // TODO: Show actual input dialog
        strncpy_s(buffer, buffer_size, "user_input", buffer_size - 1);
        return 0;
    };
    
    // Clear reserved pointers
    for (int i = 0; i < 16; i++) {
        m_api.reserved[i] = nullptr;
    }
}

// ============================================================================
// Plugin Discovery and Loading
// ============================================================================
bool NativePluginManager::LoadAllPlugins(const std::wstring& pluginDirectory) {
    if (!std::filesystem::exists(pluginDirectory)) {
        std::cout << "[NativePluginManager] Plugin directory does not exist: " 
                  << std::string(pluginDirectory.begin(), pluginDirectory.end()) << std::endl;
        return false;
    }
    
    int loadedCount = 0;
    int failedCount = 0;
    
    for (const auto& entry : std::filesystem::directory_iterator(pluginDirectory)) {
        if (entry.is_regular_file() && entry.path().extension() == L".dll") {
            if (LoadPlugin(entry.path().wstring())) {
                loadedCount++;
            } else {
                failedCount++;
            }
        }
    }
    
    std::cout << "[NativePluginManager] Loaded " << loadedCount << " plugins, " 
              << failedCount << " failed" << std::endl;
    
    return loadedCount > 0 || failedCount == 0;
}

// ============================================================================
// Plugin Loading with SEH Exception Wrapping (CRITICAL: Prevents IDE crashes)
// ============================================================================
bool NativePluginManager::LoadPlugin(const std::wstring& pluginPath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::string pluginName = std::filesystem::path(pluginPath).stem().string();
    
    // Check if already loaded
    if (m_plugins.find(pluginName) != m_plugins.end()) {
        std::cout << "[NativePluginManager] Plugin already loaded: " << pluginName << std::endl;
        return true;
    }
    
    // Load the DLL
    HMODULE hModule = LoadLibraryW(pluginPath.c_str());
    if (!hModule) {
        DWORD error = GetLastError();
        std::cerr << "[NativePluginManager] Failed to load DLL: " << pluginName 
                  << " (Error: " << error << ")" << std::endl;
        return false;
    }
    
    // Get the Initialize function
    auto initFunc = reinterpret_cast<RawrXD_PluginInitFunc>(
        GetProcAddress(hModule, "RawrXD_PluginInitialize")
    );
    
    if (!initFunc) {
        std::cerr << "[NativePluginManager] Plugin missing RawrXD_PluginInitialize export: " 
                  << pluginName << std::endl;
        FreeLibrary(hModule);
        return false;
    }
    
    // Get optional Shutdown function
    auto shutdownFunc = reinterpret_cast<RawrXD_PluginShutdownFunc>(
        GetProcAddress(hModule, "RawrXD_PluginShutdown")
    );
    
    // Create plugin info
    auto plugin = std::make_unique<PluginInfo>();
    plugin->name = pluginName;
    plugin->path = pluginPath;
    plugin->hModule = hModule;
    plugin->initializeFunc = initFunc;
    plugin->shutdownFunc = shutdownFunc;
    plugin->context = nullptr;
    plugin->loaded = false;
    
    // Initialize the plugin with SEH protection
    int result = SafeInitializePlugin(*plugin);
    
    if (result != 0) {
        std::cerr << "[NativePluginManager] Plugin initialization failed: " << pluginName 
                  << " (Error code: " << result << ")" << std::endl;
        FreeLibrary(hModule);
        return false;
    }
    
    plugin->loaded = true;
    
    std::cout << "[NativePluginManager] Successfully loaded plugin: " << pluginName << std::endl;
    
    m_plugins[pluginName] = std::move(plugin);
    return true;
}

// ============================================================================
// SEH-Wrapped Plugin Calls (CRITICAL: Prevents IDE crashes)
// ============================================================================
int NativePluginManager::SafeInitializePlugin(PluginInfo& plugin) {
    int result = RAWRXD_ERROR_EXCEPTION;
    
    __try {
        // Call the plugin's initialize function
        // This runs in the plugin's DLL context
        result = plugin.initializeFunc(
            &m_api,                    // API function pointer table
            RAWRXD_API_VERSION,        // API version
            &plugin.context           // OUT: Plugin context
        );
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // Plugin caused an exception (access violation, etc.)
        DWORD exceptionCode = GetExceptionCode();
        
        std::cerr << "[NativePluginManager] CRITICAL: Plugin '" << plugin.name 
                  << "' caused exception 0x" << std::hex << exceptionCode << std::dec
                  << " during initialization. Plugin disabled." << std::endl;
        
        result = RAWRXD_ERROR_EXCEPTION;
    }
    
    return result;
}

int NativePluginManager::SafeShutdownPlugin(PluginInfo& plugin) {
    if (!plugin.shutdownFunc || !plugin.context) {
        return 0; // Nothing to do
    }
    
    int result = 0;
    
    __try {
        result = plugin.shutdownFunc(plugin.context);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DWORD exceptionCode = GetExceptionCode();
        
        std::cerr << "[NativePluginManager] WARNING: Plugin '" << plugin.name 
                  << "' caused exception 0x" << std::hex << exceptionCode << std::dec
                  << " during shutdown." << std::endl;
        
        result = RAWRXD_ERROR_EXCEPTION;
    }
    
    return result;
}

// ============================================================================
// Plugin Unloading
// ============================================================================
bool NativePluginManager::UnloadPlugin(const std::string& pluginName) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_plugins.find(pluginName);
    if (it == m_plugins.end()) {
        return false;
    }
    
    auto& plugin = it->second;
    
    // Call shutdown with SEH protection
    if (plugin->loaded) {
        SafeShutdownPlugin(*plugin);
    }
    
    // Unload the DLL
    if (plugin->hModule) {
        FreeLibrary(plugin->hModule);
    }
    
    std::cout << "[NativePluginManager] Unloaded plugin: " << pluginName << std::endl;
    
    m_plugins.erase(it);
    return true;
}

void NativePluginManager::UnloadAllPlugins() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Shutdown in reverse order (respect dependencies)
    for (auto it = m_plugins.rbegin(); it != m_plugins.rend(); ++it) {
        auto& plugin = it->second;
        
        if (plugin->loaded) {
            SafeShutdownPlugin(*plugin);
        }
        
        if (plugin->hModule) {
            FreeLibrary(plugin->hModule);
        }
        
        std::cout << "[NativePluginManager] Unloaded plugin: " << it->first << std::endl;
    }
    
    m_plugins.clear();
}

// ============================================================================
// Plugin Query
// ============================================================================
std::vector<std::string> NativePluginManager::GetLoadedPluginNames() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::string> names;
    for (const auto& pair : m_plugins) {
        names.push_back(pair.first);
    }
    return names;
}

bool NativePluginManager::IsPluginLoaded(const std::string& pluginName) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_plugins.find(pluginName) != m_plugins.end();
}

const PluginInfo* NativePluginManager::GetPluginInfo(const std::string& pluginName) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_plugins.find(pluginName);
    if (it != m_plugins.end()) {
        return it->second.get();
    }
    return nullptr;
}

// ============================================================================
// Event Broadcasting
// ============================================================================
void NativePluginManager::BroadcastEvent(const char* event_name, const char* event_data, 
                                          RawrXD_DocumentHandle document) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // TODO: Iterate through registered event hooks and call callbacks
    // This requires maintaining a registry of event hooks per plugin
}

} // namespace RawrXD::Plugins
