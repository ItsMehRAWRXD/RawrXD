/**
 * @file thermal_plugin_loader.hpp
<<<<<<< HEAD
 * @brief Hot-injection plugin loader for Thermal Dashboard (Qt-free)
 *
 * Enables runtime loading/unloading of thermal_dashboard.dll
 * without IDE restart. Uses Win32 LoadLibrary + named pipe IPC.
 *
 * Pure C++20 / Win32 — zero Qt dependency.
=======
 * @brief Hot-injection plugin loader for Thermal Dashboard
 * 
 * Enables runtime loading/unloading of thermal_dashboard.dll
 * without IDE restart. Supports IPC-based commands and auto-discovery.
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
 */

#pragma once

<<<<<<< HEAD
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN

// SCAFFOLD_349: Plugin loader void* parent doc

#endif
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
=======
#include <memory>
#include <functional>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

// Forward declare the interface
namespace rawrxd::thermal {
    class IThermalDashboardPlugin;
}

<<<<<<< HEAD
// DLL export signature: IThermalDashboardPlugin* CreateThermalPlugin()
using CreateThermalPluginFunc = rawrxd::thermal::IThermalDashboardPlugin* (*)();

=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
namespace rawrxd::core {

/**
 * @brief Plugin loader status
 */
enum class PluginStatus {
    NotLoaded,
    Loading,
    Loaded,
    Error,
    Unloading
};

<<<<<<< HEAD
// ─────────────────────────────────────────────────────────────────────────────
// Callback types (no Qt signals)
// ─────────────────────────────────────────────────────────────────────────────
using PluginStatusCallback   = std::function<void(PluginStatus)>;
using PluginErrorCallback    = std::function<void(const std::string&)>;
using PluginFileChangedCb    = std::function<void(const std::string&)>;

/**
 * @brief Hot-injectable plugin loader for thermal dashboard
 *
 * Features:
 * - Runtime DLL loading via Win32 LoadLibrary/FreeLibrary
 * - Named pipe IPC for external injection commands
 * - File timestamp polling for auto-reload on DLL update
 * - Thread-safe plugin access
 */
class ThermalPluginLoader {
public:
    ThermalPluginLoader();
    ~ThermalPluginLoader();

    // Non-copyable
    ThermalPluginLoader(const ThermalPluginLoader&) = delete;
    ThermalPluginLoader& operator=(const ThermalPluginLoader&) = delete;
=======
/**
 * @brief Hot-injectable plugin loader for thermal dashboard
 * 
 * Features:
 * - Runtime DLL loading via QPluginLoader
 * - Named pipe IPC for external injection commands
 * - File system watching for auto-reload on DLL update
 * - Thread-safe plugin access
 */
class ThermalPluginLoader  {public:
    explicit ThermalPluginLoader( = nullptr);
    ~ThermalPluginLoader() override;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    /**
     * @brief Initialize the plugin loader system
     * @param pluginSearchPaths Directories to search for plugins
     * @return true if initialized successfully
     */
<<<<<<< HEAD
    bool initialize(const std::vector<std::string>& pluginSearchPaths = {});

    /** @brief Shutdown and cleanup */
=======
    bool initialize(const std::stringList& pluginSearchPaths = {});

    /**
     * @brief Shutdown and cleanup
     */
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    void shutdown();

    /**
     * @brief Load the thermal dashboard plugin
     * @param pluginPath Optional explicit path to DLL
     * @return true if loaded successfully
     */
<<<<<<< HEAD
    bool loadPlugin(const std::string& pluginPath = {});

    /** @brief Unload the currently loaded plugin */
    bool unloadPlugin();

    /** @brief Reload the plugin (unload then load) */
    bool reloadPlugin();

    /** @brief Check if plugin is currently loaded */
    bool isLoaded() const;

    /** @brief Get current plugin status */
    PluginStatus status() const { return m_status.load(); }

    /** @brief Get the loaded plugin interface (nullptr if not loaded) */
    rawrxd::thermal::IThermalDashboardPlugin* plugin() const;

    /** @brief Get last error message */
    std::string lastError() const;

    /** @brief Enable/disable auto-reload on DLL changes */
    void setAutoReload(bool enabled);

    /** @brief Enable/disable IPC command server */
    void setIpcEnabled(bool enabled);

    // ── Callbacks (replacement for Qt signals) ──────────────────────────────
    void onPluginLoaded(PluginStatusCallback cb)     { m_cbLoaded = std::move(cb); }
    void onPluginUnloaded(PluginStatusCallback cb)   { m_cbUnloaded = std::move(cb); }
    void onPluginError(PluginErrorCallback cb)       { m_cbError = std::move(cb); }
    void onStatusChanged(PluginStatusCallback cb)    { m_cbStatus = std::move(cb); }
    void onFileChanged(PluginFileChangedCb cb)       { m_cbFileChanged = std::move(cb); }

private:
    // ── Internal helpers ────────────────────────────────────────────────────
    void setStatus(PluginStatus s);
    std::string findPluginPath() const;
    void setupIpcServer();
    void ipcThreadFunc();
    void watcherThreadFunc();
    void handleIpcCommand(const std::string& json, HANDLE pipe);

    // ── State ───────────────────────────────────────────────────────────────
    HMODULE                                   m_hModule = nullptr;
    rawrxd::thermal::IThermalDashboardPlugin* m_plugin  = nullptr;

    std::vector<std::string>                  m_searchPaths;
    std::string                               m_currentPluginPath;
    std::string                               m_lastError;
    std::atomic<PluginStatus>                 m_status{PluginStatus::NotLoaded};

    // Auto-reload (file timestamp polling)
    std::atomic<bool>                         m_autoReloadEnabled{true};
    std::atomic<bool>                         m_watcherRunning{false};
    std::thread                               m_watcherThread;
    HANDLE                                    m_watcherStopEvent = nullptr;
    std::chrono::steady_clock::time_point     m_lastReloadTime;

    // IPC (named pipe)
    std::atomic<bool>                         m_ipcEnabled{true};
    std::atomic<bool>                         m_ipcRunning{false};
    std::thread                               m_ipcThread;
    HANDLE                                    m_ipcStopEvent = nullptr;

    mutable std::mutex                        m_mutex;

    // Callbacks
    PluginStatusCallback                      m_cbLoaded;
    PluginStatusCallback                      m_cbUnloaded;
    PluginErrorCallback                       m_cbError;
    PluginStatusCallback                      m_cbStatus;
    PluginFileChangedCb                       m_cbFileChanged;
};

// ═════════════════════════════════════════════════════════════════════════════
// Inline Implementation
// ═════════════════════════════════════════════════════════════════════════════

inline ThermalPluginLoader::ThermalPluginLoader() = default;
=======
    bool loadPlugin(const std::string& pluginPath = std::string());

    /**
     * @brief Unload the currently loaded plugin
     * @return true if unloaded successfully
     */
    bool unloadPlugin();

    /**
     * @brief Reload the plugin (unload then load)
     * @return true if reloaded successfully
     */
    bool reloadPlugin();

    /**
     * @brief Check if plugin is currently loaded
     */
    bool isLoaded() const;

    /**
     * @brief Get current plugin status
     */
    PluginStatus status() const { return m_status; }

    /**
     * @brief Get the loaded plugin interface
     * @return Plugin interface or nullptr if not loaded
     */
    rawrxd::thermal::IThermalDashboardPlugin* plugin() const;

    /**
     * @brief Get last error message
     */
    std::string lastError() const { return m_lastError; }

    /**
     * @brief Enable/disable auto-reload on DLL changes
     */
    void setAutoReload(bool enabled);

    /**
     * @brief Enable/disable IPC command server
     */
    void setIpcEnabled(bool enabled);

\npublic:\n    /**
     * @brief Emitted when plugin is loaded
     */
    void pluginLoaded();

    /**
     * @brief Emitted when plugin is unloaded
     */
    void pluginUnloaded();

    /**
     * @brief Emitted when plugin load/unload fails
     */
    void pluginError(const std::string& error);

    /**
     * @brief Emitted when plugin status changes
     */
    void statusChanged(PluginStatus status);

    /**
     * @brief Emitted when auto-reload detects DLL change
     */
    void pluginFileChanged(const std::string& path);

\nprivate:\n    void onFileChanged(const std::string& path);
    void onNewIpcConnection();
    void onIpcReadyRead();
    void onIpcDisconnected();
    void onReloadTimer();

private:
    void setStatus(PluginStatus status);
    std::string findPluginPath() const;
    void setupIpcServer();
    void handleIpcCommand(const void*& cmd, void** socket);

private:
    std::unique_ptr<QPluginLoader> m_loader;
    rawrxd::thermal::IThermalDashboardPlugin* m_plugin;
    
    std::stringList m_searchPaths;
    std::string m_currentPluginPath;
    std::string m_lastError;
    PluginStatus m_status;
    
    // Auto-reload
    std::unique_ptr<// SystemWatcher> m_watcher;
    std::unique_ptr<void> m_reloadTimer;
    bool m_autoReloadEnabled;
    bool m_pendingReload;
    
    // IPC
    std::unique_ptr<void*> m_ipcServer;
    std::vector<void**> m_ipcClients;
    bool m_ipcEnabled;
    
    mutable std::mutex m_mutex;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Inline Implementation
// ═══════════════════════════════════════════════════════════════════════════════

inline ThermalPluginLoader::ThermalPluginLoader()
    
    , m_plugin(nullptr)
    , m_status(PluginStatus::NotLoaded)
    , m_autoReloadEnabled(true)
    , m_pendingReload(false)
    , m_ipcEnabled(true)
{
}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

inline ThermalPluginLoader::~ThermalPluginLoader()
{
    shutdown();
}

<<<<<<< HEAD
inline bool ThermalPluginLoader::initialize(const std::vector<std::string>& pluginSearchPaths)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_searchPaths = pluginSearchPaths;
    if (m_searchPaths.empty()) {
        // Default search paths — use exe directory
        char exePath[MAX_PATH]{};
        if (GetModuleFileNameA(nullptr, exePath, MAX_PATH)) {
            std::string dir(exePath);
            auto pos = dir.find_last_of("\\/");
            if (pos != std::string::npos) dir = dir.substr(0, pos);
            m_searchPaths.push_back(dir);
            m_searchPaths.push_back(dir + "\\plugins");
        }
        m_searchPaths.push_back("D:\\rawrxd\\build\\bin");
        m_searchPaths.push_back("D:\\rawrxd\\build\\src\\thermal\\Release");
    }

    // Start file watcher thread
    if (m_autoReloadEnabled.load()) {
        m_watcherStopEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
        if (m_watcherStopEvent) {
            m_watcherRunning = true;
            m_watcherThread = std::thread(&ThermalPluginLoader::watcherThreadFunc, this);
        }
    }

    // Start IPC server thread
    if (m_ipcEnabled.load()) {
        setupIpcServer();
    }

=======
inline bool ThermalPluginLoader::initialize(const std::stringList& pluginSearchPaths)
{
    std::mutexLocker locker(&m_mutex);
    
    m_searchPaths = pluginSearchPaths;
    if (m_searchPaths.empty()) {
        // Default search paths
        m_searchPaths << QCoreApplication::applicationDirPath()
                      << QCoreApplication::applicationDirPath() + "/plugins"
                      << "D:/rawrxd/build/bin"
                      << "D:/rawrxd/build/src/thermal/Release";
    }
    
    // Setup file watcher for auto-reload
    m_watcher = std::make_unique<// SystemWatcher>(this);  // Signal connection removed\n// Setup reload debounce timer
    m_reloadTimer = std::make_unique<std::chrono::system_clock::time_pointr>(this);
    m_reloadTimer->setSingleShot(true);
    m_reloadTimer->setInterval(500);  // 500ms debounce  // Signal connection removed\n// Setup IPC server
    if (m_ipcEnabled) {
        setupIpcServer();
    }
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

inline void ThermalPluginLoader::shutdown()
{
<<<<<<< HEAD
    // Stop watcher
    if (m_watcherRunning.load()) {
        m_watcherRunning = false;
        if (m_watcherStopEvent) SetEvent(m_watcherStopEvent);
        if (m_watcherThread.joinable()) m_watcherThread.join();
        if (m_watcherStopEvent) { CloseHandle(m_watcherStopEvent); m_watcherStopEvent = nullptr; }
    }

    // Stop IPC
    if (m_ipcRunning.load()) {
        m_ipcRunning = false;
        if (m_ipcStopEvent) SetEvent(m_ipcStopEvent);
        if (m_ipcThread.joinable()) m_ipcThread.join();
        if (m_ipcStopEvent) { CloseHandle(m_ipcStopEvent); m_ipcStopEvent = nullptr; }
    }

    unloadPlugin();
=======
    unloadPlugin();
    
    if (m_ipcServer) {
        m_ipcServer->close();
        m_ipcServer.reset();
    }
    
    m_watcher.reset();
    m_reloadTimer.reset();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

inline bool ThermalPluginLoader::loadPlugin(const std::string& pluginPath)
{
<<<<<<< HEAD
    std::lock_guard<std::mutex> lock(m_mutex);

    // Unload existing module
    if (m_hModule) {
        if (m_plugin) { m_plugin->shutdown(); m_plugin = nullptr; }
        FreeLibrary(m_hModule);
        m_hModule = nullptr;
    }

    setStatus(PluginStatus::Loading);

    // Resolve path
=======
    std::mutexLocker locker(&m_mutex);
    
    // Unload existing plugin
    if (m_loader && m_loader->isLoaded()) {
        locker.unlock();
        unloadPlugin();
        locker.relock();
    }
    
    setStatus(PluginStatus::Loading);
    
    // Find plugin path
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::string path = pluginPath.empty() ? findPluginPath() : pluginPath;
    if (path.empty()) {
        m_lastError = "Could not find thermal_dashboard.dll";
        setStatus(PluginStatus::Error);
<<<<<<< HEAD
        if (m_cbError) m_cbError(m_lastError);
        return false;
    }

    // Load DLL
    m_hModule = LoadLibraryA(path.c_str());
    if (!m_hModule) {
        DWORD err = GetLastError();
        m_lastError = "LoadLibrary failed (" + std::to_string(err) + "): " + path;
        setStatus(PluginStatus::Error);
        if (m_cbError) m_cbError(m_lastError);
        return false;
    }

    // Resolve factory function
    auto factory = reinterpret_cast<CreateThermalPluginFunc>(
        GetProcAddress(m_hModule, "CreateThermalPlugin"));
    if (!factory) {
        m_lastError = "DLL does not export CreateThermalPlugin: " + path;
        FreeLibrary(m_hModule);
        m_hModule = nullptr;
        setStatus(PluginStatus::Error);
        if (m_cbError) m_cbError(m_lastError);
        return false;
    }

    m_plugin = factory();
    if (!m_plugin) {
        m_lastError = "CreateThermalPlugin returned nullptr";
        FreeLibrary(m_hModule);
        m_hModule = nullptr;
        setStatus(PluginStatus::Error);
        if (m_cbError) m_cbError(m_lastError);
        return false;
    }

    // Initialize plugin
    if (!m_plugin->initialize()) {
        m_lastError = "Plugin initialization failed";
        m_plugin = nullptr;
        FreeLibrary(m_hModule);
        m_hModule = nullptr;
        setStatus(PluginStatus::Error);
        if (m_cbError) m_cbError(m_lastError);
        return false;
    }

    m_currentPluginPath = path;
    setStatus(PluginStatus::Loaded);
    if (m_cbLoaded) m_cbLoaded(PluginStatus::Loaded);
=======
        pluginError(m_lastError);
        return false;
    }


    // Create loader and load
    m_loader = std::make_unique<QPluginLoader>(path);
    
    if (!m_loader->load()) {
        m_lastError = m_loader->errorString();
        setStatus(PluginStatus::Error);
        pluginError(m_lastError);
        return false;
    }
    
    // Get plugin interface
    void* instance = m_loader->instance();
// REMOVED_QT:     m_plugin = qobject_cast<rawrxd::thermal::IThermalDashboardPlugin*>(instance);
    
    if (!m_plugin) {
        m_lastError = "Plugin does not implement IThermalDashboardPlugin";
        m_loader->unload();
        setStatus(PluginStatus::Error);
        pluginError(m_lastError);
        return false;
    }
    
    // Initialize plugin
    if (!m_plugin->initialize()) {
        m_lastError = "Plugin initialization failed";
        m_loader->unload();
        m_plugin = nullptr;
        setStatus(PluginStatus::Error);
        pluginError(m_lastError);
        return false;
    }
    
    m_currentPluginPath = path;
    
    // Watch for changes
    if (m_autoReloadEnabled && m_watcher) {
        m_watcher->addPath(path);
    }
    
    setStatus(PluginStatus::Loaded);
             << m_plugin->pluginName() << m_plugin->pluginVersion();
    
    pluginLoaded();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

inline bool ThermalPluginLoader::unloadPlugin()
{
<<<<<<< HEAD
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_hModule) return true;

    setStatus(PluginStatus::Unloading);

=======
    std::mutexLocker locker(&m_mutex);
    
    if (!m_loader || !m_loader->isLoaded()) {
        return true;
    }
    
    setStatus(PluginStatus::Unloading);
    
    // Stop watching
    if (m_watcher && !m_currentPluginPath.empty()) {
        m_watcher->removePath(m_currentPluginPath);
    }
    
    // Shutdown plugin
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    if (m_plugin) {
        m_plugin->shutdown();
        m_plugin = nullptr;
    }
<<<<<<< HEAD

    if (!FreeLibrary(m_hModule)) {
        m_lastError = "FreeLibrary failed (" + std::to_string(GetLastError()) + ")";
        setStatus(PluginStatus::Error);
        return false;
    }
    m_hModule = nullptr;
    m_currentPluginPath.clear();
    setStatus(PluginStatus::NotLoaded);
    if (m_cbUnloaded) m_cbUnloaded(PluginStatus::NotLoaded);
=======
    
    // Unload DLL
    if (!m_loader->unload()) {
        m_lastError = m_loader->errorString();
        setStatus(PluginStatus::Error);
        return false;
    }
    
    m_loader.reset();
    m_currentPluginPath.clear();
    
    setStatus(PluginStatus::NotLoaded);
    
    pluginUnloaded();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

inline bool ThermalPluginLoader::reloadPlugin()
{
<<<<<<< HEAD
    std::string path;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        path = m_currentPluginPath;
    }
    if (!unloadPlugin()) return false;
    Sleep(100);  // Brief delay to ensure file handle released
=======
    std::string path = m_currentPluginPath;
    if (!unloadPlugin()) {
        return false;
    }
    
    // Small delay to ensure file is released
    std::thread::msleep(100);
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return loadPlugin(path);
}

inline bool ThermalPluginLoader::isLoaded() const
{
<<<<<<< HEAD
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_hModule != nullptr && m_plugin != nullptr;
=======
    std::mutexLocker locker(&m_mutex);
    return m_loader && m_loader->isLoaded() && m_plugin != nullptr;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

inline rawrxd::thermal::IThermalDashboardPlugin* ThermalPluginLoader::plugin() const
{
<<<<<<< HEAD
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_plugin;
}

inline std::string ThermalPluginLoader::lastError() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_lastError;
}

=======
    std::mutexLocker locker(&m_mutex);
    return m_plugin;
}

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
inline void ThermalPluginLoader::setAutoReload(bool enabled)
{
    m_autoReloadEnabled = enabled;
}

inline void ThermalPluginLoader::setIpcEnabled(bool enabled)
{
    m_ipcEnabled = enabled;
<<<<<<< HEAD
}

inline void ThermalPluginLoader::setStatus(PluginStatus s)
{
    auto old = m_status.exchange(s);
    if (old != s && m_cbStatus) {
        m_cbStatus(s);
=======
    if (enabled && !m_ipcServer) {
        setupIpcServer();
    } else if (!enabled && m_ipcServer) {
        m_ipcServer->close();
        m_ipcServer.reset();
    }
}

inline void ThermalPluginLoader::setStatus(PluginStatus status)
{
    if (m_status != status) {
        m_status = status;
        statusChanged(status);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

inline std::string ThermalPluginLoader::findPluginPath() const
{
<<<<<<< HEAD
    const char* pluginName = "thermal_dashboard.dll";

    for (const auto& dir : m_searchPaths) {
        namespace fs = std::filesystem;
        fs::path candidate = fs::path(dir) / pluginName;
        if (fs::exists(candidate)) {
            return candidate.string();
        }
    }
    return {};
=======
    const std::string pluginName = "thermal_dashboard.dll";
    
    for (const std::string& dir : m_searchPaths) {
        std::string path = // (dir).filePath(pluginName);
        if (std::filesystem::exists(path)) {
            return path;
        }
    }
    
    return std::string();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

inline void ThermalPluginLoader::setupIpcServer()
{
<<<<<<< HEAD
    m_ipcStopEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!m_ipcStopEvent) return;

    m_ipcRunning = true;
    m_ipcThread = std::thread(&ThermalPluginLoader::ipcThreadFunc, this);
}

inline void ThermalPluginLoader::ipcThreadFunc()
{
    const char* pipeName = "\\\\.\\pipe\\RawrXD_PluginLoader";

    while (m_ipcRunning.load()) {
        // Create named pipe instance
        HANDLE hPipe = CreateNamedPipeA(
            pipeName,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096, 4096, 0, nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        // Wait for connection with stop event
        OVERLAPPED ov{};
        ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
        ConnectNamedPipe(hPipe, &ov);

        HANDLE waitHandles[] = { ov.hEvent, m_ipcStopEvent };
        DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
        CloseHandle(ov.hEvent);

        if (waitResult != WAIT_OBJECT_0) {
            // Stop event or error
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            break;
        }

        // Read command
        char buf[4096]{};
        DWORD bytesRead = 0;
        if (ReadFile(hPipe, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buf[bytesRead] = '\0';
            handleIpcCommand(std::string(buf, bytesRead), hPipe);
        }

        FlushFileBuffers(hPipe);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

inline void ThermalPluginLoader::handleIpcCommand(const std::string& json, HANDLE pipe)
{
    // Minimal JSON field extraction for IPC commands
    // Expected: {"action":"LOAD_PLUGIN","path":"..."} or {"action":"STATUS"}
    std::string response;

    auto extractField = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":\"";
        auto pos = json.find(search);
        if (pos == std::string::npos) return {};
        pos += search.size();
        auto end = json.find('"', pos);
        if (end == std::string::npos) return {};
        return json.substr(pos, end - pos);
    };

    std::string action = extractField("action");

    if (action == "LOAD_PLUGIN") {
        std::string path = extractField("path");
        bool ok = loadPlugin(path);
        response = ok ? R"({"success":true})"
                      : R"({"success":false,"error":")" + m_lastError + "\"}";
    }
    else if (action == "UNLOAD_PLUGIN") {
        bool ok = unloadPlugin();
        response = ok ? R"({"success":true})" : R"({"success":false})";
    }
    else if (action == "RELOAD_PLUGIN") {
        bool ok = reloadPlugin();
        response = ok ? R"({"success":true})"
                      : R"({"success":false,"error":")" + m_lastError + "\"}";
    }
    else if (action == "STATUS") {
        bool loaded = isLoaded();
        response = R"({"success":true,"loaded":)" + std::string(loaded ? "true" : "false") +
                   R"(,"status":)" + std::to_string(static_cast<int>(m_status.load())) + "}";
    }
    else {
        response = R"({"success":false,"error":"Unknown action"})";
    }

    response += "\n";
    DWORD written = 0;
    WriteFile(pipe, response.c_str(), static_cast<DWORD>(response.size()), &written, nullptr);
}

inline void ThermalPluginLoader::watcherThreadFunc()
{
    namespace fs = std::filesystem;

    while (m_watcherRunning.load()) {
        // Interruptible 1-second poll
        if (WaitForSingleObject(m_watcherStopEvent, 1000) == WAIT_OBJECT_0) break;
        if (!m_autoReloadEnabled.load()) continue;

        std::string pluginPath;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            pluginPath = m_currentPluginPath;
        }
        if (pluginPath.empty()) continue;

        // Check if file was modified recently
        try {
            auto ftime = fs::last_write_time(pluginPath);
            // Convert file_time to system_clock for comparison
            auto ftimeSys = std::chrono::file_clock::to_sys(ftime);
            auto now = std::chrono::system_clock::now();
            auto age = now - ftimeSys;

            // Debounce: only reload if file changed within last 3s
            // and we haven't reloaded in the last 2s
            auto steadyNow = std::chrono::steady_clock::now();
            if (age < std::chrono::seconds(3) &&
                steadyNow - m_lastReloadTime > std::chrono::seconds(2)) {
                if (m_cbFileChanged) m_cbFileChanged(pluginPath);
                m_lastReloadTime = steadyNow;
                reloadPlugin();
            }
        } catch (...) {
            // File might be locked during rebuild — ignore
        }
    }
}

} // namespace rawrxd::core
=======
    // Create named pipe server for external injection commands
    std::string pipeName = std::string("RawrXD_PluginLoader_%1"));
    
    m_ipcServer = std::make_unique<void*>(this);
    m_ipcServer->setSocketOptions(void*::WorldAccessOption);
    
    // Remove any stale socket
    void*::removeServer(pipeName);
    
    if (!m_ipcServer->listen(pipeName)) {
        return;
}

inline void ThermalPluginLoader::onFileChanged(const std::string& path)
{
    pluginFileChanged(path);
    
    if (m_autoReloadEnabled) {
        m_pendingReload = true;
        m_reloadTimer->start();  // Debounce
    }
}

inline void ThermalPluginLoader::onReloadTimer()
{
    if (m_pendingReload) {
        m_pendingReload = false;
        reloadPlugin();
    }
}

inline void ThermalPluginLoader::onNewIpcConnection()
{
    while (m_ipcServer->hasPendingConnections()) {
        void** socket = m_ipcServer->nextPendingConnection();
    }
}

inline void ThermalPluginLoader::onIpcReadyRead()
{
// REMOVED_QT:     void** socket = qobject_cast<void**>(sender());
    if (!socket) return;
    
    std::vector<uint8_t> data = socket->readLine();
    void* doc = void*::fromJson(data);
    
    if (doc.isObject()) {
        handleIpcCommand(doc.object(), socket);
    }
}

inline void ThermalPluginLoader::onIpcDisconnected()
{
// REMOVED_QT:     void** socket = qobject_cast<void**>(sender());
    if (socket) {
        m_ipcClients.removeAll(socket);
        socket->deleteLater();
    }
}

inline void ThermalPluginLoader::handleIpcCommand(const void*& cmd, void** socket)
{
    std::string action = cmd["action"].toString();
    void* response;
    
    if (action == "LOAD_PLUGIN") {
        std::string path = cmd["path"].toString();
        bool success = loadPlugin(path);
        response["success"] = success;
        if (!success) {
            response["error"] = m_lastError;
        }
    }
    else if (action == "UNLOAD_PLUGIN") {
        bool success = unloadPlugin();
        response["success"] = success;
    }
    else if (action == "RELOAD_PLUGIN") {
        bool success = reloadPlugin();
        response["success"] = success;
        if (!success) {
            response["error"] = m_lastError;
        }
    }
    else if (action == "STATUS") {
        response["success"] = true;
        response["loaded"] = isLoaded();
        response["status"] = static_cast<int>(m_status);
        if (m_plugin) {
            response["name"] = m_plugin->pluginName();
            response["version"] = m_plugin->pluginVersion();
        }
    }
    else {
        response["success"] = false;
        response["error"] = "Unknown action: " + action;
    }
    
    void* respDoc(response);
    socket->write(respDoc.toJson(void*::Compact) + "\n");
    socket->flush();
}

} // namespace rawrxd::core

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
