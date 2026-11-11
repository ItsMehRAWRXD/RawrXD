// RawrXD Plugin Manager Implementation
// Phase AI: Plugin System

#include "plugin_manager.hpp"
#include <iostream>
#include <fstream>
#include <algorithm>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace rawrxd {
namespace plugin {

// Global plugin manager instance
static std::unique_ptr<PluginManager> g_plugin_manager;

PluginManager* getPluginManager() {
    return g_plugin_manager.get();
}

void setPluginManager(std::unique_ptr<PluginManager> manager) {
    g_plugin_manager = std::move(manager);
}

// PluginManager implementation
PluginManager::PluginManager()
    : sandbox_enabled_(true)
    , initialized_(false) {
}

PluginManager::~PluginManager() {
    shutdown();
}

bool PluginManager::initialize(const std::string& plugin_dir) {
    plugin_directory_ = plugin_dir;
    
    // Create plugin loader
    loader_ = std::make_unique<NativePluginLoader>();
    
    // Initialize sandbox
    if (sandbox_enabled_) {
        sandbox_ = std::make_unique<PluginSandbox>();
        if (!sandbox_->initialize()) {
            std::cerr << "Failed to initialize plugin sandbox" << std::endl;
            return false;
        }
    }
    
    // Create plugin directory if it doesn't exist
    if (!std::filesystem::exists(plugin_directory_)) {
        std::filesystem::create_directories(plugin_directory_);
    }
    
    initialized_ = true;
    
    // Auto-discover and load plugins
    auto plugins = discoverPlugins();
    for (const auto& info : plugins) {
        std::string plugin_path = plugin_directory_ + "/" + info.id;
        #ifdef _WIN32
        plugin_path += ".dll";
        #else
        plugin_path += ".so";
        #endif
        
        if (std::filesystem::exists(plugin_path)) {
            loadPlugin(plugin_path);
        }
    }
    
    return true;
}

void PluginManager::shutdown() {
    if (!initialized_) return;
    
    // Execute shutdown hooks
    HookContext ctx;
    ctx.type = HookType::ON_SHUTDOWN;
    executeHooks(HookType::ON_SHUTDOWN, ctx);
    
    // Unload all plugins
    std::vector<std::string> plugin_ids;
    {
        std::lock_guard<std::mutex> lock(plugins_mutex_);
        for (const auto& [id, plugin] : plugins_) {
            plugin_ids.push_back(id);
        }
    }
    
    for (const auto& id : plugin_ids) {
        unloadPlugin(id);
    }
    
    // Cleanup sandbox
    if (sandbox_) {
        sandbox_->shutdown();
        sandbox_.reset();
    }
    
    initialized_ = false;
}

std::vector<PluginInfo> PluginManager::discoverPlugins() {
    std::vector<PluginInfo> discovered;
    
    if (!std::filesystem::exists(plugin_directory_)) {
        return discovered;
    }
    
    // Look for plugin manifest files
    for (const auto& entry : std::filesystem::directory_iterator(plugin_directory_)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            std::ifstream file(entry.path());
            if (file.is_open()) {
                // Parse manifest (simplified)
                PluginInfo info;
                info.id = entry.path().stem().string();
                discovered.push_back(info);
            }
        }
    }
    
    return discovered;
}

bool PluginManager::loadPlugin(const std::string& plugin_path) {
    if (!initialized_) {
        std::cerr << "Plugin manager not initialized" << std::endl;
        return false;
    }
    
    // Validate plugin
    if (!validatePlugin(plugin_path)) {
        std::cerr << "Plugin validation failed: " << plugin_path << std::endl;
        return false;
    }
    
    // Load library
    void* handle = loadLibrary(plugin_path);
    if (!handle) {
        std::cerr << "Failed to load plugin library: " << plugin_path << std::endl;
        return false;
    }
    
    // Create plugin instance
    IPlugin* plugin = createPluginInstance(handle);
    if (!plugin) {
        std::cerr << "Failed to create plugin instance: " << plugin_path << std::endl;
        unloadLibrary(handle);
        return false;
    }
    
    // Get plugin info
    PluginInfo info = plugin->getInfo();
    
    // Check dependencies
    if (!checkDependencies(info)) {
        std::cerr << "Plugin dependencies not satisfied: " << info.name << std::endl;
        unloadLibrary(handle);
        return false;
    }
    
    // Check sandbox
    if (sandbox_enabled_ && sandbox_) {
        if (!sandbox_->validatePlugin(plugin_path)) {
            std::cerr << "Plugin failed sandbox validation: " << info.name << std::endl;
            unloadLibrary(handle);
            return false;
        }
    }
    
    // Initialize plugin
    auto config_it = plugin_configs_.find(info.id);
    std::unordered_map<std::string, std::string> config;
    if (config_it != plugin_configs_.end()) {
        config = config_it->second.settings;
    }
    
    if (!plugin->initialize(config)) {
        std::cerr << "Failed to initialize plugin: " << info.name << std::endl;
        unloadLibrary(handle);
        return false;
    }
    
    // Store plugin
    {
        std::lock_guard<std::mutex> lock(plugins_mutex_);
        plugins_[info.id] = std::shared_ptr<IPlugin>(plugin, [handle, this](IPlugin* p) {
            p->shutdown();
            delete p;
            unloadLibrary(handle);
        });
        plugin_handles_[info.id] = handle;
    }
    
    std::cout << "Plugin loaded: " << info.name << " v" << info.version << std::endl;
    return true;
}

bool PluginManager::unloadPlugin(const std::string& plugin_id) {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    
    auto it = plugins_.find(plugin_id);
    if (it == plugins_.end()) {
        return false;
    }
    
    // Shutdown and remove plugin
    it->second->shutdown();
    plugins_.erase(it);
    plugin_handles_.erase(plugin_id);
    
    // Unregister hooks
    std::lock_guard<std::mutex> hook_lock(hooks_mutex_);
    for (auto& [type, registrations] : hooks_) {
        registrations.erase(
            std::remove_if(registrations.begin(), registrations.end(),
                [&plugin_id](const HookRegistration& reg) {
                    return reg.plugin_id == plugin_id;
                }),
            registrations.end()
        );
    }
    
    std::cout << "Plugin unloaded: " << plugin_id << std::endl;
    return true;
}

bool PluginManager::reloadPlugin(const std::string& plugin_id) {
    // Get plugin path
    std::string plugin_path;
    {
        std::lock_guard<std::mutex> lock(plugins_mutex_);
        auto it = plugin_handles_.find(plugin_id);
        if (it == plugin_handles_.end()) {
            return false;
        }
        // Would need to store original path
    }
    
    // Unload and reload
    if (!unloadPlugin(plugin_id)) {
        return false;
    }
    
    return loadPlugin(plugin_path);
}

bool PluginManager::enablePlugin(const std::string& plugin_id) {
    auto plugin = getPlugin(plugin_id);
    if (!plugin) {
        return false;
    }
    
    plugin->setState(PluginState::RUNNING);
    return true;
}

bool PluginManager::disablePlugin(const std::string& plugin_id) {
    auto plugin = getPlugin(plugin_id);
    if (!plugin) {
        return false;
    }
    
    plugin->setState(PluginState::DISABLED);
    return true;
}

bool PluginManager::configurePlugin(const std::string& plugin_id, const PluginConfig& config) {
    plugin_configs_[plugin_id] = config;
    
    auto plugin = getPlugin(plugin_id);
    if (!plugin) {
        return false;
    }
    
    // Notify plugin of configuration changes
    for (const auto& [key, value] : config.settings) {
        plugin->onConfigChanged(key, value);
    }
    
    return true;
}

std::shared_ptr<IPlugin> PluginManager::getPlugin(const std::string& plugin_id) const {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    
    auto it = plugins_.find(plugin_id);
    if (it != plugins_.end()) {
        return it->second;
    }
    
    return nullptr;
}

std::vector<std::shared_ptr<IPlugin>> PluginManager::getPluginsByType(PluginType type) const {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    
    std::vector<std::shared_ptr<IPlugin>> result;
    for (const auto& [id, plugin] : plugins_) {
        if (plugin->getInfo().type == type) {
            result.push_back(plugin);
        }
    }
    return result;
}

std::vector<std::shared_ptr<IPlugin>> PluginManager::getAllPlugins() const {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    
    std::vector<std::shared_ptr<IPlugin>> result;
    for (const auto& [id, plugin] : plugins_) {
        result.push_back(plugin);
    }
    return result;
}

std::vector<PluginInfo> PluginManager::getLoadedPluginInfo() const {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    
    std::vector<PluginInfo> result;
    for (const auto& [id, plugin] : plugins_) {
        result.push_back(plugin->getInfo());
    }
    return result;
}

void PluginManager::registerHook(const std::string& plugin_id, HookType type, 
                                  HookCallback callback, int priority) {
    std::lock_guard<std::mutex> lock(hooks_mutex_);
    
    HookRegistration reg;
    reg.type = type;
    reg.plugin_id = plugin_id;
    reg.priority = priority;
    reg.callback = callback;
    
    hooks_[type].push_back(reg);
    sortHooks(type);
}

void PluginManager::unregisterHook(const std::string& plugin_id, HookType type) {
    std::lock_guard<std::mutex> lock(hooks_mutex_);
    
    auto& registrations = hooks_[type];
    registrations.erase(
        std::remove_if(registrations.begin(), registrations.end(),
            [&plugin_id](const HookRegistration& reg) {
                return reg.plugin_id == plugin_id;
            }),
        registrations.end()
    );
}

void PluginManager::executeHooks(HookType type, HookContext& context) {
    std::lock_guard<std::mutex> lock(hooks_mutex_);
    
    auto it = hooks_.find(type);
    if (it == hooks_.end()) return;
    
    for (const auto& reg : it->second) {
        try {
            reg.callback(context);
        } catch (const std::exception& e) {
            std::cerr << "Hook execution failed: " << e.what() << std::endl;
        }
    }
}

bool PluginManager::executeHooksWithCancel(HookType type, HookContext& context) {
    std::lock_guard<std::mutex> lock(hooks_mutex_);
    
    auto it = hooks_.find(type);
    if (it == hooks_.end()) return true;
    
    for (const auto& reg : it->second) {
        try {
            reg.callback(context);
            if (context.cancelled) {
                return false;
            }
        } catch (const std::exception& e) {
            std::cerr << "Hook execution failed: " << e.what() << std::endl;
        }
    }
    
    return true;
}

void PluginManager::notifyEvent(const std::string& event_type, 
                                 const std::unordered_map<std::string, std::string>& data) {
    // Notify all plugins that implement event handling
    auto plugins = getAllPlugins();
    for (const auto& plugin : plugins) {
        // Plugin would implement event handling
        // plugin->onEvent(event_type, data);
    }
}

bool PluginManager::isHealthy() const {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    
    for (const auto& [id, plugin] : plugins_) {
        if (!plugin->isHealthy()) {
            return false;
        }
    }
    return true;
}

size_t PluginManager::getLoadedPluginCount() const {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    return plugins_.size();
}

size_t PluginManager::getActivePluginCount() const {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    
    size_t count = 0;
    for (const auto& [id, plugin] : plugins_) {
        if (plugin->getState() == PluginState::RUNNING) {
            count++;
        }
    }
    return count;
}

void PluginManager::setPluginDirectory(const std::string& dir) {
    plugin_directory_ = dir;
}

std::string PluginManager::getPluginDirectory() const {
    return plugin_directory_;
}

void PluginManager::setSandboxEnabled(bool enabled) {
    sandbox_enabled_ = enabled;
}

bool PluginManager::isSandboxEnabled() const {
    return sandbox_enabled_;
}

bool PluginManager::validatePlugin(const std::string& plugin_path) {
    // Check file exists
    if (!std::filesystem::exists(plugin_path)) {
        return false;
    }
    
    // Check file extension
    std::string ext = plugin_path.substr(plugin_path.find_last_of("."));
    #ifdef _WIN32
    if (ext != ".dll") return false;
    #else
    if (ext != ".so") return false;
    #endif
    
    return true;
}

bool PluginManager::checkDependencies(const PluginInfo& info) {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    
    for (const auto& dep : info.dependencies) {
        if (plugins_.find(dep) == plugins_.end()) {
            return false;
        }
    }
    return true;
}

void* PluginManager::loadLibrary(const std::string& path) {
    #ifdef _WIN32
    return LoadLibraryA(path.c_str());
    #else
    return dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    #endif
}

void PluginManager::unloadLibrary(void* handle) {
    if (!handle) return;
    
    #ifdef _WIN32
    FreeLibrary(static_cast<HMODULE>(handle));
    #else
    dlclose(handle);
    #endif
}

IPlugin* PluginManager::createPluginInstance(void* handle) {
    if (!handle) return nullptr;
    
    #ifdef _WIN32
    auto create_func = (CreatePluginFunc)GetProcAddress(static_cast<HMODULE>(handle), "rawrxd_create_plugin");
    #else
    auto create_func = (CreatePluginFunc)dlsym(handle, "rawrxd_create_plugin");
    #endif
    
    if (!create_func) {
        return nullptr;
    }
    
    return create_func();
}

void PluginManager::sortHooks(HookType type) {
    auto& registrations = hooks_[type];
    std::sort(registrations.begin(), registrations.end(),
        [](const HookRegistration& a, const HookRegistration& b) {
            return a.priority > b.priority;
        });
}

// NativePluginLoader implementation
class NativePluginLoader : public PluginLoader {
public:
    std::vector<std::string> getPluginFiles(const std::string& directory) override {
        std::vector<std::string> files;
        
        if (!std::filesystem::exists(directory)) {
            return files;
        }
        
        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                #ifdef _WIN32
                if (ext == ".dll") {
                #else
                if (ext == ".so") {
                #endif
                    files.push_back(entry.path().string());
                }
            }
        }
        
        return files;
    }
    
    void* loadLibrary(const std::string& path) override {
        #ifdef _WIN32
        return LoadLibraryA(path.c_str());
        #else
        return dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
        #endif
    }
    
    void unloadLibrary(void* handle) override {
        if (!handle) return;
        
        #ifdef _WIN32
        FreeLibrary(static_cast<HMODULE>(handle));
        #else
        dlclose(handle);
        #endif
    }
    
    void* getSymbol(void* handle, const std::string& name) override {
        #ifdef _WIN32
        return GetProcAddress(static_cast<HMODULE>(handle), name.c_str());
        #else
        return dlsym(handle, name.c_str());
        #endif
    }
    
    std::string getError() override {
        #ifdef _WIN32
        DWORD error = GetLastError();
        if (error == 0) return "";
        
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        
        std::string message(messageBuffer, size);
        LocalFree(messageBuffer);
        return message;
        #else
        const char* error = dlerror();
        return error ? error : "";
        #endif
    }
};

// PluginSandbox implementation
PluginSandbox::PluginSandbox()
    : initialized_(false)
    , in_sandbox_(false)
    , memory_limit_(0)
    , cpu_time_limit_(0)
    , filesystem_allowed_(false)
    , network_allowed_(false) {
}

PluginSandbox::~PluginSandbox() {
    shutdown();
}

bool PluginSandbox::initialize() {
    initialized_ = true;
    return true;
}

void PluginSandbox::shutdown() {
    if (in_sandbox_) {
        exitSandbox();
    }
    initialized_ = false;
}

void PluginSandbox::setMemoryLimit(size_t bytes) {
    memory_limit_ = bytes;
}

void PluginSandbox::setCpuTimeLimit(int seconds) {
    cpu_time_limit_ = seconds;
}

void PluginSandbox::setFileSystemAccess(bool allowed) {
    filesystem_allowed_ = allowed;
}

void PluginSandbox::setNetworkAccess(bool allowed) {
    network_allowed_ = allowed;
}

bool PluginSandbox::enterSandbox() {
    // Platform-specific sandbox implementation would go here
    in_sandbox_ = true;
    return true;
}

void PluginSandbox::exitSandbox() {
    in_sandbox_ = false;
}

bool PluginSandbox::isInSandbox() const {
    return in_sandbox_;
}

bool PluginSandbox::validatePlugin(const std::string& plugin_path) {
    // Perform security validation on plugin
    // This is a simplified implementation
    
    // Check file size
    auto file_size = std::filesystem::file_size(plugin_path);
    if (file_size > 100 * 1024 * 1024) {  // 100MB limit
        return false;
    }
    
    return true;
}

// HookManager implementation
HookManager::HookManager() = default;

void HookManager::registerHook(const HookRegistration& reg) {
    std::lock_guard<std::mutex> lock(mutex_);
    hooks_[reg.type].push_back(reg);
    sortHooks(reg.type);
}

void HookManager::unregisterHook(const std::string& plugin_id, HookType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& registrations = hooks_[type];
    registrations.erase(
        std::remove_if(registrations.begin(), registrations.end(),
            [&plugin_id](const HookRegistration& reg) {
                return reg.plugin_id == plugin_id;
            }),
        registrations.end()
    );
}

void HookManager::executeHooks(HookType type, HookContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = hooks_.find(type);
    if (it == hooks_.end()) return;
    
    for (const auto& reg : it->second) {
        try {
            reg.callback(context);
        } catch (...) {
            // Log error but continue
        }
    }
}

bool HookManager::executeHooksWithCancel(HookType type, HookContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = hooks_.find(type);
    if (it == hooks_.end()) return true;
    
    for (const auto& reg : it->second) {
        try {
            reg.callback(context);
            if (context.cancelled) {
                return false;
            }
        } catch (...) {
            // Log error but continue
        }
    }
    
    return true;
}

std::vector<HookRegistration> HookManager::getHooks(HookType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = hooks_.find(type);
    if (it != hooks_.end()) {
        return it->second;
    }
    
    return {};
}

void HookManager::clearHooks() {
    std::lock_guard<std::mutex> lock(mutex_);
    hooks_.clear();
}

void HookManager::sortHooks(HookType type) {
    auto& registrations = hooks_[type];
    std::sort(registrations.begin(), registrations.end(),
        [](const HookRegistration& a, const HookRegistration& b) {
            return a.priority > b.priority;
        });
}

} // namespace plugin
} // namespace rawrxd
