// RawrXD Plugin Manager Implementation
// Phase X.1: Plugin system for extensibility

#include "PluginManager.hpp"
#include <filesystem>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace RawrXD {
namespace Extensions {

// ============================================================================
// PluginManager Implementation
// ============================================================================

PluginManager::PluginManager() = default;

PluginManager::~PluginManager() {
    if (initialized_) {
        shutdown();
    }
}

bool PluginManager::initialize(const std::string& pluginDirectory) {
    pluginDirectory_ = pluginDirectory;
    
    // Create plugin directory if it doesn't exist
    if (!std::filesystem::exists(pluginDirectory_)) {
        std::filesystem::create_directories(pluginDirectory_);
    }
    
    initialized_ = true;
    return true;
}

bool PluginManager::shutdown() {
    // Unload all plugins
    for (auto& [name, instance] : plugins_) {
        if (instance.instance && instance.destroyFunc) {
            instance.instance->shutdown();
            instance.destroyFunc(instance.instance);
        }
        
        // Close library
        if (instance.libraryHandle) {
#ifdef _WIN32
            FreeLibrary(static_cast<HMODULE>(instance.libraryHandle));
#else
            dlclose(instance.libraryHandle);
#endif
        }
    }
    
    plugins_.clear();
    initialized_ = false;
    return true;
}

// ============================================================================
// Plugin Loading
// ============================================================================

bool PluginManager::loadPlugin(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Validate plugin
    PluginMetadata metadata;
    if (!validatePlugin(path, metadata)) {
        return false;
    }
    
    // Check if already loaded
    if (plugins_.find(metadata.name) != plugins_.end()) {
        return false;
    }
    
    // Check dependencies
    if (!checkDependencies(metadata.name)) {
        auto missing = getMissingDependencies(metadata.name);
        // Would log missing dependencies
        return false;
    }
    
    // Load library
#ifdef _WIN32
    HMODULE handle = LoadLibraryA(path.c_str());
    if (!handle) return false;
    
    auto createFunc = (PluginCreateFunc)GetProcAddress(handle, "createPlugin");
    auto destroyFunc = (PluginDestroyFunc)GetProcAddress(handle, "destroyPlugin");
#else
    void* handle = dlopen(path.c_str(), RTLD_LAZY);
    if (!handle) return false;
    
    auto createFunc = (PluginCreateFunc)dlsym(handle, "createPlugin");
    auto destroyFunc = (PluginDestroyFunc)dlsym(handle, "destroyPlugin");
#endif
    
    if (!createFunc || !destroyFunc) {
#ifdef _WIN32
        FreeLibrary(handle);
#else
        dlclose(handle);
#endif
        return false;
    }
    
    // Create plugin instance
    IPlugin* plugin = createFunc();
    if (!plugin) {
#ifdef _WIN32
        FreeLibrary(handle);
#else
        dlclose(handle);
#endif
        return false;
    }
    
    // Initialize plugin
    if (!plugin->initialize()) {
        destroyFunc(plugin);
#ifdef _WIN32
        FreeLibrary(handle);
#else
        dlclose(handle);
#endif
        return false;
    }
    
    // Store plugin instance
    PluginInstance instance;
    instance.metadata = metadata;
    instance.metadata.path = path;
    instance.metadata.isLoaded = true;
    instance.instance = plugin;
    instance.libraryHandle = handle;
    instance.destroyFunc = destroyFunc;
    instance.loadedAt = std::chrono::system_clock::now();
    
    plugins_[metadata.name] = instance;
    
    notifyEvent("loaded", metadata.name);
    return true;
}

bool PluginManager::unloadPlugin(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = plugins_.find(name);
    if (it == plugins_.end()) {
        return false;
    }
    
    // Shutdown and destroy plugin
    if (it->second.instance) {
        it->second.instance->shutdown();
        if (it->second.destroyFunc) {
            it->second.destroyFunc(it->second.instance);
        }
    }
    
    // Close library
    if (it->second.libraryHandle) {
#ifdef _WIN32
        FreeLibrary(static_cast<HMODULE>(it->second.libraryHandle));
#else
        dlclose(it->second.libraryHandle);
#endif
    }
    
    plugins_.erase(it);
    notifyEvent("unloaded", name);
    return true;
}

bool PluginManager::reloadPlugin(const std::string& name) {
    auto it = plugins_.find(name);
    if (it == plugins_.end()) {
        return false;
    }
    
    std::string path = it->second.metadata.path;
    
    if (!unloadPlugin(name)) {
        return false;
    }
    
    return loadPlugin(path);
}

bool PluginManager::loadAllPlugins() {
    if (!std::filesystem::exists(pluginDirectory_)) {
        return false;
    }
    
    std::vector<std::string> pluginPaths;
    
    // Scan for plugin files
    for (const auto& entry : std::filesystem::directory_iterator(pluginDirectory_)) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
#ifdef _WIN32
            if (ext == ".dll" || ext == ".rawrxd") {
#else
            if (ext == ".so" || ext == ".rawrxd") {
#endif
                pluginPaths.push_back(entry.path().string());
            }
        }
    }
    
    // Resolve load order based on dependencies
    auto loadOrder = resolveLoadOrder(pluginPaths);
    
    // Load plugins in order
    bool allSuccess = true;
    for (const auto& path : loadOrder) {
        if (!loadPlugin(path)) {
            allSuccess = false;
        }
    }
    
    return allSuccess;
}

// ============================================================================
// Plugin Management
// ============================================================================

bool PluginManager::enablePlugin(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = plugins_.find(name);
    if (it == plugins_.end()) {
        return false;
    }
    
    it->second.metadata.isEnabled = true;
    notifyEvent("enabled", name);
    return true;
}

bool PluginManager::disablePlugin(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = plugins_.find(name);
    if (it == plugins_.end()) {
        return false;
    }
    
    it->second.metadata.isEnabled = false;
    notifyEvent("disabled", name);
    return true;
}

bool PluginManager::isPluginLoaded(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = plugins_.find(name);
    if (it != plugins_.end()) {
        return it->second.metadata.isLoaded;
    }
    return false;
}

bool PluginManager::isPluginEnabled(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = plugins_.find(name);
    if (it != plugins_.end()) {
        return it->second.metadata.isEnabled;
    }
    return false;
}

// ============================================================================
// Plugin Access
// ============================================================================

IPlugin* PluginManager::getPlugin(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = plugins_.find(name);
    if (it != plugins_.end()) {
        return it->second.instance;
    }
    return nullptr;
}

std::vector<std::string> PluginManager::listPlugins() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, instance] : plugins_) {
        result.push_back(name);
    }
    return result;
}

std::vector<std::string> PluginManager::listLoadedPlugins() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, instance] : plugins_) {
        if (instance.metadata.isLoaded) {
            result.push_back(name);
        }
    }
    return result;
}

std::vector<std::string> PluginManager::listEnabledPlugins() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, instance] : plugins_) {
        if (instance.metadata.isEnabled) {
            result.push_back(name);
        }
    }
    return result;
}

PluginMetadata PluginManager::getPluginMetadata(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = plugins_.find(name);
    if (it != plugins_.end()) {
        return it->second.metadata;
    }
    return PluginMetadata{};
}

// ============================================================================
// Capabilities
// ============================================================================

std::vector<std::string> PluginManager::getAvailableCapabilities() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::set<std::string> capabilities;
    for (const auto& [name, instance] : plugins_) {
        if (instance.metadata.isLoaded && instance.metadata.isEnabled) {
            for (const auto& cap : instance.metadata.capabilities) {
                capabilities.insert(cap);
            }
        }
    }
    
    return std::vector<std::string>(capabilities.begin(), capabilities.end());
}

std::vector<std::string> PluginManager::getPluginsWithCapability(const std::string& capability) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, instance] : plugins_) {
        if (instance.metadata.isLoaded && instance.metadata.isEnabled) {
            auto& caps = instance.metadata.capabilities;
            if (std::find(caps.begin(), caps.end(), capability) != caps.end()) {
                result.push_back(name);
            }
        }
    }
    return result;
}

bool PluginManager::hasCapability(const std::string& capability) const {
    return !getPluginsWithCapability(capability).empty();
}

// ============================================================================
// Extension Points
// ============================================================================

void PluginManager::registerExtensionPoint(const ExtensionPoint& point) {
    std::lock_guard<std::mutex> lock(mutex_);
    extensionPoints_[point.name] = point;
}

void PluginManager::unregisterExtensionPoint(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    extensionPoints_.erase(name);
}

std::vector<std::string> PluginManager::listExtensionPoints() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, point] : extensionPoints_) {
        result.push_back(name);
    }
    return result;
}

std::vector<IPlugin*> PluginManager::getExtensionsForPoint(const std::string& pointName) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<IPlugin*> result;
    
    auto pointIt = extensionPoints_.find(pointName);
    if (pointIt == extensionPoints_.end()) {
        return result;
    }
    
    for (const auto& [name, instance] : plugins_) {
        if (!instance.metadata.isLoaded || !instance.metadata.isEnabled) {
            continue;
        }
        
        // Check if plugin has required capabilities
        bool hasAllCaps = true;
        for (const auto& cap : pointIt->second.requiredCapabilities) {
            auto& caps = instance.metadata.capabilities;
            if (std::find(caps.begin(), caps.end(), cap) == caps.end()) {
                hasAllCaps = false;
                break;
            }
        }
        
        if (hasAllCaps) {
            // Validate plugin
            if (!pointIt->second.validator || pointIt->second.validator(instance.instance)) {
                result.push_back(instance.instance);
            }
        }
    }
    
    return result;
}

// ============================================================================
// Hooks
// ============================================================================

void PluginManager::registerHook(const PluginHook& hook) {
    std::lock_guard<std::mutex> lock(mutex_);
    hooks_[hook.name].push_back(hook);
    
    // Sort by priority
    auto& hookList = hooks_[hook.name];
    std::sort(hookList.begin(), hookList.end(), 
              [](const PluginHook& a, const PluginHook& b) {
                  return a.priority < b.priority;
              });
}

void PluginManager::unregisterHook(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    hooks_.erase(name);
}

void PluginManager::triggerHook(const std::string& name, const std::map<std::string, std::any>& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = hooks_.find(name);
    if (it == hooks_.end()) {
        return;
    }
    
    for (const auto& hook : it->second) {
        if (hook.enabled && hook.callback) {
            hook.callback(data);
        }
    }
}

void PluginManager::triggerHookAsync(const std::string& name, const std::map<std::string, std::any>& data) {
    // Would trigger hook asynchronously in a separate thread
    triggerHook(name, data);
}

// ============================================================================
// Plugin Communication
// ============================================================================

bool PluginManager::sendMessage(const std::string& pluginName, const std::string& message,
                                const std::map<std::string, std::any>& data) {
    // Would implement inter-plugin messaging
    return true;
}

std::any PluginManager::callPluginMethod(const std::string& pluginName, const std::string& method,
                                         const std::vector<std::any>& args) {
    // Would implement method calling via reflection or interface
    return {};
}

// ============================================================================
// Configuration
// ============================================================================

bool PluginManager::setPluginConfig(const std::string& name, const std::string& key, 
                                    const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = plugins_.find(name);
    if (it == plugins_.end()) {
        return false;
    }
    
    it->second.metadata.config[key] = value;
    return true;
}

std::string PluginManager::getPluginConfig(const std::string& name, const std::string& key,
                                             const std::string& defaultValue) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = plugins_.find(name);
    if (it != plugins_.end()) {
        auto configIt = it->second.metadata.config.find(key);
        if (configIt != it->second.metadata.config.end()) {
            return configIt->second;
        }
    }
    return defaultValue;
}

bool PluginManager::savePluginConfig(const std::string& name) {
    // Would save config to file
    return true;
}

bool PluginManager::loadPluginConfig(const std::string& name) {
    // Would load config from file
    return true;
}

// ============================================================================
// Dependency Resolution
// ============================================================================

bool PluginManager::checkDependencies(const std::string& name) const {
    return getMissingDependencies(name).empty();
}

std::vector<std::string> PluginManager::getMissingDependencies(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> missing;
    
    auto it = plugins_.find(name);
    if (it == plugins_.end()) {
        return missing;
    }
    
    for (const auto& dep : it->second.metadata.dependencies) {
        if (plugins_.find(dep) == plugins_.end()) {
            missing.push_back(dep);
        }
    }
    
    return missing;
}

std::vector<std::string> PluginManager::resolveLoadOrder(const std::vector<std::string>& plugins) const {
    // Simple topological sort
    std::vector<std::string> result;
    std::set<std::string> loaded;
    std::set<std::string> visited;
    
    std::function<bool(const std::string&)> visit = [&](const std::string& name) -> bool {
        if (loaded.count(name)) return true;
        if (visited.count(name)) return false;  // Circular dependency
        
        visited.insert(name);
        
        // Get dependencies
        auto it = plugins_.find(name);
        if (it != plugins_.end()) {
            for (const auto& dep : it->second.metadata.dependencies) {
                if (!visit(dep)) return false;
            }
        }
        
        visited.erase(name);
        loaded.insert(name);
        result.push_back(name);
        return true;
    };
    
    for (const auto& plugin : plugins) {
        if (!visit(plugin)) {
            // Circular dependency detected
            return {};
        }
    }
    
    return result;
}

// ============================================================================
// Sandboxing
// ============================================================================

void PluginManager::enableSandboxing(bool enabled) {
    sandboxingEnabled_ = enabled;
}

bool PluginManager::isSandboxingEnabled() const {
    return sandboxingEnabled_;
}

void PluginManager::setPluginPermissions(const std::string& name, 
                                         const std::vector<std::string>& permissions) {
    std::lock_guard<std::mutex> lock(mutex_);
    pluginPermissions_[name] = permissions;
}

std::vector<std::string> PluginManager::getPluginPermissions(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pluginPermissions_.find(name);
    if (it != pluginPermissions_.end()) {
        return it->second;
    }
    return {};
}

bool PluginManager::hasPermission(const std::string& pluginName, const std::string& permission) const {
    auto perms = getPluginPermissions(pluginName);
    return std::find(perms.begin(), perms.end(), permission) != perms.end();
}

// ============================================================================
// Statistics
// ============================================================================

PluginManager::PluginStats PluginManager::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    PluginStats stats{};
    stats.totalPlugins = static_cast<uint32_t>(plugins_.size());
    
    for (const auto& [name, instance] : plugins_) {
        if (instance.metadata.isLoaded) {
            stats.loadedPlugins++;
        }
        if (instance.metadata.isEnabled) {
            stats.enabledPlugins++;
        }
    }
    
    stats.extensionPoints = static_cast<uint32_t>(extensionPoints_.size());
    
    for (const auto& [name, hookList] : hooks_) {
        stats.registeredHooks += static_cast<uint32_t>(hookList.size());
    }
    
    return stats;
}

// ============================================================================
// Events
// ============================================================================

void PluginManager::onPluginEvent(PluginEventCallback callback) {
    eventCallback_ = callback;
}

void PluginManager::notifyEvent(const std::string& event, const std::string& pluginName) {
    if (eventCallback_) {
        eventCallback_(event, pluginName);
    }
}

// ============================================================================
// Internal Methods
// ============================================================================

bool PluginManager::validatePlugin(const std::string& path, PluginMetadata& metadata) {
    // Would validate plugin file and extract metadata
    // For now, extract name from path
    metadata.name = std::filesystem::path(path).stem().string();
    metadata.version = "1.0.0";
    metadata.apiVersion = PLUGIN_API_VERSION;
    return true;
}

} // namespace Extensions
} // namespace RawrXD
