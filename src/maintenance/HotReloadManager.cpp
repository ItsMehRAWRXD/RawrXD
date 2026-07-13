// RawrXD Hot Reload Manager Implementation
// Phase W.1: Dynamic configuration and code reloading

#include "HotReloadManager.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <sys/stat.h>
#endif

namespace RawrXD {
namespace Maintenance {

// ============================================================================
// HotReloadManager Implementation
// ============================================================================

HotReloadManager::HotReloadManager() = default;

HotReloadManager::~HotReloadManager() {
    if (running_) {
        shutdown();
    }
}

bool HotReloadManager::initialize(const std::string& configPath) {
    if (running_) {
        return true;
    }
    
    running_ = true;
    
    // Start file watcher thread
    watcherThread_ = std::thread([this]() {
        fileWatcherLoop();
    });
    
    return true;
}

bool HotReloadManager::shutdown() {
    if (!running_) {
        return true;
    }
    
    running_ = false;
    
    if (watcherThread_.joinable()) {
        watcherThread_.join();
    }
    
    return true;
}

// ============================================================================
// Component Registration
// ============================================================================

void HotReloadManager::registerComponent(const ComponentRegistration& registration) {
    std::lock_guard<std::mutex> lock(mutex_);
    components_[registration.name] = registration;
    
    // Watch files
    for (const auto& file : registration.watchedFiles) {
        watchFile(file, registration.name);
    }
}

void HotReloadManager::registerComponent(const std::string& name,
                                          IReloadable* component,
                                          const std::vector<std::string>& watchedFiles) {
    std::lock_guard<std::mutex> lock(mutex_);
    reloadableComponents_[name] = component;
    
    // Watch files
    for (const auto& file : watchedFiles) {
        watchFile(file, name);
    }
}

void HotReloadManager::unregisterComponent(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    components_.erase(name);
    reloadableComponents_.erase(name);
}

bool HotReloadManager::hasComponent(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return components_.find(name) != components_.end() ||
           reloadableComponents_.find(name) != reloadableComponents_.end();
}

std::vector<std::string> HotReloadManager::listComponents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, reg] : components_) {
        result.push_back(name);
    }
    for (const auto& [name, comp] : reloadableComponents_) {
        if (std::find(result.begin(), result.end(), name) == result.end()) {
            result.push_back(name);
        }
    }
    
    return result;
}

// ============================================================================
// Manual Reload
// ============================================================================

ReloadResult HotReloadManager::reloadComponent(const std::string& name, ReloadType type) {
    ReloadResult result;
    result.componentName = name;
    result.type = type;
    result.timestamp = std::chrono::system_clock::now();
    result.oldVersion = getComponentStatus(name).currentVersion;
    
    auto start = std::chrono::steady_clock::now();
    
    if (beforeReloadCallback_) {
        beforeReloadCallback_(name);
    }
    
    result.success = performReload(name, type);
    
    auto end = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    if (result.success) {
        result.newVersion = getComponentStatus(name).currentVersion;
    } else {
        result.errorMessage = "Reload failed";
    }
    
    // Store in history
    {
        std::lock_guard<std::mutex> lock(mutex_);
        reloadHistory_.push_back(result);
    }
    
    notifyReloadCallbacks(result);
    
    if (afterReloadCallback_) {
        afterReloadCallback_(result);
    }
    
    return result;
}

ReloadResult HotReloadManager::reloadAll(ReloadType type) {
    ReloadResult overallResult;
    overallResult.componentName = "ALL";
    overallResult.type = type;
    overallResult.timestamp = std::chrono::system_clock::now();
    overallResult.success = true;
    
    auto components = listComponents();
    for (const auto& name : components) {
        auto result = reloadComponent(name, type);
        if (!result.success) {
            overallResult.success = false;
            overallResult.errorMessage += name + ": " + result.errorMessage + "; ";
        }
    }
    
    return overallResult;
}

bool HotReloadManager::reloadConfiguration(const std::string& componentName) {
    if (componentName.empty()) {
        auto result = reloadAll(ReloadType::CONFIGURATION);
        return result.success;
    }
    auto result = reloadComponent(componentName, ReloadType::CONFIGURATION);
    return result.success;
}

bool HotReloadManager::reloadPlugins() {
    auto result = reloadAll(ReloadType::PLUGIN);
    return result.success;
}

bool HotReloadManager::reloadModels() {
    auto result = reloadAll(ReloadType::MODEL);
    return result.success;
}

bool HotReloadManager::reloadCertificates() {
    auto result = reloadAll(ReloadType::CERTIFICATE);
    return result.success;
}

// ============================================================================
// File Watching
// ============================================================================

void HotReloadManager::watchFile(const std::string& path, const std::string& componentName) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    FileWatchEvent event;
    event.path = path;
    
    if (std::filesystem::exists(path)) {
        event.lastWriteTime = std::filesystem::last_write_time(path);
        event.fileSize = std::filesystem::file_size(path);
        event.hash = calculateFileHash(path);
    }
    
    watchedFiles_[path] = event;
}

void HotReloadManager::unwatchFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    watchedFiles_.erase(path);
}

void HotReloadManager::watchDirectory(const std::string& path, const std::string& pattern) {
    if (!std::filesystem::exists(path)) {
        return;
    }
    
    for (const auto& entry : std::filesystem::directory_iterator(path)) {
        if (entry.is_regular_file()) {
            std::string filename = entry.path().filename().string();
            // Simple pattern matching (would use regex in production)
            if (pattern == "*" || filename.find(pattern) != std::string::npos) {
                watchFile(entry.path().string(), "");
            }
        }
    }
}

std::vector<std::string> HotReloadManager::getWatchedFiles() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [path, event] : watchedFiles_) {
        result.push_back(path);
    }
    return result;
}

// ============================================================================
// Auto-reload Control
// ============================================================================

void HotReloadManager::enableAutoReload(const std::string& componentName) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (componentName.empty()) {
        for (auto& [name, reg] : components_) {
            reg.autoReload = true;
        }
    } else {
        auto it = components_.find(componentName);
        if (it != components_.end()) {
            it->second.autoReload = true;
        }
    }
}

void HotReloadManager::disableAutoReload(const std::string& componentName) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (componentName.empty()) {
        for (auto& [name, reg] : components_) {
            reg.autoReload = false;
        }
    } else {
        auto it = components_.find(componentName);
        if (it != components_.end()) {
            it->second.autoReload = false;
        }
    }
}

bool HotReloadManager::isAutoReloadEnabled(const std::string& componentName) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = components_.find(componentName);
    if (it != components_.end()) {
        return it->second.autoReload;
    }
    return false;
}

void HotReloadManager::setReloadCooldown(const std::string& componentName, std::chrono::seconds cooldown) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = components_.find(componentName);
    if (it != components_.end()) {
        it->second.reloadCooldown = cooldown;
    }
}

// ============================================================================
// Reload History
// ============================================================================

std::vector<ReloadResult> HotReloadManager::getReloadHistory(std::chrono::hours duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::system_clock::now() - duration;
    std::vector<ReloadResult> result;
    
    for (const auto& reload : reloadHistory_) {
        if (reload.timestamp >= cutoff) {
            result.push_back(reload);
        }
    }
    
    return result;
}

std::vector<ReloadResult> HotReloadManager::getReloadHistoryForComponent(
    const std::string& name, std::chrono::hours duration) const {
    
    auto all = getReloadHistory(duration);
    std::vector<ReloadResult> result;
    
    for (const auto& reload : all) {
        if (reload.componentName == name) {
            result.push_back(reload);
        }
    }
    
    return result;
}

ReloadResult HotReloadManager::getLastReload(const std::string& componentName) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (componentName.empty()) {
        if (!reloadHistory_.empty()) {
            return reloadHistory_.back();
        }
    } else {
        for (auto it = reloadHistory_.rbegin(); it != reloadHistory_.rend(); ++it) {
            if (it->componentName == componentName) {
                return *it;
            }
        }
    }
    
    return ReloadResult{};
}

// ============================================================================
// Status
// ============================================================================

HotReloadManager::ComponentStatus HotReloadManager::getComponentStatus(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ComponentStatus status;
    status.name = name;
    
    auto regIt = components_.find(name);
    if (regIt != components_.end()) {
        status.autoReloadEnabled = regIt->second.autoReload;
    }
    
    auto compIt = reloadableComponents_.find(name);
    if (compIt != reloadableComponents_.end()) {
        status.currentVersion = compIt->second->getVersion();
        status.isHealthy = true;
    }
    
    // Count reloads
    for (const auto& reload : reloadHistory_) {
        if (reload.componentName == name) {
            status.reloadCount++;
            status.lastReloadTime = reload.timestamp;
        }
    }
    
    return status;
}

std::vector<HotReloadManager::ComponentStatus> HotReloadManager::getAllComponentStatuses() const {
    std::vector<ComponentStatus> result;
    
    auto components = listComponents();
    for (const auto& name : components) {
        result.push_back(getComponentStatus(name));
    }
    
    return result;
}

// ============================================================================
// Callbacks
// ============================================================================

void HotReloadManager::onReload(ReloadCallback callback) {
    reloadCallback_ = callback;
}

void HotReloadManager::onFileChange(FileChangeCallback callback) {
    fileChangeCallback_ = callback;
}

void HotReloadManager::onBeforeReload(std::function<void(const std::string&)> callback) {
    beforeReloadCallback_ = callback;
}

void HotReloadManager::onAfterReload(std::function<void(const ReloadResult&)> callback) {
    afterReloadCallback_ = callback;
}

// ============================================================================
// Validation
// ============================================================================

bool HotReloadManager::validateComponent(const std::string& name) const {
    return hasComponent(name);
}

bool HotReloadManager::canReload(const std::string& name, ReloadType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = components_.find(name);
    if (it != components_.end()) {
        // Check if type is supported
        return (static_cast<int>(it->second.supportedReloads) & static_cast<int>(type)) != 0;
    }
    
    return reloadableComponents_.find(name) != reloadableComponents_.end();
}

std::vector<std::string> HotReloadManager::getReloadableComponents(ReloadType type) const {
    std::vector<std::string> result;
    
    auto components = listComponents();
    for (const auto& name : components) {
        if (canReload(name, type)) {
            result.push_back(name);
        }
    }
    
    return result;
}

// ============================================================================
// Statistics
// ============================================================================

HotReloadManager::ReloadStats HotReloadManager::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ReloadStats stats{};
    stats.totalReloads = static_cast<uint32_t>(reloadHistory_.size());
    
    std::chrono::milliseconds totalDuration{0};
    for (const auto& reload : reloadHistory_) {
        if (reload.success) {
            stats.successfulReloads++;
        } else {
            stats.failedReloads++;
        }
        totalDuration += reload.duration;
        stats.reloadsByComponent[reload.componentName]++;
        stats.reloadsByType[reload.type]++;
    }
    
    if (stats.totalReloads > 0) {
        stats.averageReloadTime = totalDuration / stats.totalReloads;
    }
    
    return stats;
}

// ============================================================================
// Emergency Operations
// ============================================================================

bool HotReloadManager::emergencyRollback(const std::string& componentName) {
    // Would implement rollback to previous version
    return true;
}

bool HotReloadManager::emergencyRollbackAll() {
    auto components = listComponents();
    bool allSuccess = true;
    
    for (const auto& name : components) {
        if (!emergencyRollback(name)) {
            allSuccess = false;
        }
    }
    
    return allSuccess;
}

void HotReloadManager::enableEmergencyMode() {
    emergencyMode_ = true;
    disableAutoReload();
}

void HotReloadManager::disableEmergencyMode() {
    emergencyMode_ = false;
}

bool HotReloadManager::isEmergencyMode() const {
    return emergencyMode_;
}

// ============================================================================
// Internal Methods
// ============================================================================

void HotReloadManager::fileWatcherLoop() {
    while (running_) {
        if (!emergencyMode_) {
            checkForChanges();
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void HotReloadManager::checkForChanges() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [path, event] : watchedFiles_) {
        if (!std::filesystem::exists(path)) {
            continue;
        }
        
        auto currentTime = std::filesystem::last_write_time(path);
        if (currentTime != event.lastWriteTime) {
            // File changed
            event.lastWriteTime = currentTime;
            event.fileSize = std::filesystem::file_size(path);
            std::string newHash = calculateFileHash(path);
            
            if (newHash != event.hash) {
                event.hash = newHash;
                
                if (fileChangeCallback_) {
                    fileChangeCallback_(event);
                }
                
                // Auto-reload if enabled
                // Would find component and reload
            }
        }
    }
}

bool HotReloadManager::performReload(const std::string& name, ReloadType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Try IReloadable interface first
    auto compIt = reloadableComponents_.find(name);
    if (compIt != reloadableComponents_.end()) {
        return compIt->second->reload();
    }
    
    // Try callback registration
    auto regIt = components_.find(name);
    if (regIt != components_.end() && regIt->second.reloadCallback) {
        return regIt->second.reloadCallback();
    }
    
    return false;
}

std::string HotReloadManager::calculateFileHash(const std::string& path) const {
    // Simplified hash - would use proper SHA256 in production
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";
    
    std::ostringstream oss;
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        for (std::streamsize i = 0; i < file.gcount(); ++i) {
            oss << std::hex << (static_cast<unsigned char>(buffer[i]) & 0xFF);
        }
    }
    
    return oss.str();
}

void HotReloadManager::notifyReloadCallbacks(const ReloadResult& result) {
    if (reloadCallback_) {
        reloadCallback_(result);
    }
}

// ============================================================================
// ConfigurationReloader Implementation
// ============================================================================

ConfigurationReloader::ConfigurationReloader(const std::string& configPath)
    : configPath_(configPath) {
    loadFromFile(configPath);
}

bool ConfigurationReloader::reload() {
    return loadFromFile(configPath_);
}

std::string ConfigurationReloader::getVersion() const {
    return "1.0.0";
}

std::string ConfigurationReloader::getValue(const std::string& key, const std::string& defaultValue) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = config_.find(key);
    if (it != config_.end()) {
        return it->second;
    }
    return defaultValue;
}

int ConfigurationReloader::getIntValue(const std::string& key, int defaultValue) const {
    std::string val = getValue(key);
    if (val.empty()) return defaultValue;
    try {
        return std::stoi(val);
    } catch (...) {
        return defaultValue;
    }
}

double ConfigurationReloader::getDoubleValue(const std::string& key, double defaultValue) const {
    std::string val = getValue(key);
    if (val.empty()) return defaultValue;
    try {
        return std::stod(val);
    } catch (...) {
        return defaultValue;
    }
}

bool ConfigurationReloader::getBoolValue(const std::string& key, bool defaultValue) const {
    std::string val = getValue(key);
    if (val.empty()) return defaultValue;
    return val == "true" || val == "1" || val == "yes";
}

std::vector<std::string> ConfigurationReloader::getArrayValue(const std::string& key) const {
    std::string val = getValue(key);
    std::vector<std::string> result;
    
    // Simple comma-separated parsing
    std::istringstream iss(val);
    std::string item;
    while (std::getline(iss, item, ',')) {
        // Trim whitespace
        item.erase(0, item.find_first_not_of(" \t"));
        item.erase(item.find_last_not_of(" \t") + 1);
        if (!item.empty()) {
            result.push_back(item);
        }
    }
    
    return result;
}

void ConfigurationReloader::setValue(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string oldValue = config_[key];
    config_[key] = value;
    
    if (changeCallback_ && oldValue != value) {
        changeCallback_(key, oldValue, value);
    }
}

void ConfigurationReloader::removeValue(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.erase(key);
}

bool ConfigurationReloader::hasValue(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.find(key) != config_.end();
}

bool ConfigurationReloader::saveToFile(const std::string& path) {
    std::string targetPath = path.empty() ? configPath_ : path;
    
    std::ofstream file(targetPath);
    if (!file) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [key, value] : config_) {
        file << key << "=" << value << "\n";
    }
    
    return true;
}

bool ConfigurationReloader::loadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    config_.clear();
    std::string line;
    
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;
        
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            
            // Trim whitespace
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            config_[key] = value;
        }
    }
    
    return true;
}

void ConfigurationReloader::onChange(ConfigChangeCallback callback) {
    changeCallback_ = callback;
}

// ============================================================================
// PluginReloader Implementation
// ============================================================================

PluginReloader::PluginReloader(const std::string& pluginDirectory)
    : pluginDirectory_(pluginDirectory) {
}

bool PluginReloader::reload() {
    // Unload all plugins
    for (auto& [name, handle] : loadedPlugins_) {
#ifdef _WIN32
        FreeLibrary(static_cast<HMODULE>(handle));
#else
        dlclose(handle);
#endif
    }
    loadedPlugins_.clear();
    
    // Reload all plugins
    scanForPlugins();
    
    return true;
}

std::string PluginReloader::getVersion() const {
    return "1.0.0";
}

bool PluginReloader::loadPlugin(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
#ifdef _WIN32
    HMODULE handle = LoadLibraryA(path.c_str());
    if (!handle) return false;
#else
    void* handle = dlopen(path.c_str(), RTLD_LAZY);
    if (!handle) return false;
#endif
    
    std::string name = std::filesystem::path(path).stem().string();
    loadedPlugins_[name] = handle;
    
    return true;
}

bool PluginReloader::unloadPlugin(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = loadedPlugins_.find(name);
    if (it == loadedPlugins_.end()) {
        return false;
    }
    
#ifdef _WIN32
    FreeLibrary(static_cast<HMODULE>(it->second));
#else
    dlclose(it->second);
#endif
    
    loadedPlugins_.erase(it);
    return true;
}

bool PluginReloader::reloadPlugin(const std::string& name) {
    // Would need to store path to reload
    return false;
}

std::vector<std::string> PluginReloader::listLoadedPlugins() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, handle] : loadedPlugins_) {
        result.push_back(name);
    }
    return result;
}

bool PluginReloader::isPluginLoaded(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return loadedPlugins_.find(name) != loadedPlugins_.end();
}

void* PluginReloader::getPluginSymbol(const std::string& pluginName, const std::string& symbolName) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = loadedPlugins_.find(pluginName);
    if (it == loadedPlugins_.end()) {
        return nullptr;
    }
    
#ifdef _WIN32
    return GetProcAddress(static_cast<HMODULE>(it->second), symbolName.c_str());
#else
    return dlsym(it->second, symbolName.c_str());
#endif
}

void PluginReloader::scanForPlugins() {
    if (!std::filesystem::exists(pluginDirectory_)) {
        return;
    }
    
    for (const auto& entry : std::filesystem::directory_iterator(pluginDirectory_)) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
#ifdef _WIN32
            if (ext == ".dll") {
#else
            if (ext == ".so") {
#endif
                if (autoLoad_) {
                    loadPlugin(entry.path().string());
                }
            }
        }
    }
}

void PluginReloader::setAutoLoad(bool enabled) {
    autoLoad_ = enabled;
}

// ============================================================================
// ModelHotSwapper Implementation
// ============================================================================

ModelHotSwapper::ModelHotSwapper() = default;

bool ModelHotSwapper::reload() {
    // Reload all registered models
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [id, entry] : models_) {
        if (!entry.pendingPath.empty()) {
            swapModel(id, entry.pendingPath);
        }
    }
    
    return true;
}

std::string ModelHotSwapper::getVersion() const {
    return "1.0.0";
}

void ModelHotSwapper::registerModel(const std::string& modelId, const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ModelEntry entry;
    entry.path = path;
    models_[modelId] = entry;
}

void ModelHotSwapper::unregisterModel(const std::string& modelId) {
    std::lock_guard<std::mutex> lock(mutex_);
    models_.erase(modelId);
}

bool ModelHotSwapper::swapModel(const std::string& modelId, const std::string& newPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = models_.find(modelId);
    if (it == models_.end()) {
        return false;
    }
    
    // Would implement actual model hot-swap
    it->second.path = newPath;
    it->second.pendingPath.clear();
    it->second.loadTime = std::chrono::system_clock::now();
    
    return true;
}

bool ModelHotSwapper::preloadModel(const std::string& modelId, const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = models_.find(modelId);
    if (it == models_.end()) {
        return false;
    }
    
    it->second.pendingPath = path;
    return true;
}

bool ModelHotSwapper::activatePreloaded(const std::string& modelId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = models_.find(modelId);
    if (it == models_.end() || it->second.pendingPath.empty()) {
        return false;
    }
    
    return swapModel(modelId, it->second.pendingPath);
}

ModelHotSwapper::ModelStatus ModelHotSwapper::getModelStatus(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ModelStatus status;
    status.modelId = modelId;
    
    auto it = models_.find(modelId);
    if (it != models_.end()) {
        status.currentPath = it->second.path;
        status.pendingPath = it->second.pendingPath;
        status.isLoaded = it->second.isLoaded;
        status.hasPendingSwap = !it->second.pendingPath.empty();
    }
    
    return status;
}

std::vector<ModelHotSwapper::ModelStatus> ModelHotSwapper::getAllModelStatuses() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ModelStatus> result;
    for (const auto& [id, entry] : models_) {
        result.push_back(getModelStatus(id));
    }
    return result;
}

} // namespace Maintenance
} // namespace RawrXD
