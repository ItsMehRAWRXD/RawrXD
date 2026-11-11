// ============================================================================
// ExtensionHost.cpp - Extension Host Implementation
// ============================================================================

#include "ExtensionHost.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

namespace Sovereign {

ExtensionHost::ExtensionHost() = default;
ExtensionHost::~ExtensionHost() = default;

bool ExtensionHost::Install(const ExtensionManifest& manifest) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!ValidateManifest(manifest)) return false;
    if (extensions_.find(manifest.id) != extensions_.end()) return false;
    
    ExtensionInfo info;
    info.manifest = manifest;
    info.state = ExtensionState::INSTALLED;
    info.loadTime = 0;
    info.memoryUsage = 0;
    
    extensions_[manifest.id] = info;
    return true;
}

bool ExtensionHost::Uninstall(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = extensions_.find(id);
    if (it == extensions_.end()) return false;
    
    if (it->second.state == ExtensionState::ACTIVE) {
        Unload(id);
    }
    
    extensions_.erase(it);
    return true;
}

bool ExtensionHost::Enable(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = extensions_.find(id);
    if (it == extensions_.end()) return false;
    
    it->second.state = ExtensionState::ACTIVE;
    return true;
}

bool ExtensionHost::Disable(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = extensions_.find(id);
    if (it == extensions_.end()) return false;
    
    it->second.state = ExtensionState::DISABLED;
    return true;
}

bool ExtensionHost::Load(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = extensions_.find(id);
    if (it == extensions_.end()) return false;
    
    it->second.state = ExtensionState::LOADING;
    
    // In production, this would load a DLL/script
    // For now, mark as active
    it->second.state = ExtensionState::ACTIVE;
    it->second.loadTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    return true;
}

bool ExtensionHost::Unload(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = extensions_.find(id);
    if (it == extensions_.end()) return false;
    
    it->second.state = ExtensionState::INSTALLED;
    return true;
}

std::vector<ExtensionInfo> ExtensionHost::ListExtensions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ExtensionInfo> result;
    for (const auto& [id, info] : extensions_) {
        result.push_back(info);
    }
    return result;
}

ExtensionInfo ExtensionHost::GetExtensionInfo(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = extensions_.find(id);
    if (it != extensions_.end()) {
        return it->second;
    }
    return {};
}

bool ExtensionHost::IsInstalled(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return extensions_.find(id) != extensions_.end();
}

bool ExtensionHost::IsActive(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = extensions_.find(id);
    return it != extensions_.end() && it->second.state == ExtensionState::ACTIVE;
}

ExtensionAPI ExtensionHost::GetAPI(const std::string& id) {
    return api_;
}

void ExtensionHost::SetAPIImplementation(const ExtensionAPI& api) {
    api_ = api;
}

void ExtensionHost::EmitEvent(const std::string& event, const std::string& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = eventHandlers_.find(event);
    if (it != eventHandlers_.end()) {
        for (const auto& handler : it->second) {
            handler(data);
        }
    }
}

void ExtensionHost::Subscribe(const std::string& event, std::function<void(const std::string&)> handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    eventHandlers_[event].push_back(handler);
}

bool ExtensionHost::ValidateManifest(const ExtensionManifest& manifest) const {
    if (manifest.id.empty()) return false;
    if (manifest.name.empty()) return false;
    if (manifest.version.empty()) return false;
    if (manifest.entryPoint.empty()) return false;
    return true;
}

void ExtensionHost::SaveExtensions(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ofstream file(path);
    if (!file) return;
    
    for (const auto& [id, info] : extensions_) {
        file << id << "|"
             << info.manifest.name << "|"
             << info.manifest.version << "|"
             << info.manifest.author << "|"
             << static_cast<int>(info.state) << "\n";
    }
}

void ExtensionHost::LoadExtensions(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ifstream file(path);
    if (!file) return;
    
    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string id, name, version, author, stateStr;
        
        std::getline(ss, id, '|');
        std::getline(ss, name, '|');
        std::getline(ss, version, '|');
        std::getline(ss, author, '|');
        std::getline(ss, stateStr, '|');
        
        ExtensionManifest manifest;
        manifest.id = id;
        manifest.name = name;
        manifest.version = version;
        manifest.author = author;
        
        ExtensionInfo info;
        info.manifest = manifest;
        info.state = static_cast<ExtensionState>(std::stoi(stateStr));
        
        extensions_[id] = info;
    }
}

size_t ExtensionHost::GetActiveExtensionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::count_if(extensions_.begin(), extensions_.end(),
        [](const auto& pair) { return pair.second.state == ExtensionState::ACTIVE; });
}

size_t ExtensionHost::GetTotalExtensionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return extensions_.size();
}

} // namespace Sovereign
