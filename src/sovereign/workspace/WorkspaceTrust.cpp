// ============================================================================
// WorkspaceTrust.cpp - Workspace Trust Model Implementation
// ============================================================================

#include "WorkspaceTrust.hpp"
#include <algorithm>
#include <iostream>

namespace Sovereign {

WorkspaceTrust::WorkspaceTrust() = default;
WorkspaceTrust::~WorkspaceTrust() = default;

void WorkspaceTrust::SetTrust(const std::string& path, TrustLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    WorkspaceTrustConfig config;
    config.path = path;
    config.level = level;
    
    switch (level) {
        case TrustLevel::FULL:
            config.allowExecution = true;
            config.allowFileWrite = true;
            config.allowNetwork = true;
            config.allowExtensions = true;
            break;
        case TrustLevel::TRUSTED:
            config.allowExecution = true;
            config.allowFileWrite = true;
            config.allowNetwork = false;
            config.allowExtensions = true;
            break;
        case TrustLevel::PARTIAL:
            config.allowExecution = false;
            config.allowFileWrite = true;
            config.allowNetwork = false;
            config.allowExtensions = false;
            break;
        default:
            config.allowExecution = false;
            config.allowFileWrite = false;
            config.allowNetwork = false;
            config.allowExtensions = false;
            break;
    }
    
    trustConfigs_[path] = config;
}

TrustLevel WorkspaceTrust::GetTrust(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = trustConfigs_.find(path);
    if (it != trustConfigs_.end()) return it->second.level;
    return defaultTrust_;
}

bool WorkspaceTrust::IsOperationAllowed(const std::string& path, const std::string& operation) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = trustConfigs_.find(path);
    if (it == trustConfigs_.end()) return false;
    
    const auto& config = it->second;
    if (operation == "execute") return config.allowExecution;
    if (operation == "write") return config.allowFileWrite;
    if (operation == "network") return config.allowNetwork;
    if (operation == "extension") return config.allowExtensions;
    return true;
}

void WorkspaceTrust::AddRestrictedPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (std::find(restrictedPaths_.begin(), restrictedPaths_.end(), path) == restrictedPaths_.end()) {
        restrictedPaths_.push_back(path);
    }
}

void WorkspaceTrust::RemoveRestrictedPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    restrictedPaths_.erase(std::remove(restrictedPaths_.begin(), restrictedPaths_.end(), path), restrictedPaths_.end());
}

std::vector<std::string> WorkspaceTrust::GetRestrictedPaths() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return restrictedPaths_;
}

} // namespace Sovereign
