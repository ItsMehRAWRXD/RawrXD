// ============================================================================
// MultiRootWorkspace.cpp - Multi-Root Workspace Implementation
// ============================================================================

#include "MultiRootWorkspace.hpp"
#include <fstream>
#include <algorithm>
#include <iostream>

namespace Sovereign {

MultiRootWorkspace::MultiRootWorkspace() = default;
MultiRootWorkspace::~MultiRootWorkspace() = default;

bool MultiRootWorkspace::AddFolder(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check for duplicates
    for (const auto& f : folders_) {
        if (f.path == path) return false;
    }
    
    WorkspaceFolder folder;
    folder.path = path;
    folder.name = path.substr(path.find_last_of("/\\") + 1);
    folder.isActive = folders_.empty();
    folder.addedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    folders_.push_back(folder);
    if (activeFolder_.empty()) activeFolder_ = path;
    return true;
}

bool MultiRootWorkspace::RemoveFolder(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::remove_if(folders_.begin(), folders_.end(),
        [&path](const WorkspaceFolder& f) { return f.path == path; });
    
    if (it == folders_.end()) return false;
    folders_.erase(it, folders_.end());
    
    if (activeFolder_ == path) {
        activeFolder_ = folders_.empty() ? "" : folders_[0].path;
    }
    return true;
}

bool MultiRootWorkspace::SetActiveFolder(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& f : folders_) {
        f.isActive = (f.path == path);
    }
    activeFolder_ = path;
    return true;
}

std::string MultiRootWorkspace::GetActiveFolder() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return activeFolder_;
}

std::vector<WorkspaceFolder> MultiRootWorkspace::GetFolders() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return folders_;
}

void MultiRootWorkspace::SetGlobalConfig(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    globalConfig_[key] = value;
}

std::string MultiRootWorkspace::GetGlobalConfig(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = globalConfig_.find(key);
    return it != globalConfig_.end() ? it->second : "";
}

bool MultiRootWorkspace::Save(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ofstream file(path);
    if (!file) return false;
    
    for (const auto& f : folders_) {
        file << f.path << "|" << f.name << "|" << (f.isActive ? "1" : "0") << "\n";
    }
    return true;
}

bool MultiRootWorkspace::Load(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ifstream file(path);
    if (!file) return false;
    
    folders_.clear();
    std::string line;
    while (std::getline(file, line)) {
        auto pipe1 = line.find('|');
        if (pipe1 == std::string::npos) continue;
        auto pipe2 = line.find('|', pipe1 + 1);
        if (pipe2 == std::string::npos) continue;
        
        WorkspaceFolder folder;
        folder.path = line.substr(0, pipe1);
        folder.name = line.substr(pipe1 + 1, pipe2 - pipe1 - 1);
        folder.isActive = line.substr(pipe2 + 1) == "1";
        folders_.push_back(folder);
    }
    return true;
}

} // namespace Sovereign
