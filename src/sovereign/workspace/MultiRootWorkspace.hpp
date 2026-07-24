// ============================================================================
// MultiRootWorkspace.hpp - Multi-Root Workspace Support
// ============================================================================

#pragma once
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct WorkspaceFolder {
    std::string path;
    std::string name;
    bool isActive;
    uint64_t addedAt;
    std::vector<std::string> extensions;
};

class MultiRootWorkspace {
public:
    MultiRootWorkspace();
    ~MultiRootWorkspace();

    bool AddFolder(const std::string& path);
    bool RemoveFolder(const std::string& path);
    bool SetActiveFolder(const std::string& path);
    std::string GetActiveFolder() const;
    std::vector<WorkspaceFolder> GetFolders() const;
    size_t GetFolderCount() const { return folders_.size(); }
    
    void SetGlobalConfig(const std::string& key, const std::string& value);
    std::string GetGlobalConfig(const std::string& key) const;
    
    bool Save(const std::string& path);
    bool Load(const std::string& path);

private:
    std::vector<WorkspaceFolder> folders_;
    std::string activeFolder_;
    std::unordered_map<std::string, std::string> globalConfig_;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
