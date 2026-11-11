// multi_root.cpp — Multi-Root Workspace Support
#include "workspace_manager.hpp"
#include <fstream>
#include <algorithm>

namespace RawrXD {
namespace Workspace {

// ============================================================================
// Multi-Root Workspace File (.code-workspace equivalent)
// ============================================================================
class MultiRootManager {
public:
    static MultiRootManager& Get();

    bool CreateWorkspaceFile(const std::filesystem::path& path, const std::vector<std::filesystem::path>& folders);
    bool AddFolderToFile(const std::filesystem::path& workspaceFile, const std::filesystem::path& folder);
    bool RemoveFolderFromFile(const std::filesystem::path& workspaceFile, const std::filesystem::path& folder);
    std::vector<std::filesystem::path> GetFoldersFromFile(const std::filesystem::path& workspaceFile);

    // Workspace file format detection
    bool IsWorkspaceFile(const std::filesystem::path& path) const;
    std::vector<std::filesystem::path> FindWorkspaceFiles(const std::filesystem::path& searchPath) const;

private:
    MultiRootManager() = default;
    static constexpr const char* WORKSPACE_EXTENSION = ".rawrxd-workspace";
};

MultiRootManager& MultiRootManager::Get() {
    static MultiRootManager instance;
    return instance;
}

bool MultiRootManager::CreateWorkspaceFile(const std::filesystem::path& path, const std::vector<std::filesystem::path>& folders) {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "{\n";
    file << "  \"version\": \"1.0\",\n";
    file << "  \"folders\": [\n";
    for (size_t i = 0; i < folders.size(); i++) {
        if (i > 0) file << ",\n";
        file << "    { \"path\": \"" << folders[i].string() << "\" }";
    }
    file << "\n  ]\n";
    file << "}\n";
    return true;
}

bool MultiRootManager::AddFolderToFile(const std::filesystem::path& workspaceFile, const std::filesystem::path& folder) {
    auto folders = GetFoldersFromFile(workspaceFile);
    auto absFolder = std::filesystem::absolute(folder);

    // Check if already exists
    for (const auto& f : folders) {
        if (std::filesystem::absolute(f) == absFolder) return true;
    }

    folders.push_back(folder);
    return CreateWorkspaceFile(workspaceFile, folders);
}

bool MultiRootManager::RemoveFolderFromFile(const std::filesystem::path& workspaceFile, const std::filesystem::path& folder) {
    auto folders = GetFoldersFromFile(workspaceFile);
    auto absFolder = std::filesystem::absolute(folder);

    folders.erase(
        std::remove_if(folders.begin(), folders.end(),
            [&](const auto& f) { return std::filesystem::absolute(f) == absFolder; }),
        folders.end()
    );

    return CreateWorkspaceFile(workspaceFile, folders);
}

std::vector<std::filesystem::path> MultiRootManager::GetFoldersFromFile(const std::filesystem::path& workspaceFile) {
    std::vector<std::filesystem::path> folders;
    if (!std::filesystem::exists(workspaceFile)) return folders;

    std::ifstream file(workspaceFile);
    if (!file.is_open()) return folders;

    std::string line;
    while (std::getline(file, line)) {
        auto pos = line.find("\"path\"");
        if (pos == std::string::npos) continue;
        auto colon = line.find(':', pos);
        if (colon == std::string::npos) continue;
        auto start = line.find('"', colon + 1);
        if (start == std::string::npos) continue;
        auto end = line.find('"', start + 1);
        if (end == std::string::npos) continue;
        folders.push_back(line.substr(start + 1, end - start - 1));
    }

    return folders;
}

bool MultiRootManager::IsWorkspaceFile(const std::filesystem::path& path) const {
    return path.extension() == WORKSPACE_EXTENSION;
}

std::vector<std::filesystem::path> MultiRootManager::FindWorkspaceFiles(const std::filesystem::path& searchPath) const {
    std::vector<std::filesystem::path> result;
    if (!std::filesystem::exists(searchPath)) return result;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(searchPath, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file() && entry.path().extension() == WORKSPACE_EXTENSION) {
            result.push_back(entry.path());
        }
    }

    return result;
}

} // namespace Workspace
} // namespace RawrXD
