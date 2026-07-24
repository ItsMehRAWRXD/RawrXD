// ============================================================================
// FileExplorerPanel.hpp - File Explorer Panel for Sovereign IDE
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <filesystem>

namespace fs = std::filesystem;

namespace Sovereign {

struct FileEntry {
    std::string name;
    std::string path;
    uint64_t size;
    uint64_t modified;
    bool isDirectory;
    bool isSymlink;
    std::string extension;
    std::string permissions;
};

struct FileExplorerConfig {
    std::string rootPath;
    bool showHidden = false;
    bool showExtensions = true;
    bool sortByName = true;
    bool directoriesFirst = true;
    std::vector<std::string> excludePatterns;
};

class FileExplorerPanel {
public:
    FileExplorerPanel();
    ~FileExplorerPanel();

    bool Initialize(const FileExplorerConfig& config);
    void Shutdown();

    void SetRoot(const std::string& path);
    std::string GetRoot() const { return config_.rootPath; }

    std::vector<FileEntry> ListDirectory(const std::string& path = "");
    std::vector<FileEntry> Search(const std::string& query);
    std::vector<FileEntry> GetRecentFiles(size_t count = 10);

    bool CreateFile(const std::string& path);
    bool CreateDirectory(const std::string& path);
    bool Delete(const std::string& path);
    bool Rename(const std::string& oldPath, const std::string& newPath);
    bool Copy(const std::string& src, const std::string& dst);
    bool Move(const std::string& src, const std::string& dst);

    void SetSelectionCallback(std::function<void(const std::string&)> callback);
    void SetContextMenuCallback(std::function<void(const std::string&, int x, int y)> callback);

    struct ExplorerStats {
        uint64_t totalFiles;
        uint64_t totalDirectories;
        uint64_t totalSize;
        uint64_t operations;
    };
    ExplorerStats GetStats() const { return stats_; }

private:
    FileExplorerConfig config_;
    ExplorerStats stats_;
    std::function<void(const std::string&)> selectionCallback_;
    std::function<void(const std::string&, int, int)> contextMenuCallback_;
    mutable std::mutex mutex_;
    
    bool IsExcluded(const std::string& path) const;
};

} // namespace Sovereign
