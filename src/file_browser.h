#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>

struct FileInfo {
    std::string name;
    std::string path;
    bool isDirectory;
    uint64_t size;
    bool isLoaded = false;  // For lazy loading - children loaded?
};

struct DirectoryNode {
    FileInfo info;
    std::vector<DirectoryNode> children;
    bool isExpanded = false;
    bool isLoading = false;
};

class FileBrowser {
public:
    FileBrowser();
    ~FileBrowser();

    void initialize();
    std::vector<FileInfo> listDirectory(const std::string& dirpath);
    std::vector<std::string> getDrives();
    
    // Lazy loading support
    bool expandDirectory(const std::string& dirpath);
    void collapseDirectory(const std::string& dirpath);
    std::vector<FileInfo> getChildren(const std::string& dirpath);
    bool isDirectoryLoaded(const std::string& dirpath) const;
    void refreshDirectory(const std::string& dirpath);
    void clearCache();

    // Callbacks
    std::function<void(const std::string&)> onFileSelected;
    std::function<void(const std::string&, const std::string&)> onError;
    std::function<void(const std::string&)> onDirectoryExpanded;

private:
    void logOperation(const std::string& level, const std::string& message);
    
    // Cache for lazy loading
    mutable std::mutex m_cacheMutex;
    std::unordered_map<std::string, std::vector<FileInfo>> m_directoryCache;
    std::unordered_map<std::string, bool> m_expandedDirs;
    
    static constexpr size_t MAX_CACHE_SIZE = 100;
    void pruneCacheIfNeeded();
};

