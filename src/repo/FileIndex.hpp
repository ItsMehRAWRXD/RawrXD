// ============================================================================
// FileIndex.hpp - Incremental Filesystem Tracking
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>

namespace RawrXD {
namespace IDE {

struct FileEntry {
    std::string path;
    std::string hash;
    uint64_t lastModified;
    size_t size;
    std::vector<std::string> symbols;
    std::vector<std::string> includes;
};

class FileIndex {
public:
    FileIndex();
    ~FileIndex();

    bool Initialize(const std::string& rootPath);
    void Shutdown();

    void IndexFile(const std::string& filePath);
    void IndexDirectory(const std::string& dirPath);
    void RemoveFile(const std::string& filePath);

    std::vector<FileEntry> GetFiles() const;
    FileEntry* GetFile(const std::string& filePath);
    std::vector<std::string> GetModifiedFiles() const;
    std::vector<std::string> GetSourceFiles() const;
    std::vector<std::string> GetHeaderFiles() const;

    void StartWatching();
    void StopWatching();
    bool IsWatching() const;

    using ChangeCallback = std::function<void(const std::string& filePath)>;
    void SetChangeCallback(ChangeCallback cb);

    size_t GetFileCount() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace IDE
} // namespace RawrXD
