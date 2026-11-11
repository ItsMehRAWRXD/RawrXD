#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <mutex>
#include <filesystem>

namespace RawrXD {
namespace Workspace {

// File system watcher
class FileWatcher {
public:
    using ChangeCallback = std::function<void(const std::string& path, bool isDirectory)>;
    
    bool Initialize();
    bool Shutdown();
    
    bool WatchFolder(const std::string& path, bool recursive = true);
    bool UnwatchFolder(const std::string& path);
    
    void SetChangeCallback(ChangeCallback callback) { callback_ = callback; }
    
private:
    void WatcherThread();
    
    std::map<std::string, HANDLE> watchHandles_;
    std::mutex mutex_;
    ChangeCallback callback_;
    bool running_ = false;
    std::thread watcherThread_;
};

// Workspace folder (multi-root support)
struct WorkspaceFolder {
    std::string name;
    std::string uri;        // file:///path/to/folder
    std::string path;       // Actual filesystem path
    int index = 0;
};

// Text document in workspace
struct TextDocument {
    std::string uri;
    std::string path;
    std::string languageId;
    int version = 0;
    bool isDirty = false;
    bool isUntitled = false;
};

// Git status for files
enum class GitStatus {
    Unmodified,
    Modified,
    Added,
    Deleted,
    Renamed,
    Copied,
    Untracked,
    Ignored,
    Conflict
};

// File tree node
struct FileTreeNode {
    std::string name;
    std::string path;
    bool isDirectory = false;
    GitStatus gitStatus = GitStatus::Unmodified;
    std::vector<std::unique_ptr<FileTreeNode>> children;
    FileTreeNode* parent = nullptr;
};

// Main workspace manager
class WorkspaceManager {
public:
    static WorkspaceManager& Instance();
    
    // Lifecycle
    bool Initialize();
    bool Shutdown();
    
    // Multi-root workspace
    bool AddFolder(const std::string& path, const std::string& name = "");
    bool RemoveFolder(const std::string& name);
    bool RemoveFolder(int index);
    std::vector<WorkspaceFolder> GetFolders() const;
    
    // File operations
    std::vector<std::string> GetFiles(const std::string& pattern = "*");
    std::vector<std::string> GetDirectories(const std::string& path = "");
    bool FileExists(const std::string& path);
    bool CreateFile(const std::string& path);
    bool CreateDirectory(const std::string& path);
    bool DeleteFile(const std::string& path);
    bool RenameFile(const std::string& oldPath, const std::string& newPath);
    
    // Text documents
    bool OpenTextDocument(const std::string& path);
    bool CloseTextDocument(const std::string& uri);
    std::vector<TextDocument> GetTextDocuments() const;
    TextDocument* GetTextDocument(const std::string& uri);
    
    // File tree
    std::unique_ptr<FileTreeNode> BuildFileTree(const std::string& folderPath);
    void RefreshFileTree();
    
    // Git integration
    void UpdateGitStatus(const std::string& path, GitStatus status);
    GitStatus GetGitStatus(const std::string& path) const;
    
    // Configuration
    bool LoadWorkspaceConfiguration(const std::string& path);
    bool SaveWorkspaceConfiguration(const std::string& path);
    
    // Settings
    std::string GetSetting(const std::string& key, const std::string& defaultValue = "");
    void SetSetting(const std::string& key, const std::string& value);
    
    // Events
    using FileChangeCallback = std::function<void(const std::string& path, const std::string& changeType)>;
    void SetFileChangeCallback(FileChangeCallback callback) { fileChangeCallback_ = callback; }
    
private:
    WorkspaceManager() = default;
    ~WorkspaceManager() = default;
    
    std::vector<WorkspaceFolder> folders_;
    std::vector<TextDocument> textDocuments_;
    std::map<std::string, GitStatus> gitStatus_;
    std::map<std::string, std::string> settings_;
    
    std::unique_ptr<FileWatcher> fileWatcher_;
    FileChangeCallback fileChangeCallback_;
    
    mutable std::mutex mutex_;
    
    void OnFileChanged(const std::string& path, bool isDirectory);
    std::string MakeRelativePath(const std::string& path);
};

} // namespace Workspace
} // namespace RawrXD