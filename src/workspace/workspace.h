#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Workspace {

using json = nlohmann::json;

// File system watcher
struct FileChangeEvent {
    enum class Type {
        Created,
        Changed,
        Deleted,
        Renamed
    };
    
    Type type;
    std::filesystem::path path;
    std::filesystem::path oldPath; // For rename
};

class FileWatcher {
public:
    FileWatcher();
    ~FileWatcher();
    
    bool startWatching(const std::filesystem::path& path, bool recursive = true);
    void stopWatching(const std::filesystem::path& path);
    void stopAll();
    
    std::function<void(const FileChangeEvent&)> onFileChanged;
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Workspace folder (multi-root support)
struct WorkspaceFolder {
    std::string name;
    std::filesystem::path uri;
    int index;
    
    std::string toString() const { return uri.string(); }
};

// Text document
struct TextDocument {
    std::filesystem::path uri;
    std::string languageId;
    int version = 0;
    std::string content;
    bool isDirty = false;
    bool isUntitled = false;
    
    std::vector<std::string> getLines() const;
    std::string getLine(int line) const;
    int lineCount() const;
    void update(const std::string& newContent, int version);
};

// Configuration (settings.json equivalent)
class Configuration {
public:
    Configuration(const std::string& section = "");
    
    json get(const std::string& key, const json& defaultValue = nullptr) const;
    template<typename T>
    T get(const std::string& key, const T& defaultValue = T{}) const;
    
    void update(const std::string& key, const json& value);
    bool has(const std::string& key) const;
    
    std::vector<std::string> keys() const;
    
    void load(const std::filesystem::path& path);
    void save(const std::filesystem::path& path) const;
    
    std::function<void(const std::string& key)> onChange;

private:
    std::string section_;
    json data_;
};

// Workspace state (persists across sessions)
struct WorkspaceState {
    std::vector<std::filesystem::path> openFiles;
    std::filesystem::path activeFile;
    std::vector<int> editorLayout;
    json panelState;
    json viewState;
    
    void load(const std::filesystem::path& path);
    void save(const std::filesystem::path& path) const;
};

// Main Workspace class
class Workspace {
public:
    static Workspace& Instance();
    
    // Lifecycle
    bool initialize(const std::filesystem::path& workspaceFile = "");
    void shutdown();
    
    // Multi-root workspace
    void addFolder(const std::filesystem::path& path, const std::string& name = "");
    void removeFolder(const std::filesystem::path& path);
    std::vector<WorkspaceFolder> getFolders() const;
    std::filesystem::path resolvePath(const std::filesystem::path& relative) const;
    
    // File operations
    bool openFile(const std::filesystem::path& path);
    bool closeFile(const std::filesystem::path& path);
    bool saveFile(const std::filesystem::path& path);
    bool saveAll();
    
    std::shared_ptr<TextDocument> getDocument(const std::filesystem::path& path);
    std::vector<std::shared_ptr<TextDocument>> getOpenDocuments() const;
    
    // Search
    std::vector<std::filesystem::path> findFiles(const std::string& pattern, 
                                                   const std::filesystem::path& root = "") const;
    std::vector<std::filesystem::path> findText(const std::string& query,
                                                   const std::filesystem::path& root = "") const;
    
    // Configuration
    Configuration& getConfiguration(const std::string& section = "");
    void updateConfiguration(const std::string& section, const std::string& key, const json& value);
    
    // State persistence
    void saveState();
    void restoreState();
    
    // Git integration
    bool isGitRepository(const std::filesystem::path& path) const;
    std::filesystem::path getGitRoot(const std::filesystem::path& path) const;
    std::string getGitBranch(const std::filesystem::path& path) const;
    
    // Events
    std::function<void(const std::filesystem::path&)> onFileOpened;
    std::function<void(const std::filesystem::path&)> onFileClosed;
    std::function<void(const std::filesystem::path&)> onFileSaved;
    std::function<void(const FileChangeEvent&)> onFileChanged;
    std::function<void()> onConfigurationChanged;

private:
    Workspace() = default;
    ~Workspace() = default;
    
    std::vector<WorkspaceFolder> folders_;
    std::unordered_map<std::string, std::shared_ptr<TextDocument>> documents_;
    std::unordered_map<std::string, std::unique_ptr<Configuration>> configurations_;
    std::unique_ptr<FileWatcher> fileWatcher_;
    WorkspaceState state_;
    
    std::filesystem::path workspaceFile_;
    std::filesystem::path workspaceRoot_;
    std::filesystem::path stateFile_;
    
    void loadWorkspaceFile(const std::filesystem::path& path);
    void saveWorkspaceFile() const;
    void onFileSystemChanged(const FileChangeEvent& event);
    
    std::string normalizePath(const std::filesystem::path& path) const;
};

// Workspace file format (.code-workspace equivalent)
struct WorkspaceFile {
    std::vector<WorkspaceFolder> folders;
    json settings;
    json extensions;
    json launch;
    json tasks;
    
    void load(const std::filesystem::path& path);
    void save(const std::filesystem::path& path) const;
};

} // namespace Workspace
} // namespace RawrXD