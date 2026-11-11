// workspace_manager.hpp — Workspace Intelligence Core
// Multi-root workspace support, project graph, file watching, settings inheritance
// Pure C++20 / Win32 — Zero Qt Dependencies
#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <filesystem>
#include <optional>
#include <chrono>

namespace RawrXD {
namespace Workspace {

// ============================================================================
// Workspace Folder
// ============================================================================
struct WorkspaceFolder {
    std::filesystem::path path;
    std::string name;
    std::string rootUri;
    int index = 0;
    bool isTrusted = true;
};

// ============================================================================
// File Change Types
// ============================================================================
enum class FileChangeType {
    Created,
    Modified,
    Deleted,
    Renamed
};

// ============================================================================
// File Watch Event
// ============================================================================
struct FileWatchEvent {
    std::filesystem::path path;
    FileChangeType changeType;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Project Info
// ============================================================================
struct ProjectInfo {
    std::string name;
    std::string type;           // "cmake", "msbuild", "npm", "python", etc.
    std::filesystem::path rootPath;
    std::vector<std::filesystem::path> buildFiles;
    std::vector<std::string> languages;
    std::vector<std::string> dependencies;
    std::map<std::string, std::string> metadata;
};

// ============================================================================
// Workspace Settings
// ============================================================================
struct WorkspaceSettings {
    std::map<std::string, std::string> values;
    std::filesystem::path settingsPath;
    int priority = 0;  // Higher = overrides lower
};

// ============================================================================
// Workspace Manager
// ============================================================================
class WorkspaceManager {
public:
    WorkspaceManager();
    ~WorkspaceManager();

    // Initialize workspace manager
    bool Initialize();

    // Shutdown
    void Shutdown();

    // ========================================================================
    // Multi-Root Workspace
    // ========================================================================
    bool AddFolder(const std::filesystem::path& path);
    bool RemoveFolder(int index);
    bool RemoveFolder(const std::filesystem::path& path);
    std::vector<WorkspaceFolder> GetFolders() const;
    WorkspaceFolder* GetFolder(int index);
    bool HasFolder(const std::filesystem::path& path) const;
    size_t GetFolderCount() const { return m_folders.size(); }

    // Save/load workspace file (.code-workspace equivalent)
    bool SaveWorkspaceFile(const std::filesystem::path& path);
    bool LoadWorkspaceFile(const std::filesystem::path& path);

    // ========================================================================
    // File Watching
    // ========================================================================
    bool StartWatching(const std::filesystem::path& path);
    bool StopWatching(const std::filesystem::path& path);
    void StopAllWatching();

    using FileChangeCallback = std::function<void(const FileWatchEvent& event)>;
    void SetFileChangeCallback(FileChangeCallback callback) { m_fileChangeCallback = callback; }

    // ========================================================================
    // Project Indexing
    // ========================================================================
    bool IndexProject(const std::filesystem::path& path);
    bool IndexAllProjects();
    std::vector<ProjectInfo> GetProjects() const;
    ProjectInfo* GetProject(const std::filesystem::path& path);
    bool IsProjectIndexed(const std::filesystem::path& path) const;

    // ========================================================================
    // Workspace Graph
    // ========================================================================
    struct WorkspaceGraph {
        std::vector<std::filesystem::path> nodes;
        std::map<std::filesystem::path, std::vector<std::filesystem::path>> edges; // dependency edges
    };
    WorkspaceGraph BuildGraph() const;
    std::vector<std::filesystem::path> GetDependencyOrder() const;

    // ========================================================================
    // Settings Inheritance
    // ========================================================================
    void SetSetting(const std::string& key, const std::string& value, int priority = 0);
    std::string GetSetting(const std::string& key) const;
    bool HasSetting(const std::string& key) const;
    void RemoveSetting(const std::string& key);
    std::map<std::string, std::string> GetAllSettings() const;

    // Load settings from file
    bool LoadSettingsFile(const std::filesystem::path& path, int priority = 0);
    bool SaveSettingsFile(const std::filesystem::path& path) const;

    // ========================================================================
    // Workspace Trust
    // ========================================================================
    enum class TrustLevel { Unknown, Trusted, Untrusted };
    TrustLevel GetTrustLevel(const std::filesystem::path& path) const;
    void SetTrustLevel(const std::filesystem::path& path, TrustLevel level);
    bool IsWorkspaceTrusted() const;

    // ========================================================================
    // Utility
    // ========================================================================
    std::filesystem::path GetRootPath() const;
    std::filesystem::path GetWorkspaceStoragePath() const;
    void SetWorkspaceStoragePath(const std::filesystem::path& path);

    // Events
    using WorkspaceEventCallback = std::function<void(const std::string& event, const std::filesystem::path& path)>;
    void OnFolderAdded(WorkspaceEventCallback callback) { m_onFolderAdded = callback; }
    void OnFolderRemoved(WorkspaceEventCallback callback) { m_onFolderRemoved = callback; }
    void OnProjectIndexed(WorkspaceEventCallback callback) { m_onProjectIndexed = callback; }

private:
    void ScanForProjects(const std::filesystem::path& path);
    void WatchLoop();
    bool DetectProjectType(const std::filesystem::path& path, ProjectInfo& info);

    std::vector<WorkspaceFolder> m_folders;
    std::vector<ProjectInfo> m_projects;
    std::map<std::string, std::string> m_settings;
    std::vector<WorkspaceSettings> m_settingsLayers;
    std::map<std::filesystem::path, TrustLevel> m_trustLevels;

    // File watching
    std::unique_ptr<std::thread> m_watchThread;
    std::atomic<bool> m_watching{false};
    std::map<std::filesystem::path, std::filesystem::file_time_type> m_watchedFiles;
    FileChangeCallback m_fileChangeCallback;

    // Events
    WorkspaceEventCallback m_onFolderAdded;
    WorkspaceEventCallback m_onFolderRemoved;
    WorkspaceEventCallback m_onProjectIndexed;

    mutable std::mutex m_mutex;
    std::filesystem::path m_storagePath;
    bool m_initialized = false;
};

} // namespace Workspace
} // namespace RawrXD
