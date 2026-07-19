#pragma once
#include <string>
#include <vector>
#include <map>
#include <functional>

namespace IDE {

// File entry in workspace
struct WorkspaceFile {
    std::string path;
    std::string name;
    std::string extension;
    size_t size;
    bool isDirectory;
    bool isModified;
    bool isOpen;
};

// Project configuration
struct ProjectConfig {
    std::string name;
    std::string rootPath;
    std::string buildCommand;
    std::string runCommand;
    std::vector<std::string> includePaths;
    std::vector<std::string> libraryPaths;
    std::map<std::string, std::string> defines;
};

// Workspace service - central project management
class WorkspaceService {
public:
    static void Init();
    static void Shutdown();
    
    // Project operations
    static bool OpenProject(const std::string& path);
    static void CloseProject();
    static bool IsProjectOpen();
    static const std::string& GetProjectRoot();
    static const std::string& GetProjectName();
    
    // File operations
    static void RefreshFileTree();
    static const std::vector<WorkspaceFile>& GetFiles();
    static std::vector<WorkspaceFile> GetFilesInDirectory(const std::string& dir);
    static bool FileExists(const std::string& path);
    static std::string ReadFile(const std::string& path);
    static bool WriteFile(const std::string& path, const std::string& content);
    
    // Recent projects
    static void AddRecentProject(const std::string& path);
    static std::vector<std::string> GetRecentProjects();
    static void ClearRecentProjects();
    
    // File watching
    static void StartFileWatcher();
    static void StopFileWatcher();
    static void SetFileChangeCallback(std::function<void(const std::string&)> callback);
    
    // Build configuration
    static ProjectConfig& GetConfig();
    static void SaveConfig();
    static void LoadConfig();
    
private:
    static bool s_initialized;
    static std::string s_projectRoot;
    static std::string s_projectName;
    static std::vector<WorkspaceFile> s_files;
    static std::vector<std::string> s_recentProjects;
    static ProjectConfig s_config;
    static bool s_fileWatcherRunning;
    static std::function<void(const std::string&)> s_fileChangeCallback;
    
    static void ScanDirectory(const std::string& path, std::vector<WorkspaceFile>& files);
    static void LoadRecentProjects();
    static void SaveRecentProjects();
};

} // namespace IDE
