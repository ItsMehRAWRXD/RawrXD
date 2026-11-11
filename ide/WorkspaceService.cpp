#include "ide/WorkspaceService.hpp"
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <json.hpp>

namespace IDE {

bool WorkspaceService::s_initialized = false;
std::string WorkspaceService::s_projectRoot;
std::string WorkspaceService::s_projectName;
std::vector<WorkspaceFile> WorkspaceService::s_files;
std::vector<std::string> WorkspaceService::s_recentProjects;
ProjectConfig WorkspaceService::s_config;
bool WorkspaceService::s_fileWatcherRunning = false;
std::function<void(const std::string&)> WorkspaceService::s_fileChangeCallback;

void WorkspaceService::Init() {
    if (s_initialized) return;
    
    LoadRecentProjects();
    s_initialized = true;
}

void WorkspaceService::Shutdown() {
    if (!s_initialized) return;
    
    StopFileWatcher();
    SaveRecentProjects();
    s_initialized = false;
}

bool WorkspaceService::OpenProject(const std::string& path) {
    // Check if path exists
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    
    s_projectRoot = path;
    
    // Extract project name from path
    size_t lastSlash = path.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        s_projectName = path.substr(lastSlash + 1);
    } else {
        s_projectName = path;
    }
    
    // Load or create config
    LoadConfig();
    
    // Scan files
    RefreshFileTree();
    
    // Add to recent
    AddRecentProject(path);
    
    // Start watching
    StartFileWatcher();
    
    return true;
}

void WorkspaceService::CloseProject() {
    StopFileWatcher();
    SaveConfig();
    
    s_projectRoot.clear();
    s_projectName.clear();
    s_files.clear();
}

bool WorkspaceService::IsProjectOpen() {
    return !s_projectRoot.empty();
}

const std::string& WorkspaceService::GetProjectRoot() {
    return s_projectRoot;
}

const std::string& WorkspaceService::GetProjectName() {
    return s_projectName;
}

void WorkspaceService::RefreshFileTree() {
    s_files.clear();
    if (!s_projectRoot.empty()) {
        ScanDirectory(s_projectRoot, s_files);
    }
}

const std::vector<WorkspaceFile>& WorkspaceService::GetFiles() {
    return s_files;
}

std::vector<WorkspaceFile> WorkspaceService::GetFilesInDirectory(const std::string& dir) {
    std::vector<WorkspaceFile> result;
    for (const auto& file : s_files) {
        size_t lastSlash = file.path.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            std::string fileDir = file.path.substr(0, lastSlash);
            if (fileDir == dir) {
                result.push_back(file);
            }
        }
    }
    return result;
}

bool WorkspaceService::FileExists(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

std::string WorkspaceService::ReadFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

bool WorkspaceService::WriteFile(const std::string& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    
    file << content;
    return file.good();
}

void WorkspaceService::AddRecentProject(const std::string& path) {
    // Remove if already exists
    auto it = std::find(s_recentProjects.begin(), s_recentProjects.end(), path);
    if (it != s_recentProjects.end()) {
        s_recentProjects.erase(it);
    }
    
    // Add to front
    s_recentProjects.insert(s_recentProjects.begin(), path);
    
    // Keep only last 10
    if (s_recentProjects.size() > 10) {
        s_recentProjects.resize(10);
    }
    
    SaveRecentProjects();
}

std::vector<std::string> WorkspaceService::GetRecentProjects() {
    return s_recentProjects;
}

void WorkspaceService::ClearRecentProjects() {
    s_recentProjects.clear();
    SaveRecentProjects();
}

void WorkspaceService::StartFileWatcher() {
    s_fileWatcherRunning = true;
    // TODO: Implement actual file watcher thread
}

void WorkspaceService::StopFileWatcher() {
    s_fileWatcherRunning = false;
}

void WorkspaceService::SetFileChangeCallback(std::function<void(const std::string&)> callback) {
    s_fileChangeCallback = callback;
}

ProjectConfig& WorkspaceService::GetConfig() {
    return s_config;
}

void WorkspaceService::SaveConfig() {
    if (!IsProjectOpen()) return;
    
    std::string configPath = s_projectRoot + "\\.rawrxd\\project.json";
    CreateDirectoryA((s_projectRoot + "\\.rawrxd").c_str(), NULL);
    
    nlohmann::json j;
    j["name"] = s_config.name;
    j["buildCommand"] = s_config.buildCommand;
    j["runCommand"] = s_config.runCommand;
    j["includePaths"] = s_config.includePaths;
    j["libraryPaths"] = s_config.libraryPaths;
    j["defines"] = s_config.defines;
    
    std::ofstream file(configPath);
    if (file) {
        file << j.dump(4);
    }
}

void WorkspaceService::LoadConfig() {
    s_config = ProjectConfig{};
    s_config.name = s_projectName;
    s_config.rootPath = s_projectRoot;
    
    if (!IsProjectOpen()) return;
    
    std::string configPath = s_projectRoot + "\\.rawrxd\\project.json";
    std::ifstream file(configPath);
    if (!file) return;
    
    try {
        nlohmann::json j;
        file >> j;
        
        if (j.contains("name")) s_config.name = j["name"];
        if (j.contains("buildCommand")) s_config.buildCommand = j["buildCommand"];
        if (j.contains("runCommand")) s_config.runCommand = j["runCommand"];
        if (j.contains("includePaths")) s_config.includePaths = j["includePaths"].get<std::vector<std::string>>();
        if (j.contains("libraryPaths")) s_config.libraryPaths = j["libraryPaths"].get<std::vector<std::string>>();
        if (j.contains("defines")) {
            for (auto& [key, value] : j["defines"].items()) {
                s_config.defines[key] = value.get<std::string>();
            }
        }
    } catch (...) {
        // Use defaults
    }
}

void WorkspaceService::ScanDirectory(const std::string& path, std::vector<WorkspaceFile>& files) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA((path + "\\*").c_str(), &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) return;
    
    do {
        std::string name = findData.cFileName;
        if (name == "." || name == "..") continue;
        
        WorkspaceFile file;
        file.path = path + "\\" + name;
        file.name = name;
        file.isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        file.isModified = false;
        file.isOpen = false;
        
        // Get extension
        size_t dotPos = name.find_last_of('.');
        if (dotPos != std::string::npos) {
            file.extension = name.substr(dotPos + 1);
        }
        
        // Get size
        LARGE_INTEGER size;
        size.LowPart = findData.nFileSizeLow;
        size.HighPart = findData.nFileSizeHigh;
        file.size = size.QuadPart;
        
        files.push_back(file);
        
        // Recurse into directories
        if (file.isDirectory) {
            ScanDirectory(file.path, files);
        }
    } while (FindNextFileA(hFind, &findData));
    
    FindClose(hFind);
}

void WorkspaceService::LoadRecentProjects() {
    char appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
        std::string recentPath = std::string(appDataPath) + "\\RawrXD\\recent_projects.json";
        std::ifstream file(recentPath);
        if (file) {
            try {
                nlohmann::json j;
                file >> j;
                s_recentProjects = j.get<std::vector<std::string>>();
            } catch (...) {}
        }
    }
}

void WorkspaceService::SaveRecentProjects() {
    char appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
        CreateDirectoryA((std::string(appDataPath) + "\\RawrXD").c_str(), NULL);
        std::string recentPath = std::string(appDataPath) + "\\RawrXD\\recent_projects.json";
        
        std::ofstream file(recentPath);
        if (file) {
            nlohmann::json j = s_recentProjects;
            file << j.dump(4);
        }
    }
}

} // namespace IDE
