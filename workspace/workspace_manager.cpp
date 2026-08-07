// workspace_manager.cpp — Workspace Intelligence Implementation
#include "workspace_manager.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <thread>
#include <chrono>

namespace RawrXD {
namespace Workspace {

WorkspaceManager::WorkspaceManager() = default;
WorkspaceManager::~WorkspaceManager() { Shutdown(); }

bool WorkspaceManager::Initialize() {
    m_initialized = true;
    return true;
}

void WorkspaceManager::Shutdown() {
    StopAllWatching();
    m_folders.clear();
    m_projects.clear();
    m_initialized = false;
}

// ============================================================================
// Multi-Root Workspace
// ============================================================================
bool WorkspaceManager::AddFolder(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) return false;
    if (HasFolder(path)) return false;

    std::lock_guard<std::mutex> lock(m_mutex);

    WorkspaceFolder folder;
    folder.path = std::filesystem::absolute(path);
    folder.name = path.filename().string();
    folder.index = static_cast<int>(m_folders.size());
    folder.isTrusted = true;
    m_folders.push_back(folder);

    // Start watching the folder
    StartWatching(folder.path);

    // Index projects in the folder
    ScanForProjects(folder.path);

    if (m_onFolderAdded) {
        m_onFolderAdded("added", folder.path);
    }

    return true;
}

bool WorkspaceManager::RemoveFolder(int index) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (index < 0 || index >= static_cast<int>(m_folders.size())) return false;

    auto path = m_folders[index].path;
    StopWatching(path);
    m_folders.erase(m_folders.begin() + index);

    // Re-index
    for (size_t i = 0; i < m_folders.size(); i++) {
        m_folders[i].index = static_cast<int>(i);
    }

    if (m_onFolderRemoved) {
        m_onFolderRemoved("removed", path);
    }

    return true;
}

bool WorkspaceManager::RemoveFolder(const std::filesystem::path& path) {
    auto absPath = std::filesystem::absolute(path);
    for (size_t i = 0; i < m_folders.size(); i++) {
        if (m_folders[i].path == absPath) {
            return RemoveFolder(static_cast<int>(i));
        }
    }
    return false;
}

std::vector<WorkspaceFolder> WorkspaceManager::GetFolders() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_folders;
}

WorkspaceFolder* WorkspaceManager::GetFolder(int index) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (index < 0 || index >= static_cast<int>(m_folders.size())) return nullptr;
    return &m_folders[index];
}

bool WorkspaceManager::HasFolder(const std::filesystem::path& path) const {
    auto absPath = std::filesystem::absolute(path);
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& folder : m_folders) {
        if (folder.path == absPath) return true;
    }
    return false;
}

bool WorkspaceManager::SaveWorkspaceFile(const std::filesystem::path& path) {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "{\n";
    file << "  \"folders\": [\n";
    for (size_t i = 0; i < m_folders.size(); i++) {
        if (i > 0) file << ",\n";
        file << "    { \"path\": \"" << m_folders[i].path.string() << "\" }";
    }
    file << "\n  ],\n";
    file << "  \"settings\": {\n";
    bool first = true;
    for (const auto& [key, value] : m_settings) {
        if (!first) file << ",\n";
        first = false;
        file << "    \"" << key << "\": \"" << value << "\"";
    }
    file << "\n  }\n";
    file << "}\n";
    return true;
}

bool WorkspaceManager::LoadWorkspaceFile(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) return false;

    std::ifstream file(path);
    if (!file.is_open()) return false;

    // Simple JSON parsing for workspace file
    std::string line;
    while (std::getline(file, line)) {
        auto parseStr = [](const std::string& l, const std::string& key) -> std::string {
            auto pos = l.find("\"" + key + "\"");
            if (pos == std::string::npos) return {};
            auto colon = l.find(':', pos);
            if (colon == std::string::npos) return {};
            auto start = l.find('"', colon + 1);
            if (start == std::string::npos) return {};
            auto end = l.find('"', start + 1);
            if (end == std::string::npos) return {};
            return l.substr(start + 1, end - start - 1);
        };

        if (line.find("\"path\"") != std::string::npos) {
            auto folderPath = parseStr(line, "path");
            if (!folderPath.empty()) {
                AddFolder(folderPath);
            }
        }
    }

    return true;
}

// ============================================================================
// File Watching
// ============================================================================
bool WorkspaceManager::StartWatching(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) return false;

    // Initialize watched files
    for (const auto& entry : std::filesystem::recursive_directory_iterator(path, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            m_watchedFiles[entry.path()] = std::filesystem::last_write_time(entry.path());
        }
    }

    // Start watch thread if not running
    if (!m_watching) {
        m_watching = true;
        m_watchThread = std::make_unique<std::thread>(&WorkspaceManager::WatchLoop, this);
    }

    return true;
}

bool WorkspaceManager::StopWatching(const std::filesystem::path& path) {
    // Remove path from watched files
    auto absPath = std::filesystem::absolute(path);
    for (auto it = m_watchedFiles.begin(); it != m_watchedFiles.end(); ) {
        if (it->first.string().find(absPath.string()) == 0) {
            it = m_watchedFiles.erase(it);
        } else {
            ++it;
        }
    }
    return true;
}

void WorkspaceManager::StopAllWatching() {
    m_watching = false;
    if (m_watchThread && m_watchThread->joinable()) {
        m_watchThread->join();
    }
    m_watchThread.reset();
    m_watchedFiles.clear();
}

void WorkspaceManager::WatchLoop() {
    while (m_watching) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        std::lock_guard<std::mutex> lock(m_mutex);

        for (auto it = m_watchedFiles.begin(); it != m_watchedFiles.end(); ) {
            const auto& path = it->first;
            auto oldTime = it->second;

            if (!std::filesystem::exists(path)) {
                // File was deleted
                FileWatchEvent event;
                event.path = path;
                event.changeType = FileChangeType::Deleted;
                event.timestamp = std::chrono::system_clock::now();
                if (m_fileChangeCallback) m_fileChangeCallback(event);
                it = m_watchedFiles.erase(it);
                continue;
            }

            auto newTime = std::filesystem::last_write_time(path);
            if (newTime != oldTime) {
                it->second = newTime;
                FileWatchEvent event;
                event.path = path;
                event.changeType = FileChangeType::Modified;
                event.timestamp = std::chrono::system_clock::now();
                if (m_fileChangeCallback) m_fileChangeCallback(event);
            }

            ++it;
        }
    }
}

// ============================================================================
// Project Indexing
// ============================================================================
bool WorkspaceManager::IndexProject(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) return false;

    ProjectInfo info;
    if (!DetectProjectType(path, info)) return false;

    std::lock_guard<std::mutex> lock(m_mutex);

    // Update or add
    for (auto& p : m_projects) {
        if (p.rootPath == info.rootPath) {
            p = info;
            return true;
        }
    }
    m_projects.push_back(info);

    if (m_onProjectIndexed) {
        m_onProjectIndexed("indexed", info.rootPath);
    }

    return true;
}

bool WorkspaceManager::IndexAllProjects() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_projects.clear();
    for (const auto& folder : m_folders) {
        ScanForProjects(folder.path);
    }
    return true;
}

std::vector<ProjectInfo> WorkspaceManager::GetProjects() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_projects;
}

ProjectInfo* WorkspaceManager::GetProject(const std::filesystem::path& path) {
    auto absPath = std::filesystem::absolute(path);
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& p : m_projects) {
        if (p.rootPath == absPath) return &p;
    }
    return nullptr;
}

bool WorkspaceManager::IsProjectIndexed(const std::filesystem::path& path) const {
    auto absPath = std::filesystem::absolute(path);
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& p : m_projects) {
        if (p.rootPath == absPath) return true;
    }
    return false;
}

void WorkspaceManager::ScanForProjects(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) return;

    // Check root
    ProjectInfo rootInfo;
    if (DetectProjectType(path, rootInfo)) {
        m_projects.push_back(rootInfo);
    }

    // Check subdirectories (one level deep)
    try {
        for (const auto& entry : std::filesystem::directory_iterator(path)) {
            if (entry.is_directory()) {
                ProjectInfo subInfo;
                if (DetectProjectType(entry.path(), subInfo)) {
                    m_projects.push_back(subInfo);
                }
            }
        }
    } catch (...) {
        // Permission denied, skip
    }
}

bool WorkspaceManager::DetectProjectType(const std::filesystem::path& path, ProjectInfo& info) {
    info.rootPath = std::filesystem::absolute(path);
    info.name = path.filename().string();

    // Check for CMake
    if (std::filesystem::exists(path / "CMakeLists.txt")) {
        info.type = "cmake";
        info.buildFiles.push_back(path / "CMakeLists.txt");
        info.languages.push_back("cpp");
        return true;
    }

    // Check for MSBuild
    for (const auto& entry : std::filesystem::directory_iterator(path, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.path().extension() == ".sln" || entry.path().extension() == ".vcxproj") {
            info.type = "msbuild";
            info.buildFiles.push_back(entry.path());
            info.languages.push_back("cpp");
            return true;
        }
    }

    // Check for Node.js
    if (std::filesystem::exists(path / "package.json")) {
        info.type = "npm";
        info.buildFiles.push_back(path / "package.json");
        info.languages.push_back("javascript");
        info.languages.push_back("typescript");
        return true;
    }

    // Check for Python
    if (std::filesystem::exists(path / "setup.py") || std::filesystem::exists(path / "pyproject.toml") || std::filesystem::exists(path / "requirements.txt")) {
        info.type = "python";
        info.languages.push_back("python");
        return true;
    }

    // Check for Rust
    if (std::filesystem::exists(path / "Cargo.toml")) {
        info.type = "cargo";
        info.buildFiles.push_back(path / "Cargo.toml");
        info.languages.push_back("rust");
        return true;
    }

    // Check for .NET
    if (std::filesystem::exists(path / "*.csproj")) {
        info.type = "dotnet";
        info.languages.push_back("csharp");
        return true;
    }

    return false;
}

// ============================================================================
// Workspace Graph
// ============================================================================
WorkspaceManager::WorkspaceGraph WorkspaceManager::BuildGraph() const {
    WorkspaceGraph graph;
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto& project : m_projects) {
        graph.nodes.push_back(project.rootPath);
        for (const auto& dep : project.dependencies) {
            graph.edges[project.rootPath].push_back(std::filesystem::path(dep));
        }
    }

    return graph;
}

std::vector<std::filesystem::path> WorkspaceManager::GetDependencyOrder() const {
    // Topological sort of projects by dependency
    auto graph = BuildGraph();
    std::vector<std::filesystem::path> result;
    std::map<std::filesystem::path, bool> visited;

    std::function<void(const std::filesystem::path&)> visit;
    visit = [&](const std::filesystem::path& node) {
        if (visited[node]) return;
        visited[node] = true;

        auto it = graph.edges.find(node);
        if (it != graph.edges.end()) {
            for (const auto& dep : it->second) {
                visit(dep);
            }
        }
        result.push_back(node);
    };

    for (const auto& node : graph.nodes) {
        visit(node);
    }

    return result;
}

// ============================================================================
// Settings Inheritance
// ============================================================================
void WorkspaceManager::SetSetting(const std::string& key, const std::string& value, int priority) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_settings[key] = value;
}

std::string WorkspaceManager::GetSetting(const std::string& key) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_settings.find(key);
    return it != m_settings.end() ? it->second : std::string{};
}

bool WorkspaceManager::HasSetting(const std::string& key) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_settings.find(key) != m_settings.end();
}

void WorkspaceManager::RemoveSetting(const std::string& key) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_settings.erase(key);
}

std::map<std::string, std::string> WorkspaceManager::GetAllSettings() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_settings;
}

bool WorkspaceManager::LoadSettingsFile(const std::filesystem::path& path, int priority) {
    if (!std::filesystem::exists(path)) return false;

    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        auto parseStr = [](const std::string& l, const std::string& key) -> std::string {
            auto pos = l.find("\"" + key + "\"");
            if (pos == std::string::npos) return {};
            auto colon = l.find(':', pos);
            if (colon == std::string::npos) return {};
            auto start = l.find('"', colon + 1);
            if (start == std::string::npos) return {};
            auto end = l.find('"', start + 1);
            if (end == std::string::npos) return {};
            return l.substr(start + 1, end - start - 1);
        };

        // Parse "key": "value" pairs
        for (size_t i = 0; i < line.length(); i++) {
            if (line[i] == '"') {
                auto endKey = line.find('"', i + 1);
                if (endKey == std::string::npos) break;
                auto key = line.substr(i + 1, endKey - i - 1);
                auto colon = line.find(':', endKey);
                if (colon == std::string::npos) break;
                auto startVal = line.find('"', colon + 1);
                if (startVal == std::string::npos) break;
                auto endVal = line.find('"', startVal + 1);
                if (endVal == std::string::npos) break;
                auto value = line.substr(startVal + 1, endVal - startVal - 1);
                m_settings[key] = value;
                break;
            }
        }
    }

    return true;
}

bool WorkspaceManager::SaveSettingsFile(const std::filesystem::path& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "{\n";
    bool first = true;
    for (const auto& [key, value] : m_settings) {
        if (!first) file << ",\n";
        first = false;
        file << "  \"" << key << "\": \"" << value << "\"";
    }
    file << "\n}\n";
    return true;
}

// ============================================================================
// Workspace Trust
// ============================================================================
WorkspaceManager::TrustLevel WorkspaceManager::GetTrustLevel(const std::filesystem::path& path) const {
    auto absPath = std::filesystem::absolute(path);
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_trustLevels.find(absPath);
    return it != m_trustLevels.end() ? it->second : TrustLevel::Unknown;
}

void WorkspaceManager::SetTrustLevel(const std::filesystem::path& path, TrustLevel level) {
    auto absPath = std::filesystem::absolute(path);
    std::lock_guard<std::mutex> lock(m_mutex);
    m_trustLevels[absPath] = level;
}

bool WorkspaceManager::IsWorkspaceTrusted() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& folder : m_folders) {
        auto it = m_trustLevels.find(folder.path);
        if (it != m_trustLevels.end() && it->second == TrustLevel::Untrusted) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// Utility
// ============================================================================
std::filesystem::path WorkspaceManager::GetRootPath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_folders.empty()) return {};
    return m_folders[0].path;
}

std::filesystem::path WorkspaceManager::GetWorkspaceStoragePath() const {
    return m_storagePath;
}

void WorkspaceManager::SetWorkspaceStoragePath(const std::filesystem::path& path) {
    m_storagePath = path;
    std::filesystem::create_directories(m_storagePath);
}

} // namespace Workspace
} // namespace RawrXD
