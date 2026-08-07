#include "workspace_manager.h"
#include <windows.h>
#include <shlwapi.h>
#include <json/json.h>
#include <fstream>
#include <sstream>

#pragma comment(lib, "shlwapi.lib")

namespace RawrXD {
namespace Workspace {

// FileWatcher implementation
bool FileWatcher::Initialize() {
    running_ = true;
    watcherThread_ = std::thread(&FileWatcher::WatcherThread, this);
    return true;
}

bool FileWatcher::Shutdown() {
    running_ = false;
    
    // Close all watch handles
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [path, handle] : watchHandles_) {
        FindCloseChangeNotification(handle);
    }
    watchHandles_.clear();
    
    if (watcherThread_.joinable()) {
        watcherThread_.join();
    }
    return true;
}

bool FileWatcher::WatchFolder(const std::string& path, bool recursive) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (watchHandles_.find(path) != watchHandles_.end()) {
        return true; // Already watching
    }
    
    HANDLE hChange = FindFirstChangeNotificationA(
        path.c_str(),
        recursive ? TRUE : FALSE,
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | 
        FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
        FILE_NOTIFY_CHANGE_LAST_WRITE
    );
    
    if (hChange == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    watchHandles_[path] = hChange;
    return true;
}

bool FileWatcher::UnwatchFolder(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = watchHandles_.find(path);
    if (it == watchHandles_.end()) return false;
    
    FindCloseChangeNotification(it->second);
    watchHandles_.erase(it);
    return true;
}

void FileWatcher::WatcherThread() {
    while (running_) {
        std::vector<HANDLE> handles;
        std::vector<std::string> paths;
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& [path, handle] : watchHandles_) {
                handles.push_back(handle);
                paths.push_back(path);
            }
        }
        
        if (handles.empty()) {
            Sleep(100);
            continue;
        }
        
        DWORD result = WaitForMultipleObjects(
            static_cast<DWORD>(handles.size()),
            handles.data(),
            FALSE,
            100
        );
        
        if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + handles.size()) {
            size_t index = result - WAIT_OBJECT_0;
            if (callback_) {
                callback_(paths[index], false);
            }
            
            // Reset the notification
            FindNextChangeNotification(handles[index]);
        }
    }
}

// WorkspaceManager implementation
WorkspaceManager& WorkspaceManager::Instance() {
    static WorkspaceManager instance;
    return instance;
}

bool WorkspaceManager::Initialize() {
    fileWatcher_ = std::make_unique<FileWatcher>();
    fileWatcher_->Initialize();
    fileWatcher_->SetChangeCallback([this](const std::string& path, bool isDir) {
        OnFileChanged(path, isDir);
    });
    return true;
}

bool WorkspaceManager::Shutdown() {
    if (fileWatcher_) {
        fileWatcher_->Shutdown();
        fileWatcher_.reset();
    }
    return true;
}

bool WorkspaceManager::AddFolder(const std::string& path, const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    WorkspaceFolder folder;
    folder.path = path;
    folder.name = name.empty() ? PathFindFileNameA(path.c_str()) : name;
    folder.index = static_cast<int>(folders_.size());
    folder.uri = "file:///" + path;
    
    folders_.push_back(folder);
    
    // Start watching this folder
    if (fileWatcher_) {
        fileWatcher_->WatchFolder(path, true);
    }
    
    return true;
}

bool WorkspaceManager::RemoveFolder(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = std::find_if(folders_.begin(), folders_.end(),
        [&name](const WorkspaceFolder& f) { return f.name == name; });
    
    if (it == folders_.end()) return false;
    
    if (fileWatcher_) {
        fileWatcher_->UnwatchFolder(it->path);
    }
    
    folders_.erase(it);
    return true;
}

bool WorkspaceManager::RemoveFolder(int index) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (index < 0 || index >= static_cast<int>(folders_.size())) return false;
    
    if (fileWatcher_) {
        fileWatcher_->UnwatchFolder(folders_[index].path);
    }
    
    folders_.erase(folders_.begin() + index);
    return true;
}

std::vector<WorkspaceFolder> WorkspaceManager::GetFolders() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return folders_;
}

std::vector<std::string> WorkspaceManager::GetFiles(const std::string& pattern) {
    std::vector<std::string> files;
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& folder : folders_) {
        std::string searchPath = folder.path + "\\" + pattern;
        
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    files.push_back(folder.path + "\\" + findData.cFileName);
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    return files;
}

std::vector<std::string> WorkspaceManager::GetDirectories(const std::string& path) {
    std::vector<std::string> dirs;
    
    std::string searchPath = path.empty() ? "*" : path + "\\*";
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                strcmp(findData.cFileName, ".") != 0 &&
                strcmp(findData.cFileName, "..") != 0) {
                dirs.push_back(findData.cFileName);
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    
    return dirs;
}

bool WorkspaceManager::FileExists(const std::string& path) {
    DWORD attribs = GetFileAttributesA(path.c_str());
    return attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY);
}

bool WorkspaceManager::CreateFile(const std::string& path) {
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, 
                               CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        return true;
    }
    return false;
}

bool WorkspaceManager::CreateDirectory(const std::string& path) {
    return CreateDirectoryA(path.c_str(), nullptr) != 0 || GetLastError() == ERROR_ALREADY_EXISTS;
}

bool WorkspaceManager::DeleteFile(const std::string& path) {
    return DeleteFileA(path.c_str()) != 0;
}

bool WorkspaceManager::RenameFile(const std::string& oldPath, const std::string& newPath) {
    return MoveFileA(oldPath.c_str(), newPath.c_str()) != 0;
}

bool WorkspaceManager::OpenTextDocument(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if already open
    for (const auto& doc : textDocuments_) {
        if (doc.path == path) return true;
    }
    
    TextDocument doc;
    doc.path = path;
    doc.uri = "file:///" + path;
    
    // Determine language from extension
    const char* ext = PathFindExtensionA(path.c_str());
    if (_stricmp(ext, ".cpp") == 0 || _stricmp(ext, ".cc") == 0 || _stricmp(ext, ".h") == 0) {
        doc.languageId = "cpp";
    } else if (_stricmp(ext, ".c") == 0) {
        doc.languageId = "c";
    } else if (_stricmp(ext, ".js") == 0) {
        doc.languageId = "javascript";
    } else if (_stricmp(ext, ".json") == 0) {
        doc.languageId = "json";
    } else if (_stricmp(ext, ".md") == 0) {
        doc.languageId = "markdown";
    } else {
        doc.languageId = "plaintext";
    }
    
    textDocuments_.push_back(doc);
    return true;
}

bool WorkspaceManager::CloseTextDocument(const std::string& uri) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = std::remove_if(textDocuments_.begin(), textDocuments_.end(),
        [&uri](const TextDocument& doc) { return doc.uri == uri; });
    
    if (it == textDocuments_.end()) return false;
    
    textDocuments_.erase(it, textDocuments_.end());
    return true;
}

std::vector<TextDocument> WorkspaceManager::GetTextDocuments() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return textDocuments_;
}

TextDocument* WorkspaceManager::GetTextDocument(const std::string& uri) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& doc : textDocuments_) {
        if (doc.uri == uri) return &doc;
    }
    return nullptr;
}

std::unique_ptr<FileTreeNode> WorkspaceManager::BuildFileTree(const std::string& folderPath) {
    auto root = std::make_unique<FileTreeNode>();
    root->name = PathFindFileNameA(folderPath.c_str());
    root->path = folderPath;
    root->isDirectory = true;
    
    std::function<void(FileTreeNode*, const std::string&)> buildTree = 
        [&](FileTreeNode* node, const std::string& path) {
        std::string searchPath = path + "\\*";
        
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) return;
        
        do {
            if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
                continue;
            
            auto child = std::make_unique<FileTreeNode>();
            child->name = findData.cFileName;
            child->path = path + "\\" + findData.cFileName;
            child->isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            child->parent = node;
            
            // Get git status
            auto it = gitStatus_.find(child->path);
            if (it != gitStatus_.end()) {
                child->gitStatus = it->second;
            }
            
            if (child->isDirectory) {
                buildTree(child.get(), child->path);
            }
            
            node->children.push_back(std::move(child));
        } while (FindNextFileA(hFind, &findData));
        
        FindClose(hFind);
    };
    
    buildTree(root.get(), folderPath);
    return root;
}

void WorkspaceManager::RefreshFileTree() {
    // Triggered by file watcher
}

void WorkspaceManager::UpdateGitStatus(const std::string& path, GitStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);
    gitStatus_[path] = status;
}

GitStatus WorkspaceManager::GetGitStatus(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = gitStatus_.find(path);
    if (it != gitStatus_.end()) return it->second;
    return GitStatus::Unmodified;
}

bool WorkspaceManager::LoadWorkspaceConfiguration(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;
    
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(file, root)) return false;
    
    // Load folders
    const Json::Value& folders = root["folders"];
    for (const auto& folder : folders) {
        std::string folderPath = folder["path"].asString();
        std::string name = folder.get("name", "").asString();
        AddFolder(folderPath, name);
    }
    
    // Load settings
    const Json::Value& settings = root["settings"];
    for (const auto& member : settings.getMemberNames()) {
        settings_[member] = settings[member].asString();
    }
    
    return true;
}

bool WorkspaceManager::SaveWorkspaceConfiguration(const std::string& path) {
    Json::Value root;
    
    // Save folders
    Json::Value folders(Json::arrayValue);
    for (const auto& folder : folders_) {
        Json::Value f;
        f["path"] = folder.path;
        f["name"] = folder.name;
        folders.append(f);
    }
    root["folders"] = folders;
    
    // Save settings
    Json::Value settings;
    for (const auto& [key, value] : settings_) {
        settings[key] = value;
    }
    root["settings"] = settings;
    
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    Json::StreamWriterBuilder builder;
    file << Json::writeString(builder, root);
    return true;
}

std::string WorkspaceManager::GetSetting(const std::string& key, const std::string& defaultValue) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = settings_.find(key);
    if (it != settings_.end()) return it->second;
    return defaultValue;
}

void WorkspaceManager::SetSetting(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    settings_[key] = value;
}

void WorkspaceManager::OnFileChanged(const std::string& path, bool isDirectory) {
    if (fileChangeCallback_) {
        fileChangeCallback_(path, isDirectory ? "directory" : "file");
    }
}

std::string WorkspaceManager::MakeRelativePath(const std::string& path) {
    // Convert absolute path to relative path based on workspace folders
    for (const auto& folder : folders_) {
        if (path.find(folder.path) == 0) {
            return path.substr(folder.path.length() + 1);
        }
    }
    return path;
}

} // namespace Workspace
} // namespace RawrXD
