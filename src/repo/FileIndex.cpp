// ============================================================================
// FileIndex.cpp - Incremental Filesystem Tracking
// WORKING IMPLEMENTATION
// ============================================================================

#include "RepositoryIntelligence.hpp"
#include <fstream>
#include <filesystem>
#include <chrono>
#include <string>
#include <thread>
#include <mutex>
#include <set>
#include <unordered_set>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace RawrXD {
namespace Repo {

// ============================================================================
// File Watcher Implementation (Windows)
// ============================================================================

class FileWatcher {
public:
    FileWatcher() : watching_(false), hDir_(INVALID_HANDLE_VALUE) {}
    
    ~FileWatcher() {
        Stop();
    }
    
    bool Start(const std::filesystem::path& root, 
               std::function<void(const std::filesystem::path&, bool)> callback) {
#ifdef _WIN32
        root_ = root;
        callback_ = callback;
        
        hDir_ = CreateFileW(
            root.wstring().c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            nullptr
        );
        
        if (hDir_ == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        watching_ = true;
        
        // Start async watch
        ZeroMemory(&overlapped_, sizeof(overlapped_));
        overlapped_.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        
        watchThread_ = std::thread([this]() {
            WatchLoop();
        });
        
        return true;
#else
        // Linux/macOS: use inotify/FSEvents
        return false;
#endif
    }
    
    void Stop() {
        watching_ = false;
        
#ifdef _WIN32
        if (hDir_ != INVALID_HANDLE_VALUE) {
            CancelIo(hDir_);
            CloseHandle(hDir_);
            hDir_ = INVALID_HANDLE_VALUE;
        }
        if (overlapped_.hEvent) {
            CloseHandle(overlapped_.hEvent);
        }
#endif
        
        if (watchThread_.joinable()) {
            watchThread_.join();
        }
    }
    
    std::vector<std::filesystem::path> PollChanges() {
        std::lock_guard<std::mutex> lock(changesMutex_);
        auto result = pendingChanges_;
        pendingChanges_.clear();
        return result;
    }

private:
#ifdef _WIN32
    void WatchLoop() {
        char buffer[4096];
        DWORD bytesReturned;
        
        while (watching_) {
            if (!ReadDirectoryChangesW(
                hDir_,
                buffer,
                sizeof(buffer),
                TRUE,  // Recursive
                FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_CREATION,
                &bytesReturned,
                &overlapped_,
                nullptr
            )) {
                break;
            }
            
            DWORD waitResult = WaitForSingleObject(overlapped_.hEvent, 100);
            if (waitResult == WAIT_OBJECT_0) {
                DWORD transferred;
                if (GetOverlappedResult(hDir_, &overlapped_, &transferred, FALSE)) {
                    ProcessNotification(buffer, bytesReturned);
                }
                ZeroMemory(&overlapped_, sizeof(overlapped_));
                overlapped_.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
            }
        }
    }
    
    void ProcessNotification(char* buffer, DWORD length) {
        FILE_NOTIFY_INFORMATION* info = (FILE_NOTIFY_INFORMATION*)buffer;
        
        while (true) {
            std::wstring filename(info->FileName, info->FileNameLength / sizeof(WCHAR));
            filename.push_back(L'\0');
            
            std::filesystem::path fullPath = root_ / filename;
            bool isDelete = (info->Action == FILE_ACTION_REMOVED ||
                           info->Action == FILE_ACTION_RENAMED_OLD_NAME);
            
            {
                std::lock_guard<std::mutex> lock(changesMutex_);
                pendingChanges_.push_back(fullPath);
            }
            
            if (callback_) {
                callback_(fullPath, isDelete);
            }
            
            if (info->NextEntryOffset == 0) break;
            info = (FILE_NOTIFY_INFORMATION*)((char*)info + info->NextEntryOffset);
        }
    }
#endif

    std::atomic<bool> watching_;
    std::filesystem::path root_;
    std::thread watchThread_;
    std::function<void(const std::filesystem::path&, bool)> callback_;
    
    std::mutex changesMutex_;
    std::vector<std::filesystem::path> pendingChanges_;
    
#ifdef _WIN32
    HANDLE hDir_;
    OVERLAPPED overlapped_;
#endif
};

// ============================================================================
// FileIndexManager Implementation
// ============================================================================

struct FileIndexManager::Impl {
    std::filesystem::path root_;
    std::unordered_map<std::string, FileInfo> files_;
    std::unordered_map<std::string, FileInfo*> byPath_;
    std::vector<FileInfo*> dirtyFiles_;
    std::unique_ptr<FileWatcher> watcher_;
    std::mutex mutex_;
    uint32_t nextId_ = 1;
    
    // File extensions to index
    std::unordered_set<std::string> indexExtensions_ = {
        ".cpp", ".cc", ".cxx", ".c", 
        ".h", ".hpp", ".hxx",
        ".asm", ".S",
        ".py", ".js", ".ts",
        ".md", ".txt"
    };
};

FileIndexManager::FileIndexManager() : impl_(std::make_unique<Impl>()) {}
FileIndexManager::~FileIndexManager() = default;

void FileIndexManager::IndexWorkspace(const std::filesystem::path& root) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->root_ = root;
    
    // Clear existing
    impl_->files_.clear();
    impl_->byPath_.clear();
    impl_->dirtyFiles_.clear();
    
    // Walk directory
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) continue;
        
        auto ext = entry.path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        
        if (impl_->indexExtensions_.count(ext) == 0) continue;
        
        IndexFileInternal(entry.path());
    }
    
    std::cout << "[FileIndex] Indexed " << impl_->files_.size() << " files\n";
}

void FileIndexManager::IndexFile(const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    IndexFileInternal(path);
}

void FileIndexManager::IndexFileInternal(const std::filesystem::path& path) {
    try {
        auto canonical = std::filesystem::canonical(path);
        auto pathStr = canonical.string();
        
        // Check if already indexed
        if (impl_->byPath_.count(pathStr)) {
            return;
        }
        
        FileInfo info;
        info.id = impl_->nextId_++;
        info.path = canonical;
        info.pathStr = pathStr;
        info.extension = canonical.extension().string();
        
        auto status = std::filesystem::status(canonical);
        if (std::filesystem::exists(canonical)) {
            info.size = std::filesystem::file_size(canonical);
            auto time = std::filesystem::last_write_time(canonical);
            info.mtime = std::chrono::duration_cast<std::chrono::seconds>(
                time.time_since_epoch()
            ).count();
            
            // Compute hash
            std::ifstream file(canonical, std::ios::binary);
            if (file) {
                std::string content((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
                info.content = content;
                info.hash = ComputeHash(content);
            }
        }
        
        std::string idStr = std::to_string(info.id);
        impl_->files_[idStr] = info;
        impl_->byPath_[pathStr] = &impl_->files_[idStr];
        
    } catch (const std::exception& e) {
        std::cerr << "[FileIndex] Failed to index " << path << ": " << e.what() << "\n";
    }
}

void FileIndexManager::ReindexFile(const std::string& fileId) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->files_.find(fileId);
    if (it == impl_->files_.end()) return;
    
    auto& info = it->second;
    
    try {
        auto newSize = std::filesystem::file_size(info.path);
        auto newTime = std::filesystem::last_write_time(info.path);
        auto newMtime = std::chrono::duration_cast<std::chrono::seconds>(
            newTime.time_since_epoch()
        ).count();
        
        if (newSize != info.size || newMtime != info.mtime) {
            // Re-read content
            std::ifstream file(info.path, std::ios::binary);
            if (file) {
                std::string content((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
                
                auto newHash = ComputeHash(content);
                if (newHash != info.hash) {
                    info.content = content;
                    info.hash = newHash;
                    info.size = newSize;
                    info.mtime = newMtime;
                    info.isDirty = true;
                    impl_->dirtyFiles_.push_back(&info);
                    
                    std::cout << "[FileIndex] File changed: " << info.pathStr << "\n";
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[FileIndex] Failed to reindex " << fileId << ": " << e.what() << "\n";
    }
}

std::optional<FileInfo> FileIndexManager::GetFile(const std::string& fileId) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->files_.find(fileId);
    if (it != impl_->files_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<FileInfo> FileIndexManager::GetFileByPath(const std::filesystem::path& path) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto canonical = std::filesystem::weakly_canonical(path);
    auto it = impl_->byPath_.find(canonical.string());
    if (it != impl_->byPath_.end()) {
        return *it->second;
    }
    return std::nullopt;
}

std::vector<FileInfo> FileIndexManager::GetAllFiles() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::vector<FileInfo> result;
    result.reserve(impl_->files_.size());
    
    for (const auto& [id, info] : impl_->files_) {
        result.push_back(info);
    }
    
    return result;
}

std::vector<FileInfo> FileIndexManager::GetModifiedSince(std::time_t timestamp) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::vector<FileInfo> result;
    for (const auto& [id, info] : impl_->files_) {
        if (info.mtime > timestamp) {
            result.push_back(info);
        }
    }
    return result;
}

std::vector<FileInfo> FileIndexManager::GetFilesByExtension(const std::string& ext) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::vector<FileInfo> result;
    for (const auto& [id, info] : impl_->files_) {
        if (info.extension == ext) {
            result.push_back(info);
        }
    }
    return result;
}

void FileIndexManager::MarkDirty(const std::string& fileId) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->files_.find(fileId);
    if (it != impl_->files_.end() && !it->second.isDirty) {
        it->second.isDirty = true;
        impl_->dirtyFiles_.push_back(&it->second);
    }
}

void FileIndexManager::MarkClean(const std::string& fileId) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->files_.find(fileId);
    if (it != impl_->files_.end()) {
        it->second.isDirty = false;
    }
}

std::vector<FileInfo> FileIndexManager::GetDirtyFiles() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::vector<FileInfo> result;
    result.reserve(impl_->dirtyFiles_.size());
    
    for (const auto* ptr : impl_->dirtyFiles_) {
        result.push_back(*ptr);
    }
    
    return result;
}

void FileIndexManager::StartWatching() {
    if (!impl_->watcher_) {
        impl_->watcher_ = std::make_unique<FileWatcher>();
    }
    
    impl_->watcher_->Start(impl_->root_, [this](const std::filesystem::path& path, bool isDelete) {
        if (isDelete) {
            // Handle deletion
            std::lock_guard<std::mutex> lock(impl_->mutex_);
            auto it = impl_->byPath_.find(path.string());
            if (it != impl_->byPath_.end()) {
                std::string id = std::to_string(it->second->id);
                impl_->files_.erase(id);
                impl_->byPath_.erase(it);
            }
        } else {
            // Handle modification
            auto file = GetFileByPath(path);
            if (file) {
                ReindexFile(std::to_string(file->id));
            } else {
                IndexFile(path);
            }
        }
    });
}

void FileIndexManager::StopWatching() {
    if (impl_->watcher_) {
        impl_->watcher_->Stop();
    }
}

std::vector<std::filesystem::path> FileIndexManager::PollChanges() {
    if (impl_->watcher_) {
        return impl_->watcher_->PollChanges();
    }
    return {};
}

std::string FileIndexManager::ComputeHash(const std::string& content) {
    // Simple FNV-1a hash
    uint64_t hash = 14695981039346656037ULL;
    for (char c : content) {
        hash ^= static_cast<uint64_t>(c);
        hash *= 1099511628211ULL;
    }
    
    char buf[17];
    snprintf(buf, sizeof(buf), "%016llx", hash);
    return std::string(buf);
}

} // namespace Repo
} // namespace RawrXD
