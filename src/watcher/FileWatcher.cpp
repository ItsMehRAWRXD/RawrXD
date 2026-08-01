// ============================================================================
// FileWatcher.cpp — Incremental File System Watcher Implementation
// ============================================================================
#include "FileWatcher.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace RawrXD {
namespace Watcher {

FileWatcher::FileWatcher() = default;
FileWatcher::~FileWatcher() { Shutdown(); }

bool FileWatcher::Initialize(const WatcherConfig& config) {
    m_config = config;
    
    // Resolve root path
    try {
        m_config.rootPath = fs::absolute(m_config.rootPath).string();
    } catch (...) {
        m_config.rootPath = fs::current_path().string();
    }

    // Build initial file snapshot
    ScanNow();

    m_initialized = true;
    return true;
}

void FileWatcher::Shutdown() {
    Stop();
    m_initialized = false;
}

bool FileWatcher::Start() {
    if (!m_initialized || m_watching.exchange(true)) return false;

#ifdef _WIN32
    if (m_config.useNativeWatcher) {
        m_watchThread = std::thread(&FileWatcher::NativeWatchLoop, this);
    }
#endif

    if (m_config.enablePollingFallback) {
        m_pollThread = std::thread(&FileWatcher::PollingLoop, this);
    }

    return true;
}

void FileWatcher::Stop() {
    m_watching = false;
    if (m_watchThread.joinable()) m_watchThread.join();
    if (m_pollThread.joinable()) m_pollThread.join();
}

void FileWatcher::Pause() {
    m_paused = true;
}

void FileWatcher::Resume() {
    m_paused = false;
}

bool FileWatcher::ScanNow() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_snapshots.clear();

    try {
        for (const auto& entry : fs::recursive_directory_iterator(m_config.rootPath)) {
            if (!entry.is_regular_file()) continue;
            if (!ShouldWatchFile(entry.path().string())) continue;

            FileSnapshot snap;
            snap.path = entry.path().string();
            snap.lastWriteTime = entry.last_write_time();
            snap.fileSize = entry.file_size();
            m_snapshots[snap.path] = snap;
        }
    } catch (const std::exception& e) {
        fprintf(stderr, "[FileWatcher] Scan error: %s\n", e.what());
    }

    return true;
}

bool FileWatcher::ScanFile(const std::string& path) {
    try {
        if (!fs::exists(path)) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_snapshots.erase(path);
            return true;
        }

        FileSnapshot snap;
        snap.path = path;
        snap.lastWriteTime = fs::last_write_time(path);
        snap.fileSize = fs::file_size(path);

        std::lock_guard<std::mutex> lock(m_mutex);
        m_snapshots[path] = snap;
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<std::string> FileWatcher::GetWatchedDirectories() const {
    std::vector<std::string> dirs;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [path, snap] : m_snapshots) {
        std::string dir = fs::path(path).parent_path().string();
        if (std::find(dirs.begin(), dirs.end(), dir) == dirs.end()) {
            dirs.push_back(dir);
        }
    }
    return dirs;
}

// ============================================================================
// Private: Polling Loop
// ============================================================================
void FileWatcher::PollingLoop() {
    while (m_watching.load()) {
        if (!m_paused.load()) {
            auto changes = DetectChanges();
            if (!changes.empty()) {
                ProcessEvents(changes);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(m_config.pollIntervalMs));
    }
}

// ============================================================================
// Private: Detect Changes
// ============================================================================
std::vector<FileChangeEvent> FileWatcher::DetectChanges() {
    std::vector<FileChangeEvent> events;
    std::lock_guard<std::mutex> lock(m_mutex);

    // Check for new and modified files
    try {
        for (const auto& entry : fs::recursive_directory_iterator(m_config.rootPath)) {
            if (!entry.is_regular_file()) continue;
            if (!ShouldWatchFile(entry.path().string())) continue;

            std::string path = entry.path().string();
            auto it = m_snapshots.find(path);

            if (it == m_snapshots.end()) {
                // New file
                FileChangeEvent event;
                event.type = FileChangeType::Created;
                event.path = path;
                event.extension = entry.path().extension().string();
                event.fileSize = entry.file_size();
                event.timestamp = std::chrono::system_clock::now();
                events.push_back(event);

                FileSnapshot snap;
                snap.path = path;
                snap.lastWriteTime = entry.last_write_time();
                snap.fileSize = entry.file_size();
                m_snapshots[path] = snap;
            } else if (entry.last_write_time() != it->second.lastWriteTime) {
                // Modified file
                FileChangeEvent event;
                event.type = FileChangeType::Modified;
                event.path = path;
                event.extension = entry.path().extension().string();
                event.fileSize = entry.file_size();
                event.timestamp = std::chrono::system_clock::now();
                events.push_back(event);

                it->second.lastWriteTime = entry.last_write_time();
                it->second.fileSize = entry.file_size();
            }
        }
    } catch (const std::exception& e) {
        fprintf(stderr, "[FileWatcher] Detect error: %s\n", e.what());
    }

    // Check for deleted files
    auto it = m_snapshots.begin();
    while (it != m_snapshots.end()) {
        if (!fs::exists(it->first)) {
            FileChangeEvent event;
            event.type = FileChangeType::Deleted;
            event.path = it->first;
            event.timestamp = std::chrono::system_clock::now();
            events.push_back(event);
            it = m_snapshots.erase(it);
        } else {
            ++it;
        }
    }

    m_totalChanges += events.size();
    return events;
}

// ============================================================================
// Private: Process Events
// ============================================================================
void FileWatcher::ProcessEvents(std::vector<FileChangeEvent>& events) {
    if (events.empty()) return;

    // Debounce: group rapid events
    if (m_config.debounceMs > 0 && events.size() > 1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(m_config.debounceMs));
        
        // Re-scan to get final state
        auto freshEvents = DetectChanges();
        if (!freshEvents.empty()) {
            events = std::move(freshEvents);
        }
    }

    // Fire individual callbacks
    for (const auto& event : events) {
        m_processedChanges++;
        if (m_changeCb) {
            m_changeCb(event);
        }
    }

    // Fire batch callback
    if (m_batchCb) {
        m_batchCb(events);
    }
}

// ============================================================================
// Private: Filtering
// ============================================================================
bool FileWatcher::ShouldWatchFile(const std::string& path) const {
    // Check exclude dirs
    for (const auto& dir : m_config.excludeDirs) {
        if (path.find("/" + dir + "/") != std::string::npos ||
            path.find("\\" + dir + "\\") != std::string::npos) {
            return false;
        }
    }

    // Check include extensions
    if (!m_config.includeExtensions.empty()) {
        std::string ext = fs::path(path).extension().string();
        if (std::find(m_config.includeExtensions.begin(), 
                      m_config.includeExtensions.end(), ext) == m_config.includeExtensions.end()) {
            return false;
        }
    }

    return true;
}

bool FileWatcher::ShouldWatchDirectory(const std::string& path) const {
    for (const auto& dir : m_config.excludeDirs) {
        if (path.find(dir) != std::string::npos) return false;
    }
    return true;
}

// ============================================================================
// Private: Windows Native Watcher
// ============================================================================
#ifdef _WIN32
void FileWatcher::NativeWatchLoop() {
    std::string watchPath = m_config.rootPath;

    m_watchHandle = CreateFileA(
        watchPath.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (m_watchHandle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[FileWatcher] Native watch failed, using polling\n");
        return;
    }

    memset(&m_overlapped, 0, sizeof(m_overlapped));
    m_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    while (m_watching.load()) {
        DWORD bytesReturned = 0;
        BOOL result = ReadDirectoryChangesW(
            m_watchHandle,
            m_notifyBuffer,
            sizeof(m_notifyBuffer),
            TRUE,  // Watch subtree
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_SIZE,
            &bytesReturned,
            &m_overlapped,
            NULL
        );

        if (!result) break;

        DWORD waitResult = WaitForSingleObject(m_overlapped.hEvent, 1000);
        if (waitResult == WAIT_OBJECT_0) {
            GetOverlappedResult(m_watchHandle, &m_overlapped, &bytesReturned, FALSE);
            
            // Process notifications
            FILE_NOTIFY_INFORMATION* notify = 
                reinterpret_cast<FILE_NOTIFY_INFORMATION*>(m_notifyBuffer);
            
            std::vector<FileChangeEvent> events;
            
            while (notify) {
                FileChangeEvent event;
                std::wstring fileName(notify->FileName, notify->FileNameLength / sizeof(wchar_t));
                event.path = watchPath + "\\" + std::string(fileName.begin(), fileName.end());
                event.timestamp = std::chrono::system_clock::now();

                switch (notify->Action) {
                    case FILE_ACTION_ADDED:
                        event.type = FileChangeType::Created;
                        break;
                    case FILE_ACTION_MODIFIED:
                        event.type = FileChangeType::Modified;
                        break;
                    case FILE_ACTION_REMOVED:
                        event.type = FileChangeType::Deleted;
                        break;
                    case FILE_ACTION_RENAMED_OLD_NAME:
                        event.type = FileChangeType::Renamed;
                        event.oldPath = event.path;
                        break;
                    case FILE_ACTION_RENAMED_NEW_NAME:
                        // Paired with RENAMED_OLD_NAME
                        break;
                }

                events.push_back(event);
                m_totalChanges++;

                if (notify->NextEntryOffset == 0) break;
                notify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                    reinterpret_cast<uint8_t*>(notify) + notify->NextEntryOffset);
            }

            if (!events.empty()) {
                ProcessEvents(events);
            }

            ResetEvent(m_overlapped.hEvent);
        }
    }

    CloseHandle(m_overlapped.hEvent);
    CloseHandle(m_watchHandle);
    m_watchHandle = INVALID_HANDLE_VALUE;
}
#endif

} // namespace Watcher
} // namespace RawrXD
