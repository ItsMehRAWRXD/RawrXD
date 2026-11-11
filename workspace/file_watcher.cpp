// file_watcher.cpp — File System Watcher
#include "workspace_manager.hpp"
#include <thread>
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Workspace {

// ============================================================================
// File Watcher — Polling-based cross-platform file change detection
// ============================================================================
class FileWatcher {
public:
    FileWatcher();
    ~FileWatcher();

    bool Watch(const std::filesystem::path& path, bool recursive = true);
    bool Unwatch(const std::filesystem::path& path);
    void UnwatchAll();

    void SetCallback(WorkspaceManager::FileChangeCallback callback) { m_callback = callback; }
    bool IsWatching(const std::filesystem::path& path) const;

    // Polling interval
    void SetPollInterval(int ms) { m_pollIntervalMs = ms; }
    int GetPollInterval() const { return m_pollIntervalMs; }

    // Debounce settings
    void SetDebounceMs(int ms) { m_debounceMs = ms; }
    int GetDebounceMs() const { return m_debounceMs; }

private:
    void PollLoop();
    void CheckFile(const std::filesystem::path& path);

    std::map<std::filesystem::path, std::filesystem::file_time_type> m_fileStates;
    std::map<std::filesystem::path, std::chrono::steady_clock::time_point> m_lastNotified;
    std::unique_ptr<std::thread> m_pollThread;
    std::atomic<bool> m_running{false};
    WorkspaceManager::FileChangeCallback m_callback;

    int m_pollIntervalMs = 1000;
    int m_debounceMs = 100;
    mutable std::mutex m_mutex;
};

FileWatcher::FileWatcher() = default;
FileWatcher::~FileWatcher() { UnwatchAll(); }

bool FileWatcher::Watch(const std::filesystem::path& path, bool recursive) {
    if (!std::filesystem::exists(path)) return false;

    std::lock_guard<std::mutex> lock(m_mutex);

    // Index all files
    auto watchDir = [&](const std::filesystem::path& dir, auto& self) -> void {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                if (entry.is_regular_file()) {
                    m_fileStates[entry.path()] = std::filesystem::last_write_time(entry.path());
                } else if (entry.is_directory() && recursive) {
                    self(entry.path(), self);
                }
            }
        } catch (...) {}
    };
    watchDir(path, watchDir);

    // Start poll thread if not running
    if (!m_running) {
        m_running = true;
        m_pollThread = std::make_unique<std::thread>(&FileWatcher::PollLoop, this);
    }

    return true;
}

bool FileWatcher::Unwatch(const std::filesystem::path& path) {
    auto absPath = std::filesystem::absolute(path);
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto it = m_fileStates.begin(); it != m_fileStates.end(); ) {
        if (it->first.string().find(absPath.string()) == 0) {
            it = m_fileStates.erase(it);
        } else {
            ++it;
        }
    }
    return true;
}

void FileWatcher::UnwatchAll() {
    m_running = false;
    if (m_pollThread && m_pollThread->joinable()) {
        m_pollThread->join();
    }
    m_pollThread.reset();

    std::lock_guard<std::mutex> lock(m_mutex);
    m_fileStates.clear();
}

bool FileWatcher::IsWatching(const std::filesystem::path& path) const {
    auto absPath = std::filesystem::absolute(path);
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [filePath, _] : m_fileStates) {
        if (filePath.string().find(absPath.string()) == 0) return true;
    }
    return false;
}

void FileWatcher::PollLoop() {
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(m_pollIntervalMs));

        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = m_fileStates.begin(); it != m_fileStates.end(); ) {
            const auto& path = it->first;
            auto oldTime = it->second;

            if (!std::filesystem::exists(path)) {
                // File deleted
                FileWatchEvent event;
                event.path = path;
                event.changeType = FileChangeType::Deleted;
                event.timestamp = std::chrono::system_clock::now();
                if (m_callback) m_callback(event);
                it = m_fileStates.erase(it);
                continue;
            }

            try {
                auto newTime = std::filesystem::last_write_time(path);
                if (newTime != oldTime) {
                    it->second = newTime;

                    // Debounce: only notify if enough time has passed
                    auto now = std::chrono::steady_clock::now();
                    auto& lastNotified = m_lastNotified[path];
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastNotified).count() >= m_debounceMs) {
                        lastNotified = now;

                        FileWatchEvent event;
                        event.path = path;
                        event.changeType = FileChangeType::Modified;
                        event.timestamp = std::chrono::system_clock::now();
                        if (m_callback) m_callback(event);
                    }
                }
            } catch (...) {
                // Permission error, skip
            }

            ++it;
        }
    }
}

} // namespace Workspace
} // namespace RawrXD
