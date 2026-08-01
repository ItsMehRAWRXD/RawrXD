// ============================================================================
// FileWatcher.hpp — Incremental File System Watcher
// Monitors repository changes and triggers re-indexing
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <filesystem>

namespace RawrXD {
namespace Watcher {

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
// File Change Event
// ============================================================================
struct FileChangeEvent {
    FileChangeType type;
    std::string path;
    std::string oldPath;        // For renames
    std::string extension;
    uint64_t fileSize = 0;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Watcher Configuration
// ============================================================================
struct WatcherConfig {
    std::string rootPath = ".";
    int pollIntervalMs = 1000;          // Polling interval for fallback
    std::vector<std::string> includeExtensions;  // Empty = all
    std::vector<std::string> excludePatterns;    // Glob patterns to exclude
    std::vector<std::string> excludeDirs = {     // Directories to exclude
        ".git", "build", "node_modules", ".rawrxd", ".cache"
    };
    bool useNativeWatcher = true;       // Use OS-native file watching
    bool enablePollingFallback = true;  // Fall back to polling if native fails
    int debounceMs = 100;               // Debounce multiple rapid events
};

// ============================================================================
// File Watcher
// ============================================================================
class FileWatcher {
public:
    FileWatcher();
    ~FileWatcher();

    // Initialization
    bool Initialize(const WatcherConfig& config);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }
    bool IsWatching() const { return m_watching.load(); }

    // Control
    bool Start();
    void Stop();
    void Pause();
    void Resume();

    // Manual scan
    bool ScanNow();
    bool ScanFile(const std::string& path);

    // Callbacks
    using ChangeCallback = std::function<void(const FileChangeEvent&)>;
    using BatchCallback = std::function<void(const std::vector<FileChangeEvent>&)>;

    void SetChangeCallback(ChangeCallback cb) { m_changeCb = cb; }
    void SetBatchCallback(BatchCallback cb) { m_batchCb = cb; }

    // Statistics
    uint64_t GetTotalChanges() const { return m_totalChanges.load(); }
    uint64_t GetProcessedChanges() const { return m_processedChanges.load(); }
    std::vector<std::string> GetWatchedDirectories() const;

private:
    void WatchLoop();
    void PollingLoop();
    void ProcessEvents(std::vector<FileChangeEvent>& events);
    bool ShouldWatchFile(const std::string& path) const;
    bool ShouldWatchDirectory(const std::string& path) const;
    void UpdateFileSnapshot(const std::string& path);
    std::vector<FileChangeEvent> DetectChanges();

#ifdef _WIN32
    void NativeWatchLoop();
    HANDLE m_watchHandle = INVALID_HANDLE_VALUE;
    OVERLAPPED m_overlapped = {0};
    uint8_t m_notifyBuffer[65536];
#endif

private:
    WatcherConfig m_config;
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_watching{false};
    std::atomic<bool> m_paused{false};
    std::atomic<uint64_t> m_totalChanges{0};
    std::atomic<uint64_t> m_processedChanges{0};

    std::thread m_watchThread;
    std::thread m_pollThread;

    // File snapshot for change detection
    struct FileSnapshot {
        std::string path;
        std::filesystem::file_time_type lastWriteTime;
        uint64_t fileSize = 0;
    };
    std::map<std::string, FileSnapshot> m_snapshots;
    mutable std::mutex m_mutex;

    // Callbacks
    ChangeCallback m_changeCb;
    BatchCallback m_batchCb;
};

} // namespace Watcher
} // namespace RawrXD
