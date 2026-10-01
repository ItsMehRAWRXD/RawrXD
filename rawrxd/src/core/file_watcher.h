// file_watcher.h — RAWRXD_CORE_HEADERS_PRESENT_001
//
// This header did not exist. src/core/file_watcher.cpp included it, so the
// translation unit could never compile, and it was not in any build target — so
// the defect was invisible in both a source listing and a successful build.
//
// Declared from the implementation, not the other way round: every member and
// enumeration value below is used by file_watcher.cpp, and the class shape is
// what that file's ReadDirectoryChangesW loop requires.
#pragma once

#include <windows.h>
#include <functional>
#include <string>
#include <thread>

namespace RawrXD::Core {

enum class FileChangeType {
    CREATED,
    DELETED,
    MODIFIED,
    RENAMED_OLD,
    RENAMED_NEW
};

struct FileChangeEvent {
    std::string   path;
    FileChangeType type = FileChangeType::MODIFIED;
};

using FileChangeCallback = std::function<void(const FileChangeEvent&)>;

// Watches one directory recursively (bWatchSubtree = TRUE) on a dedicated
// thread. Not recursive over the tree, only over the entries of the watched
// directory: FILE_NOTIFY_CHANGE_FILE_NAME / CREATION / LAST_WRITE, and
// ReadDirectoryChangesW is issued with bWatchSubtree = TRUE so subdirectories
// report through their parents.
class FileWatcher {
public:
    FileWatcher();
    ~FileWatcher();

    // Stops any previous watch, then starts watching `path`. Returns false if
    // the directory could not be opened.
    bool watch(const std::string& path, FileChangeCallback cb);

    // Stops the worker thread and closes the directory handle. Idempotent.
    void stop();

    bool isWatching() const { return m_running; }

private:
    HANDLE        m_hDir = INVALID_HANDLE_VALUE;
    std::thread   m_worker;
    FileChangeCallback m_callback;
    bool          m_running = false;
};

} // namespace RawrXD::Core
