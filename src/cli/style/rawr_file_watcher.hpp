// rawr_file_watcher.hpp — Win32 FindFirstChangeNotification snapshot poll
#pragma once
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr::style {

struct FileWatcher {
    std::string root;
#ifdef _WIN32
    HANDLE hChange = nullptr;
#endif
    bool watching = false;

    bool start(const std::string& workspace) {
        root = workspace;
#ifdef _WIN32
        hChange = FindFirstChangeNotificationA(
            workspace.c_str(), TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_DIR_NAME);
        watching = hChange && hChange != INVALID_HANDLE_VALUE;
        return watching;
#else
        return false;
#endif
    }

    // Non-blocking: returns true if a change was signaled.
    bool poll(DWORD timeoutMs = 0) {
#ifdef _WIN32
        if (!watching) return false;
        DWORD w = WaitForSingleObject(hChange, timeoutMs);
        if (w == WAIT_OBJECT_0) {
            FindNextChangeNotification(hChange);
            return true;
        }
        return false;
#else
        (void)timeoutMs;
        return false;
#endif
    }

    void stop() {
#ifdef _WIN32
        if (watching && hChange) {
            FindCloseChangeNotification(hChange);
            hChange = nullptr;
        }
#endif
        watching = false;
    }

    ~FileWatcher() { stop(); }
};

} // namespace rawr::style
