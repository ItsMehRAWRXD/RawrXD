// Win32IDE_FileSystemEvents.cpp — Incremental Indexing (Batch 6 R04)
// Only re-index changed files
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <map>
#include <ctime>

struct FileWatchInfo {
    std::string path;
    time_t lastModified;
    size_t fileSize;
};

static std::map<std::string, FileWatchInfo> g_watchedFiles;

void Win32IDE::initFileSystemWatcher() {
    appendToOutput("[FileSystemEvents] Incremental indexer initialized.\n", "Output", OutputSeverity::Info);
}

bool Win32IDE::fileNeedsReindex(const std::string& filePath) {
    WIN32_FIND_DATA fd;
    HANDLE h = FindFirstFileA(filePath.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    FindClose(h);

    time_t modTime = fd.ftLastWriteTime.dwHighDateTime;
    modTime <<= 32;
    modTime |= fd.ftLastWriteTime.dwLowDateTime;
    size_t size = fd.nFileSizeHigh;
    size <<= 32;
    size |= fd.nFileSizeLow;

    auto it = g_watchedFiles.find(filePath);
    if (it == g_watchedFiles.end()) {
        g_watchedFiles[filePath] = {filePath, modTime, size};
        return true;
    }

    if (it->second.lastModified != modTime || it->second.fileSize != size) {
        it->second.lastModified = modTime;
        it->second.fileSize = size;
        return true;
    }

    return false;
}

void Win32IDE::removeWatchedFile(const std::string& filePath) {
    g_watchedFiles.erase(filePath);
}
