// Win32IDE_FileSystemEvents.cpp — Incremental Indexing (Batch 6 R04)
// Only re-index changed files
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <map>
#include <cstdint>
#include <limits>

struct FileWatchInfo {
    std::string path;
    uint64_t lastModified;
    uint64_t fileSize;
};

static std::map<std::string, FileWatchInfo> g_watchedFiles;

void Win32IDE::initFileSystemWatcher() {
    appendToOutput("[FileSystemEvents] Incremental indexer initialized.\n", "Output", Win32IDE::OutputSeverity::Info);
}

bool Win32IDE::fileNeedsReindex(const std::string& filePath) {
    // The IDE paths are UTF-8; Win32 filesystem APIs require UTF-16.
    if (filePath.empty() || filePath.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     filePath.data(), static_cast<int>(filePath.size()),
                                     nullptr, 0);
    if (length <= 0) return false;
    std::wstring widePath(static_cast<size_t>(length), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            filePath.data(), static_cast<int>(filePath.size()),
                            widePath.data(), length) != length)
        return false;

    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(widePath.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    FindClose(h);

    const uint64_t modTime = (uint64_t{fd.ftLastWriteTime.dwHighDateTime} << 32) |
                              fd.ftLastWriteTime.dwLowDateTime;
    const uint64_t size = (uint64_t{fd.nFileSizeHigh} << 32) | fd.nFileSizeLow;

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
