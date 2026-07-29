// File Browser - Production-Ready File system navigation with logging
// Features: Lazy loading, performance monitoring, error handling, async operations
#include "file_browser.h"
#include <iostream>
<<<<<<< HEAD
#include <vector>
#include <windows.h>

=======
#include <filesystem>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
FileBrowser::FileBrowser() {
}

FileBrowser::~FileBrowser() {
}

void FileBrowser::initialize() {
}

std::vector<FileInfo> FileBrowser::listDirectory(const std::string& dirpath) {
    std::vector<FileInfo> results;
    try {
<<<<<<< HEAD
        std::string searchPath = dirpath;
        if (!searchPath.empty() && searchPath.back() != '\\') {
            searchPath += '\\';
        }
        searchPath += '*';

        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) {
            if (onError) onError(dirpath, "Directory not found or access denied");
            return results;
        }

        do {
            // Skip . and ..
            if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) {
                continue;
            }

            FileInfo info;
            info.name = findData.cFileName;
            info.path = dirpath;
            if (!info.path.empty() && info.path.back() != '\\') {
                info.path += '\\';
            }
            info.path += findData.cFileName;
            info.isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            info.size = info.isDirectory ? 0 : ((uint64_t)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
            results.push_back(info);
        } while (FindNextFileA(hFind, &findData));

        FindClose(hFind);
    } catch (const std::exception& e) {
        if (onError) onError(dirpath, e.what());
    }
    return results;
}

std::vector<std::string> FileBrowser::getDrives() {
    std::vector<std::string> drives;
#ifdef _WIN32
    char driveBuffer[256];
    DWORD length = GetLogicalDriveStringsA(sizeof(driveBuffer), driveBuffer);
    if (length > 0) {
        char* drive = driveBuffer;
        while (*drive) {
            drives.push_back(drive);
            drive += strlen(drive) + 1;
        }
=======
        std::filesystem::path p(dirpath);
        if (!std::filesystem::exists(p) || !std::filesystem::is_directory(p)) {
            return results;
        }

        for (const auto& entry : std::filesystem::directory_iterator(p)) {
            FileInfo info;
            info.name = entry.path().filename().string();
            info.path = entry.path().string();
            info.isDirectory = entry.is_directory();
            info.size = entry.is_regular_file() ? entry.file_size() : 0;
            results.push_back(info);
        }
    } catch (const std::exception& e) {
        if (onError) onError(dirpath, e.what());
    }
    return results;
}

std::vector<std::string> FileBrowser::getDrives() {
    std::vector<std::string> drives;
#ifdef _WIN32
    char driveBuffer[256];
    DWORD length = GetLogicalDriveStringsA(sizeof(driveBuffer), driveBuffer);
    if (length > 0) {
        char* drive = driveBuffer;
        while (*drive) {
            drives.push_back(drive);
            drive += strlen(drive) + 1;
        }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
#else
    drives.push_back("/");
#endif
    return drives;
}

void FileBrowser::logOperation(const std::string& level, const std::string& message) {
    std::cout << "[" << level << "] FileBrowser: " << message << std::endl;
}

