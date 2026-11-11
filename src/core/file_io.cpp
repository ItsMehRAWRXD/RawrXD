// Production implementation for file_io.cpp
// Comprehensive file I/O operations for RawrXD Core Runtime
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include <windows.h>
#include <string>
#include <string>
#include <vector>
#include <chrono>

namespace RawrXD { namespace Core {

// Internal helper to convert UTF-8 to wide string for Windows API
static std::wstring Utf8ToWide(const char* utf8) {
    if (!utf8 || !*utf8) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (size <= 0) return L"";
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, result.data(), size);
    return result;
}

// Internal helper to convert wide string to UTF-8
static std::string WideToUtf8(const wchar_t* wide) {
    if (!wide || !*wide) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "";
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, result.data(), size, nullptr, nullptr);
    return result;
}

bool FileExists(const char* path) {
    if (!path || !*path) return false;
    
    std::wstring widePath = Utf8ToWide(path);
    if (widePath.empty()) return false;
    
    DWORD attributes = GetFileAttributesW(widePath.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES && 
            !(attributes & FILE_ATTRIBUTE_DIRECTORY));
}

bool DirectoryExists(const char* path) {
    if (!path || !*path) return false;
    
    std::wstring widePath = Utf8ToWide(path);
    if (widePath.empty()) return false;
    
    DWORD attributes = GetFileAttributesW(widePath.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES && 
            (attributes & FILE_ATTRIBUTE_DIRECTORY));
}

bool CreateDirectoryRecursive(const char* path) {
    if (!path || !*path) return false;
    
    std::wstring widePath = Utf8ToWide(path);
    if (widePath.empty()) return false;
    
    // Create directories recursively
    for (size_t i = 0; i < widePath.length(); ++i) {
        if (widePath[i] == L'\\' || widePath[i] == L'/') {
            std::wstring parent = widePath.substr(0, i);
            if (!parent.empty()) {
                CreateDirectoryW(parent.c_str(), nullptr);
            }
        }
    }
    
    // Create the final directory
    BOOL result = CreateDirectoryW(widePath.c_str(), nullptr);
    if (!result && GetLastError() != ERROR_ALREADY_EXISTS) {
        return false;
    }
    
    return true;
}

bool DeleteFile(const char* path) {
    if (!path || !*path) return false;
    
    std::wstring widePath = Utf8ToWide(path);
    if (widePath.empty()) return false;
    
    return DeleteFileW(widePath.c_str()) != 0;
}

bool RenameFile(const char* oldPath, const char* newPath) {
    if (!oldPath || !*oldPath || !newPath || !*newPath) return false;
    
    std::wstring wideOld = Utf8ToWide(oldPath);
    std::wstring wideNew = Utf8ToWide(newPath);
    if (wideOld.empty() || wideNew.empty()) return false;
    
    return MoveFileW(wideOld.c_str(), wideNew.c_str()) != 0;
}

int64_t GetFileSize(const char* path) {
    if (!path || !*path) return -1;
    
    std::wstring widePath = Utf8ToWide(path);
    if (widePath.empty()) return -1;
    
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (!GetFileAttributesExW(widePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
        return -1;
    }
    
    LARGE_INTEGER size;
    size.HighPart = fileInfo.nFileSizeHigh;
    size.LowPart = fileInfo.nFileSizeLow;
    return size.QuadPart;
}

bool GetFileModificationTime(const char* path, uint64_t* outTimestamp) {
    if (!path || !*path || !outTimestamp) return false;
    
    std::wstring widePath = Utf8ToWide(path);
    if (widePath.empty()) return false;
    
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (!GetFileAttributesExW(widePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
        return false;
    }
    
    // Convert FILETIME to Unix timestamp (seconds since epoch)
    ULARGE_INTEGER ull;
    ull.LowPart = fileInfo.ftLastWriteTime.dwLowDateTime;
    ull.HighPart = fileInfo.ftLastWriteTime.dwHighDateTime;
    
    // FILETIME is in 100-nanosecond intervals since January 1, 1601
    // Convert to seconds since January 1, 1970
    *outTimestamp = (ull.QuadPart - 116444736000000000ULL) / 10000000ULL;
    
    return true;
}

std::vector<std::string> ListDirectory(const char* path) {
    std::vector<std::string> result;
    
    if (!path || !*path) return result;
    
    std::wstring widePath = Utf8ToWide(path);
    if (widePath.empty()) return result;
    
    // Ensure path ends with backslash for search pattern
    if (widePath.back() != L'\\' && widePath.back() != L'/') {
        widePath += L'\\';
    }
    widePath += L'*';
    
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(widePath.c_str(), &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return result;
    }
    
    do {
        // Skip . and ..
        if (wcscmp(findData.cFileName, L".") == 0 || 
            wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }
        
        result.push_back(WideToUtf8(findData.cFileName));
    } while (FindNextFileW(hFind, &findData));
    
    FindClose(hFind);
    return result;
}

bool IsDirectory(const char* path) {
    return DirectoryExists(path);
}

bool IsFile(const char* path) {
    return FileExists(path);
}

bool IsSymbolicLink(const char* path) {
    if (!path || !*path) return false;
    
    std::wstring widePath = Utf8ToWide(path);
    if (widePath.empty()) return false;
    
    DWORD attributes = GetFileAttributesW(widePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return false;
    
    return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

std::string GetCurrentWorkingDirectory() {
    DWORD bufferSize = GetCurrentDirectoryW(0, nullptr);
    if (bufferSize == 0) return "";
    
    std::wstring buffer(bufferSize - 1, 0);
    if (GetCurrentDirectoryW(bufferSize, buffer.data()) == 0) {
        return "";
    }
    
    return WideToUtf8(buffer.c_str());
}

bool SetCurrentWorkingDirectory(const char* path) {
    if (!path || !*path) return false;
    
    std::wstring widePath = Utf8ToWide(path);
    if (widePath.empty()) return false;
    
    return SetCurrentDirectoryW(widePath.c_str()) != 0;
}

std::string GetAbsolutePath(const char* path) {
    if (!path || !*path) return "";
    
    std::wstring widePath = Utf8ToWide(path);
    if (widePath.empty()) return "";
    
    DWORD bufferSize = GetFullPathNameW(widePath.c_str(), 0, nullptr, nullptr);
    if (bufferSize == 0) return "";
    
    std::wstring buffer(bufferSize - 1, 0);
    if (GetFullPathNameW(widePath.c_str(), bufferSize, buffer.data(), nullptr) == 0) {
        return "";
    }
    
    return WideToUtf8(buffer.c_str());
}

std::string GetFileName(const char* path) {
    if (!path || !*path) return "";
    
    const char* lastSlash = strrchr(path, '/');
    const char* lastBackslash = strrchr(path, '\\');
    
    const char* fileName = path;
    if (lastSlash && lastSlash > fileName) fileName = lastSlash + 1;
    if (lastBackslash && lastBackslash > fileName) fileName = lastBackslash + 1;
    
    return std::string(fileName);
}

std::string GetDirectoryName(const char* path) {
    if (!path || !*path) return "";
    
    std::string absPath = GetAbsolutePath(path);
    if (absPath.empty()) return "";
    
    // Remove trailing slashes
    while (!absPath.empty() && 
           (absPath.back() == '/' || absPath.back() == '\\')) {
        absPath.pop_back();
    }
    
    size_t lastSlash = absPath.find_last_of("/\\");
    if (lastSlash == std::string::npos) return "";
    
    return absPath.substr(0, lastSlash);
}

std::string GetFileExtension(const char* path) {
    if (!path || !*path) return "";
    
    std::string fileName = GetFileName(path);
    size_t lastDot = fileName.find_last_of('.');
    
    if (lastDot == std::string::npos || lastDot == 0) return "";
    
    return fileName.substr(lastDot + 1);
}

bool CopyFile(const char* sourcePath, const char* destPath, bool overwrite) {
    if (!sourcePath || !*sourcePath || !destPath || !*destPath) return false;
    
    std::wstring wideSource = Utf8ToWide(sourcePath);
    std::wstring wideDest = Utf8ToWide(destPath);
    if (wideSource.empty() || wideDest.empty()) return false;
    
    return CopyFileW(wideSource.c_str(), wideDest.c_str(), !overwrite) != 0;
}

bool EnsureDirectoryExists(const char* path) {
    return CreateDirectoryRecursive(path);
}

bool RemoveDirectoryRecursive(const char* path) {
    if (!path || !*path) return false;
    
    std::wstring widePath = Utf8ToWide(path);
    if (widePath.empty()) return false;
    
    // First, delete all contents
    std::vector<std::string> entries = ListDirectory(path);
    for (const auto& entry : entries) {
        std::string fullPath = std::string(path);
        if (fullPath.back() != '/' && fullPath.back() != '\\') {
            fullPath += '\\';
        }
        fullPath += entry;
        
        if (IsDirectory(fullPath.c_str())) {
            RemoveDirectoryRecursive(fullPath.c_str());
        } else {
            DeleteFile(fullPath.c_str());
        }
    }
    
    // Then remove the directory itself
    return RemoveDirectoryW(widePath.c_str()) != 0;
}

}} // namespace RawrXD::Core
