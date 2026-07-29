#ifndef RAWRXD_CORE_FILE_IO_H
#define RAWRXD_CORE_FILE_IO_H
#include "core_export.h"
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD { namespace Core {

// Basic file existence checks
RAWRXD_CORE_EXPORT bool FileExists(const char* path);
RAWRXD_CORE_EXPORT bool DirectoryExists(const char* path);

// Directory operations
RAWRXD_CORE_EXPORT bool CreateDirectoryRecursive(const char* path);
RAWRXD_CORE_EXPORT bool EnsureDirectoryExists(const char* path);
RAWRXD_CORE_EXPORT bool RemoveDirectoryRecursive(const char* path);

// File operations
RAWRXD_CORE_EXPORT bool DeleteFile(const char* path);
RAWRXD_CORE_EXPORT bool RenameFile(const char* oldPath, const char* newPath);
RAWRXD_CORE_EXPORT bool CopyFile(const char* sourcePath, const char* destPath, bool overwrite = true);

// File information
RAWRXD_CORE_EXPORT int64_t GetFileSize(const char* path);
RAWRXD_CORE_EXPORT bool GetFileModificationTime(const char* path, uint64_t* outTimestamp);
RAWRXD_CORE_EXPORT bool IsDirectory(const char* path);
RAWRXD_CORE_EXPORT bool IsFile(const char* path);
RAWRXD_CORE_EXPORT bool IsSymbolicLink(const char* path);

// Directory listing
RAWRXD_CORE_EXPORT std::vector<std::string> ListDirectory(const char* path);

// Path operations
RAWRXD_CORE_EXPORT std::string GetCurrentWorkingDirectory();
RAWRXD_CORE_EXPORT bool SetCurrentWorkingDirectory(const char* path);
RAWRXD_CORE_EXPORT std::string GetAbsolutePath(const char* path);
RAWRXD_CORE_EXPORT std::string GetFileName(const char* path);
RAWRXD_CORE_EXPORT std::string GetDirectoryName(const char* path);
RAWRXD_CORE_EXPORT std::string GetFileExtension(const char* path);

}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_FILE_IO_H
