#pragma once
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
namespace rawr::product {

inline bool OpenWorkspace(const std::string& path) {
#ifdef _WIN32
    if (path.empty()) return false;
    DWORD a = GetFileAttributesA(path.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) return false;
    return (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
    (void)path;
    return false;
#endif
}

inline bool openWorkspace(const std::string& path) { return OpenWorkspace(path); }

} // namespace rawr::product
