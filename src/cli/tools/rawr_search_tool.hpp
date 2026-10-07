#pragma once
#include "../rawr_safety_policy.hpp"
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
namespace rawr {
inline int ToolSearchFiles(const SafetyPolicy& p, const std::string& ws,
                           const std::string& pattern, std::string& report) {
    if (!p.mayRead()) return 0;
    int hits = 0;
#ifdef _WIN32
    std::string pat = ws + "\\" + pattern;
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) { report = "0 hits"; return 0; }
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            ++hits;
            report += fd.cFileName;
            report += "\n";
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    (void)pattern; report = "unsupported";
#endif
    return hits;
}
} // namespace rawr
