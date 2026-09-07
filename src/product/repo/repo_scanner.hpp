#pragma once
#include "cpp_scan.hpp"
#include "language_detect.hpp"
#include <cstring>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr::product {

struct RepoIndex {
    std::string root;
    std::vector<std::string> files;
    std::vector<Sym> symbols;
};

inline bool SkipDirName(const char* n) {
    return !_stricmp(n, "build") || !_stricmp(n, "build-fd") ||
           !_stricmp(n, "node_modules") || !_stricmp(n, ".git") ||
           !_stricmp(n, "_deps") || !_stricmp(n, "Full Source");
}

inline void Walk(const std::string& dir, RepoIndex& idx, int maxFiles) {
#ifdef _WIN32
    std::vector<std::string> stack{dir};
    while (!stack.empty() && (int)idx.files.size() < maxFiles) {
        std::string cur = stack.back();
        stack.pop_back();
        WIN32_FIND_DATAA fd{};
        HANDLE h = FindFirstFileA((cur + "\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, ".."))
                continue;
            if (fd.cFileName[0] == '.') continue;
            std::string p = cur + "\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!SkipDirName(fd.cFileName)) stack.push_back(p);
            } else {
                const char* lang = DetectLang(p);
                if (strcmp(lang, "text") == 0) continue;
                idx.files.push_back(p);
                if (strcmp(lang, "cpp") == 0 || strcmp(lang, "c") == 0)
                    ScanCppFile(p, idx.symbols);
            }
        } while (FindNextFileA(h, &fd) && (int)idx.files.size() < maxFiles);
        FindClose(h);
    }
#else
    (void)dir;
    (void)idx;
    (void)maxFiles;
#endif
}

inline bool ScanRepo(const std::string& root, RepoIndex& idx, int maxFiles = 400) {
    idx = {};
    idx.root = root;
    Walk(root, idx, maxFiles);
    return true;
}

} // namespace rawr::product
