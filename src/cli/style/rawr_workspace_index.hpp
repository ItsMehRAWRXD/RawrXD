// rawr_workspace_index.hpp — lightweight path index (no deps)
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

struct WorkspaceIndex {
    std::string root;
    std::vector<std::string> files;

    bool build(const std::string& workspace, int maxFiles = 2000) {
        root = workspace;
        files.clear();
#ifdef _WIN32
        std::vector<std::string> stack;
        stack.push_back(workspace);
        while (!stack.empty() && (int)files.size() < maxFiles) {
            std::string dir = stack.back();
            stack.pop_back();
            std::string pat = dir + "\\*";
            WIN32_FIND_DATAA fd{};
            HANDLE h = FindFirstFileA(pat.c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) continue;
            do {
                if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, ".."))
                    continue;
                if (fd.cFileName[0] == '.') continue;
                std::string path = dir + "\\" + fd.cFileName;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (!_stricmp(fd.cFileName, "build-fd") ||
                        !_stricmp(fd.cFileName, "node_modules") ||
                        !_stricmp(fd.cFileName, ".git"))
                        continue;
                    stack.push_back(path);
                } else {
                    files.push_back(path);
                }
            } while (FindNextFileA(h, &fd) && (int)files.size() < maxFiles);
            FindClose(h);
        }
#endif
        return !files.empty() || true;
    }

    std::vector<std::string> findSuffix(const char* suf, int limit = 32) const {
        std::vector<std::string> out;
        size_t n = strlen(suf);
        for (const auto& f : files) {
            if (f.size() >= n && _stricmp(f.c_str() + f.size() - n, suf) == 0) {
                out.push_back(f);
                if ((int)out.size() >= limit) break;
            }
        }
        return out;
    }
};

} // namespace rawr::style
