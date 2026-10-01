// ============================================================================
// RepositoryUniverse.cpp — RAWRXD_REPOSITORY_INTELLIGENCE_001
//
// Win32 directory enumeration. Pruned directories are descended into anyway so
// their size can be reported; that is the cost of never lying about scope.
// ============================================================================
#include "repointel/RepositoryUniverse.hpp"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace rawrxd {
namespace repointel {
namespace {

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
}

bool wildcardMatch(const char* pat, const char* str) {
    // Supports '*' and '?' only, which is all prune patterns need.
    const char* starPat = nullptr;
    const char* starStr = nullptr;
    while (*str) {
        if (*pat == '?' || *pat == *str) {
            ++pat;
            ++str;
        } else if (*pat == '*') {
            starPat = ++pat;
            starStr = str;
        } else if (starPat) {
            pat = starPat;
            ++starStr;
            str = starStr;
        } else {
            return false;
        }
    }
    while (*pat == '*') ++pat;
    return *pat == 0;
}

bool matchesAny(const std::vector<std::string>& pats, const std::string& name) {
    for (const std::string& p : pats) {
        if (wildcardMatch(p.c_str(), name.c_str())) return true;
    }
    return false;
}

std::string dirNameOf(const std::string& path) {
    const size_t cut = path.find_last_of("\\/");
    if (cut == std::string::npos) return std::string();
    return path.substr(0, cut);
}

std::string toSlashes(const std::string& p) {
    std::string s = p;
    for (char& c : s) {
        if (c == '\\') c = '/';
    }
    return s;
}

std::string relFrom(const std::string& rootSlash, const std::string& abs) {
    if (abs.size() > rootSlash.size() &&
        strncmp(abs.c_str(), rootSlash.c_str(), rootSlash.size()) == 0)
        return toSlashes(abs.substr(rootSlash.size()));
    return toSlashes(abs);
}

std::string extensionOf(const std::string& path) {
    const size_t slash = path.find_last_of("\\/");
    const size_t dot = path.find_last_of('.');
    if (dot == std::string::npos) return std::string();
    if (slash != std::string::npos && dot < slash) return std::string();
    std::string ext = path.substr(dot);
    for (char& c : ext) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return ext;
}

uint64_t fileTimeOf(const WIN32_FIND_DATAA& fd) {
    ULARGE_INTEGER u;
    u.LowPart = fd.ftLastWriteTime.dwLowDateTime;
    u.HighPart = fd.ftLastWriteTime.dwHighDateTime;
    return u.QuadPart;
}

struct Walker {
    Universe*        u = nullptr;
    std::string      rootSlash;   // trailing slash
    std::string      rootAbs;

    void addFile(const std::string& abs, const WIN32_FIND_DATAA& fd) {
        ++u->filesSeen;
        u->bytesSeen += fd.nFileSizeLow;

        const std::string rel = relFrom(rootSlash, abs);
        if (!u->policy.extensions.empty() &&
            !matchesAny(u->policy.extensions, extensionOf(rel))) {
            return;
        }
        if (u->policy.maxFiles != 0 &&
            u->files.size() >= u->policy.maxFiles) {
            ++u->truncated;
            return;
        }

        UniverseFile f;
        f.rel = rel;
        f.abs = abs;
        f.size = fd.nFileSizeLow;
        f.mtime = fileTimeOf(fd);

        std::string text;
        std::string err;
        if (readWholeFile(abs, text, &err)) {
            f.hash = contentHash(text);
            f.lineCount = 0;
            for (char c : text) {
                if (c == '\n') ++f.lineCount;
            }
            if (!text.empty() && text.back() != '\n') ++f.lineCount;
        } else {
            f.hash.clear();
            ++u->unreadable;
        }
        u->files.push_back(std::move(f));
    }

    void addPrunedStat(const std::string& abs, const WIN32_FIND_DATAA& fd,
                       PrunedDir& bucket) {
        (void)abs;
        ++bucket.filesBelow;
        bucket.bytesBelow += fd.nFileSizeLow;
    }

    void pruneTree(const std::string& dir, const std::string& rel,
                   PrunedDir& bucket) {
        const std::string pattern = dir + "\\*";
        WIN32_FIND_DATAA fd{};
        HANDLE           h = FindFirstFileA(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;
            const std::string child = dir + "\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                pruneTree(child, rel, bucket);
            } else {
                addPrunedStat(child, fd, bucket);
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }

    void walk(const std::string& dir, const std::string& rel) {
        const std::string pattern = dir + "\\*";
        WIN32_FIND_DATAA fd{};
        HANDLE           h = FindFirstFileA(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return;

        std::vector<std::string> subdirs;
        std::vector<PrunedDir>   pruneHere;
        bool                     pruneThisDir = false;

        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;
            const std::string name = fd.cFileName;
            const std::string child = dir + "\\" + name;
            const std::string childRel = rel.empty() ? name : rel + "/" + name;

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!u->policy.includeBuildTrees &&
                    matchesAny(u->policy.pruneDirPatterns, name)) {
                    PrunedDir bucket;
                    bucket.rel = childRel;
                    pruneThisDir = true;
                    pruneTree(child, childRel, bucket);
                    pruneHere.push_back(bucket);
                    continue;
                }
                subdirs.push_back(name);
                continue;
            }
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            addFile(child, fd);
        } while (FindNextFileA(h, &fd));
        FindClose(h);

        for (const PrunedDir& p : pruneHere) u->pruned.push_back(p);
        std::sort(subdirs.begin(), subdirs.end());
        for (const std::string& d : subdirs) {
            walk(dir + "\\" + d, rel.empty() ? d : rel + "/" + d);
        }
    }
};

bool directoryExists(const std::string& p) {
    const DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

}  // namespace

std::string contentHash(const void* data, size_t bytes) {
    const unsigned char* p = static_cast<const unsigned char*>(data);
    uint64_t             h = 1469598103934665603ULL;
    for (size_t i = 0; i < bytes; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    char out[17];
    std::snprintf(out, sizeof(out), "%016llx",
                  static_cast<unsigned long long>(h));
    return std::string(out, 16);
}

std::string contentHash(const std::string& text) {
    return contentHash(text.data(), text.size());
}

bool readWholeFile(const std::string& path, std::string& out, std::string* err) {
    out.clear();
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ |
                                                         FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (err) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "win32:%lu", GetLastError());
            *err = buf;
        }
        return false;
    }
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz)) {
        CloseHandle(h);
        if (err) *err = "size";
        return false;
    }
    const uint64_t n = static_cast<uint64_t>(sz.QuadPart);
    out.resize(static_cast<size_t>(n));
    uint64_t got = 0;
    while (got < n) {
        DWORD chunk = static_cast<DWORD>((n - got) > (1u << 20)
                                             ? (1u << 20)
                                             : (n - got));
        DWORD readBytes = 0;
        if (!ReadFile(h, &out[static_cast<size_t>(got)], chunk, &readBytes,
                      nullptr) ||
            readBytes == 0) {
            out.clear();
            CloseHandle(h);
            if (err) *err = "read";
            return false;
        }
        got += readBytes;
    }
    CloseHandle(h);
    return true;
}

uint32_t countLines(const std::string& path) {
    std::string text;
    if (!readWholeFile(path, text)) return 0;
    uint32_t n = 0;
    for (char c : text) {
        if (c == '\n') ++n;
    }
    if (!text.empty() && text.back() != '\n') ++n;
    return n;
}

std::string resolveRepositoryRoot(const std::string& startDir) {
    std::string dir = startDir;
    if (dir.empty()) dir = ".";
    for (int depth = 0; depth < 64; ++depth) {
        if (directoryExists(dir + "\\CMakeLists.txt")) return dir;
        const std::string parent = dirNameOf(dir);
        if (parent.empty() || parent == dir) break;
        dir = parent;
    }
    return std::string();
}

Universe buildUniverse(const UniversePolicy& policy) {
    Universe u;
    u.policy = policy;
    // A restricted walk is a narrowed scope by definition, whether or not the
    // caller remembered to say so.
    u.narrowed = policy.narrowed || !policy.restrictToRoots.empty();

    std::string root = policy.explicitRoot;
    if (root.empty()) root = resolveRepositoryRoot(policy.startDir);
    if (root.empty()) root = policy.startDir.empty() ? "." : policy.startDir;
    while (root.size() > 3 && (root.back() == '\\' || root.back() == '/'))
        root.pop_back();

    u.rootExists = directoryExists(root);

    Walker w;
    w.u = &u;
    w.rootAbs = root;
    w.rootSlash = root + "\\";

    if (u.rootExists) {
        if (policy.restrictToRoots.empty()) {
            w.walk(root, std::string());
        } else {
            // A restricted walk. Each named subtree is still walked in full and
            // its pruned subtrees are still counted, so the scope is described
            // precisely rather than merely named.
            std::vector<std::string> roots = policy.restrictToRoots;
            std::sort(roots.begin(), roots.end());
            roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
            for (const std::string& r : roots) {
                const std::string sub = root + "\\" + r;
                if (!directoryExists(sub)) continue;
                w.walk(sub, toSlashes(r));
                u.rootsIndexed.push_back(toSlashes(r));
            }
        }
        for (const std::string& extra : policy.extraRoots) {
            const std::string sub = root + "\\" + extra;
            if (directoryExists(sub)) {
                w.walk(sub, extra);
                u.rootsIndexed.push_back(toSlashes(extra));
            }
        }
    }

    u.rootsIndexed.insert(u.rootsIndexed.begin(), policy.restrictToRoots.empty()
                                                    ? std::string(".")
                                                    : std::string("<restricted>"));
    std::sort(u.rootsIndexed.begin(), u.rootsIndexed.end());
    u.rootsIndexed.erase(std::unique(u.rootsIndexed.begin(), u.rootsIndexed.end()),
                         u.rootsIndexed.end());

    std::sort(u.files.begin(), u.files.end(),
              [](const UniverseFile& a, const UniverseFile& b) {
                  return a.rel < b.rel;
              });
    u.files.erase(std::unique(u.files.begin(), u.files.end(),
                              [](const UniverseFile& a, const UniverseFile& b) {
                                  return a.rel == b.rel;
                              }),
                  u.files.end());

    std::sort(u.pruned.begin(), u.pruned.end(),
              [](const PrunedDir& a, const PrunedDir& b) {
                  return a.rel < b.rel;
              });
    return u;
}

}  // namespace repointel
}  // namespace rawrxd