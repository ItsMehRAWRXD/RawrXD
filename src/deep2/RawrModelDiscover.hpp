// RawrModelDiscover.hpp — recursive local GGUF discovery (no Ollama/network)
#pragma once
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace rawr_run {

struct LocalModelUnit {
    std::string alias;   // stem or dir name (user-facing)
    std::string path;    // file OR shard directory
    uint32_t shards = 1;
    bool isDir = false;
};

inline std::string NormKey(const char* s) {
    std::string o;
    if (!s) return o;
    for (const unsigned char* p = (const unsigned char*)s; *p; ++p) {
        char c = (char)tolower(*p);
        if (c == '/' || c == '\\') c = '-';
        if (c == ' ' || c == '_' || c == '.') c = '-';
        if (isalnum((unsigned char)c) || c == '-') o.push_back(c);
    }
    while (!o.empty() && o.back() == '-') o.pop_back();
    return o;
}

inline bool IsJunkName(const char* name) {
    if (!name || !name[0]) return true;
    std::string n = NormKey(name);
    if (n.rfind("mmproj", 0) == 0) return true;
    if (n.rfind("dummy", 0) == 0) return true;
    if (n.rfind("bench-", 0) == 0 || n == "bench-min" || n == "bench-frag")
        return true;
    if (n.rfind("test-", 0) == 0) return true;
    if (n.find("simulation") != std::string::npos) return true;
    if (n == "model" || n == "test-model" || n == "test-mock") return true;
    if (n.find("test-edge") != std::string::npos ||
        n.find("test-profile") != std::string::npos ||
        n.find("test-types") != std::string::npos ||
        n.find("test-unicode") != std::string::npos ||
        n.find("test-many-kv") != std::string::npos ||
        n.find("test-minimal") != std::string::npos)
        return true;
    return false;
}

inline bool ParseShardOf(const char* fname, int& idx, int& total) {
    idx = total = 0;
    if (!fname) return false;
    const char* p = strstr(fname, "-of-");
    if (!p || p - fname < 6) return false;
    const char* dig = p - 1;
    while (dig > fname && isdigit((unsigned char)*dig)) --dig;
    if (*dig != '-') return false;
    idx = atoi(dig + 1);
    total = atoi(p + 4);
    return idx > 0 && total > 0;
}

inline void PushUnique(std::vector<LocalModelUnit>& out, LocalModelUnit u) {
    for (const auto& e : out) {
        if (_stricmp(e.path.c_str(), u.path.c_str()) == 0) return;
    }
    out.push_back(std::move(u));
}

inline void ScanDirRecursive(const char* dir, int depth,
                             std::vector<LocalModelUnit>& out) {
#ifdef _WIN32
    if (!dir || depth > 6) return;
    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.' &&
            (fd.cFileName[1] == 0 ||
             (fd.cFileName[1] == '.' && fd.cFileName[2] == 0)))
            continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (_stricmp(fd.cFileName, ".git") == 0 ||
                _stricmp(fd.cFileName, "blobs") == 0 ||
                _stricmp(fd.cFileName, "manifests") == 0 ||
                _stricmp(fd.cFileName, "build") == 0 ||
                _stricmp(fd.cFileName, "build-fd") == 0 ||
                _stricmp(fd.cFileName, "build2") == 0 ||
                _stricmp(fd.cFileName, "build_gguf_profile_test") == 0 ||
                _stricmp(fd.cFileName, "audit_build") == 0 ||
                _stricmp(fd.cFileName, "tmp") == 0 ||
                _stricmp(fd.cFileName, "history") == 0 ||
                _stricmp(fd.cFileName, "Full_Source") == 0 ||
                _stricmp(fd.cFileName, ".archive") == 0 ||
                _stricmp(fd.cFileName, "compilers") == 0 ||
                _stricmp(fd.cFileName, "crash_dumps") == 0 ||
                _stricmp(fd.cFileName, "llama.cpp") == 0 ||
                _stricmp(fd.cFileName, "node_modules") == 0)
                continue;
            char sub[MAX_PATH];
            snprintf(sub, sizeof(sub), "%s\\%s", dir, fd.cFileName);
            ScanDirRecursive(sub, depth + 1, out);
            continue;
        }
        const char* ext = strrchr(fd.cFileName, '.');
        if (!ext || _stricmp(ext, ".gguf") != 0) continue;
        if (IsJunkName(fd.cFileName)) continue;
        int idx = 0, total = 0;
        if (ParseShardOf(fd.cFileName, idx, total)) {
            if (idx != 1) continue; // only register shard pack once
            LocalModelUnit u;
            u.isDir = true;
            u.shards = (uint32_t)total;
            u.path = dir;
            // Prefer parent-ish alias: use directory leaf name
            const char* slash = strrchr(dir, '\\');
            u.alias = slash ? (slash + 1) : dir;
            if (IsJunkName(u.alias.c_str())) continue;
            PushUnique(out, std::move(u));
            continue;
        }
        LocalModelUnit u;
        u.isDir = false;
        u.shards = 1;
        u.path = std::string(dir) + "\\" + fd.cFileName;
        u.alias = std::string(fd.cFileName, ext - fd.cFileName);
        PushUnique(out, std::move(u));
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    (void)dir;
    (void)depth;
    (void)out;
#endif
}

inline void CollectModelRoots(std::vector<std::string>& roots) {
    auto push = [&](const char* r) {
        if (!r || !r[0]) return;
#ifdef _WIN32
        DWORD a = GetFileAttributesA(r);
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY))
            roots.emplace_back(r);
#endif
    };
    if (const char* e = std::getenv("RAWRXD_MODEL_ROOT")) push(e);
    push("F:\\OllamaModels");
    push("G:\\~dev\\rawrxd\\models");
    push("G:\\~dev\\rawrxd");
    push("G:\\~dev\\rawrxd\\rawrxd_test_models");
    push("F:\\OllamaModels\\rawrxd_test_models");
}

inline void DiscoverLocalModels(std::vector<LocalModelUnit>& out) {
    out.clear();
    std::vector<std::string> roots;
    CollectModelRoots(roots);
    for (const auto& r : roots) ScanDirRecursive(r.c_str(), 0, out);
}

inline int MatchScore(const std::string& want, const LocalModelUnit& u) {
    const std::string a = NormKey(want.c_str());
    const std::string b = NormKey(u.alias.c_str());
    const std::string p = NormKey(u.path.c_str());
    if (a.empty() || b.empty()) return 0;
    if (a == b) return 1000;
    if (b.rfind(a, 0) == 0) return 800 + (int)a.size();
    if (a.rfind(b, 0) == 0) return 700 + (int)b.size();
    if (b.find(a) != std::string::npos) return 500 + (int)a.size();
    if (a.find(b) != std::string::npos) return 400 + (int)b.size();
    if (p.find(a) != std::string::npos) return 300 + (int)a.size();
    return 0;
}

inline bool DiscoverResolve(const char* alias, LocalModelUnit& best) {
    std::vector<LocalModelUnit> all;
    DiscoverLocalModels(all);
    int bestScore = 0;
    bool hit = false;
    for (const auto& u : all) {
        int s = MatchScore(alias ? alias : "", u);
        if (s > bestScore) {
            bestScore = s;
            best = u;
            hit = true;
        }
    }
    return hit && bestScore >= 300;
}

} // namespace rawr_run
} // namespace Deep2
