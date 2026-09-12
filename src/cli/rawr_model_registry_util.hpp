// rawr_model_registry_util.hpp — cheap id / quant / file helpers
#pragma once
#include "rawr_model_registry.hpp"
#include "../deep2/RawrModelDiscover.hpp"
#include "../deep2/GgufModelPath.hpp"
#include <cstdio>
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr {
namespace regutil {

inline uint64_t Fnv1a64(const char* s, uint64_t seed = 14695981039346656037ull) {
    uint64_t h = seed;
    if (!s) return h;
    for (const unsigned char* p = (const unsigned char*)s; *p; ++p) {
        h ^= (uint64_t)*p;
        h *= 1099511628211ull;
    }
    return h;
}

inline std::string CheapId(const char* path, uint64_t size, uint64_t mtime) {
    char buf[96];
    uint64_t h = Fnv1a64(path);
    h ^= size + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
    h ^= mtime + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
    std::snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)h);
    return buf;
}

inline std::string GuessQuant(const char* name) {
    if (!name) return {};
    static const char* q[] = {"Q8_0", "Q6_K", "Q5_K_M", "Q5_K_S", "Q4_K_M",
                              "Q4_K_S", "Q3_K_M", "Q3_K_S", "Q2_K", "IQ4_XS",
                              "F16", "BF16", "FP16"};
    for (const char* t : q) {
        if (std::strstr(name, t)) return t;
    }
    return {};
}

inline bool FileStat(const char* path, uint64_t& size, uint64_t& mtime) {
    size = mtime = 0;
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) return false;
    ULARGE_INTEGER u;
    u.HighPart = fad.nFileSizeHigh;
    u.LowPart = fad.nFileSizeLow;
    size = u.QuadPart;
    ULARGE_INTEGER t;
    t.LowPart = fad.ftLastWriteTime.dwLowDateTime;
    t.HighPart = fad.ftLastWriteTime.dwHighDateTime;
    mtime = t.QuadPart;
    return true;
#else
    (void)path;
    return false;
#endif
}

inline uint64_t DirShardBytes(const char* dir, uint32_t& count) {
    count = 0;
    uint64_t total = 0;
#ifdef _WIN32
    char pat[MAX_PATH];
    std::snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        const char* ext = std::strrchr(fd.cFileName, '.');
        if (!ext || _stricmp(ext, ".gguf") != 0) continue;
        int idx = 0, tot = 0;
        if (!Deep2::rawr_run::ParseShardOf(fd.cFileName, idx, tot)) continue;
        ULARGE_INTEGER u;
        u.HighPart = fd.nFileSizeHigh;
        u.LowPart = fd.nFileSizeLow;
        total += u.QuadPart;
        ++count;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    (void)dir;
#endif
    return total;
}

} // namespace regutil
} // namespace rawr
