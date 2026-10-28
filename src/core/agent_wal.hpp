// agent_wal.hpp — append-only agent WAL (Win32). ≤99 lines.
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawrxd {
namespace agent_wal {

inline const char* DefaultRoot() {
    return "G:\\~dev\\rawrxd\\evidence\\RAWRXD_AGENT_WAL";
}

inline uint32_t Fnv1a32(const char* s, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; ++i) { h ^= (uint8_t)s[i]; h *= 16777619u; }
    return h;
}

inline bool EnsureRoot(const char* root) {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    return CreateDirectoryA(root, nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
#else
    (void)root; return false;
#endif
}

// Line: seq\top\tpayload\tCRC32\n  (CRC over "seq\top\tpayload")
inline bool Append(const char* root, uint64_t seq, const char* op, const char* payload) {
    if (!root || !op || !payload || !EnsureRoot(root)) return false;
#ifdef _WIN32
    char path[520], body[700], line[780];
    std::snprintf(path, sizeof(path), "%s\\agent.wal", root);
    int bl = std::snprintf(body, sizeof(body), "%llu\t%s\t%s",
                           (unsigned long long)seq, op, payload);
    if (bl <= 0 || bl >= (int)sizeof(body)) return false;
    int ll = std::snprintf(line, sizeof(line), "%s\t%08X\n", body, Fnv1a32(body, (size_t)bl));
    if (ll <= 0 || ll >= (int)sizeof(line)) return false;
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA | SYNCHRONIZE, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, line, (DWORD)ll, &wr, nullptr) && wr == (DWORD)ll;
    if (ok) ok = FlushFileBuffers(h);
    CloseHandle(h);
    return ok != 0;
#else
    return false;
#endif
}

// Count CRC-valid lines; return count or -1 on I/O/parse failure.
inline int VerifyAll(const char* root) {
    if (!root) return -1;
#ifdef _WIN32
    char path[520];
    std::snprintf(path, sizeof(path), "%s\\agent.wal", root);
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return -1;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (1 << 20)) {
        CloseHandle(h); return -1;
    }
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)sz.QuadPart + 1);
    if (!buf) { CloseHandle(h); return -1; }
    DWORD rd = 0;
    BOOL rok = ReadFile(h, buf, (DWORD)sz.QuadPart, &rd, nullptr);
    CloseHandle(h);
    if (!rok) { HeapFree(GetProcessHeap(), 0, buf); return -1; }
    buf[rd] = 0;
    int okc = 0;
    for (char* p = buf; *p; ) {
        char* nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n == 0) { if (!nl) break; p = nl + 1; continue; }
        char tmp[780];
        if (n >= sizeof(tmp)) { okc = -1; break; }
        memcpy(tmp, p, n); tmp[n] = 0;
        char* tab = strrchr(tmp, '\t');
        if (!tab) { okc = -1; break; }
        *tab = 0;
        unsigned got = 0;
        if (sscanf_s(tab + 1, "%08X", &got) != 1) { okc = -1; break; }
        if (got != Fnv1a32(tmp, strlen(tmp))) { okc = -1; break; }
        ++okc;
        if (!nl) break;
        p = nl + 1;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return okc;
#else
    return -1;
#endif
}

} // namespace agent_wal
} // namespace rawrxd
