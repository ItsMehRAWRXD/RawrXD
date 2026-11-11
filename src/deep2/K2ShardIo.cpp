// K2ShardIo.cpp — keep shard HANDLEs open across tensor loads
#include "K2ShardIo.hpp"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace {
bool g_on = true;
uint64_t g_readCalls = 0, g_readBytes = 0, g_readUs = 0;
uint64_t g_reopen = 0, g_seeks = 0, g_mapFaults = 0, g_mapFaultUs = 0;
#ifdef _WIN32
struct ShardHandle {
    HANDLE h = INVALID_HANDLE_VALUE;
    std::mutex ioMu;
};
std::mutex g_mu;
std::unordered_map<std::string, std::unique_ptr<ShardHandle>> g_h;

uint64_t NowUs() {
    static LARGE_INTEGER f{};
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (uint64_t)((c.QuadPart * 1000000ull) / (uint64_t)f.QuadPart);
}
#endif
} // namespace

void K2ShardIo_SetEnabled(bool on) { g_on = on; }
bool K2ShardIo_Enabled() {
    const char* e = std::getenv("DEEP2_TRAMP_FAST_IO");
    if (e && e[0] == '0' && e[1] == 0) return false;
    if (e && e[0] == '1' && e[1] == 0) return true;
    return g_on;
}

void K2ShardIo_Close() {
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(g_mu);
    for (auto& kv : g_h) {
        if (kv.second && kv.second->h != INVALID_HANDLE_VALUE)
            CloseHandle(kv.second->h);
    }
    g_h.clear();
#endif
}

void K2ShardIo_ResetCounters() {
    g_readCalls = g_readBytes = g_readUs = 0;
    g_reopen = g_seeks = g_mapFaults = g_mapFaultUs = 0;
}

void K2ShardIo_Reset() {
    K2ShardIo_Close();
    K2ShardIo_ResetCounters();
}

K2ShardIoSnapshot K2ShardIo_Snapshot() {
    K2ShardIoSnapshot s;
    s.readCalls = g_readCalls;
    s.readBytes = g_readBytes;
    s.readUs = g_readUs;
    s.reopenCount = g_reopen;
    s.seekCount = g_seeks;
    s.mapFaults = g_mapFaults;
    s.mapFaultUs = g_mapFaultUs;
    return s;
}

void K2ShardIo_Emit(FILE* f) {
    if (!f) f = stdout;
    auto s = K2ShardIo_Snapshot();
    fprintf(f,
            "SHARD_IO_CALLS=%llu SHARD_IO_BYTES=%llu SHARD_IO_US=%llu "
            "SHARD_IO_REOPEN=%llu SHARD_IO_SEEKS=%llu "
            "SHARD_IO_MAPFAULT=%llu SHARD_IO_MAPFAULT_US=%llu\n",
            (unsigned long long)s.readCalls, (unsigned long long)s.readBytes,
            (unsigned long long)s.readUs, (unsigned long long)s.reopenCount,
            (unsigned long long)s.seekCount, (unsigned long long)s.mapFaults,
            (unsigned long long)s.mapFaultUs);
    fflush(f);
}

bool K2ShardIo_Read(const std::string& path, uint64_t offset, void* dst,
                    size_t n) {
    if (!dst || !n) return false;
#ifdef _WIN32
    if (!K2ShardIo_Enabled()) return false;
    const uint64_t t0 = NowUs();
    ShardHandle* sh = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        auto it = g_h.find(path);
        if (it != g_h.end()) sh = it->second.get();
        else {
            int nchars =
                MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
            if (nchars <= 0) return false;
            std::wstring w(static_cast<size_t>(nchars), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &w[0], nchars);
            HANDLE h = CreateFileW(w.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
                                   nullptr);
            if (h == INVALID_HANDLE_VALUE) {
                ++g_mapFaults;
                g_mapFaultUs += NowUs() - t0;
                return false;
            }
            auto up = std::unique_ptr<ShardHandle>(new ShardHandle());
            up->h = h;
            sh = up.get();
            g_h.emplace(path, std::move(up));
            // reopen: counted only after Close wiped the map (warm→timed leak).
            // First open of a path is not a reopen.
        }
    }
    std::lock_guard<std::mutex> ioLock(sh->ioMu);
    size_t total = 0;
    while (total < n) {
        DWORD want = (DWORD)((std::min)(n - total, (size_t)(4u << 20)));
        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)(offset + total);
        OVERLAPPED ov{};
        ov.Offset = li.LowPart;
        ov.OffsetHigh = (DWORD)li.HighPart;
        ++g_seeks;
        DWORD did = 0;
        if (!ReadFile(sh->h, (char*)dst + total, want, &did, &ov) || did == 0) {
            ++g_mapFaults;
            g_mapFaultUs += NowUs() - t0;
            return false;
        }
        total += did;
    }
    ++g_readCalls;
    g_readBytes += n;
    g_readUs += NowUs() - t0;
    return true;
#else
    (void)path;
    (void)offset;
    return false;
#endif
}

size_t K2ShardIo_WarmDirectory(const std::string& dir) {
    if (dir.empty() || !K2ShardIo_Enabled()) return 0;
    static std::string s_warmed;
    static size_t s_n = 0;
    if (s_warmed == dir && s_n > 0) return s_n;
    size_t n = 0;
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return 0;
    uint8_t probe = 0;
    for (auto& e : fs::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!e.is_regular_file()) continue;
        if (e.path().extension() != ".gguf") continue;
        if (K2ShardIo_Read(e.path().string(), 0, &probe, 1)) ++n;
    }
    s_warmed = dir;
    s_n = n;
    return n;
}

} // namespace Deep2
