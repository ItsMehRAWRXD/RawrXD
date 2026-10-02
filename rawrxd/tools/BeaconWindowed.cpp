// RAWRXD_BEACON_WINDOWED_002
//
// Certificate B, take 2. The whole-file view is what let the working set climb
// to 9.88 GB. Two separate mechanisms, and only one of them bounds physical
// residency:
//
//   WINDOWED VIEW   MapViewOfFile per 512 KiB at a file offset, Unmap after.
//                   Bounds VIRTUAL ADDRESS SPACE only. Unmapped pages go to
//                   standby and stay there; the working set can still climb
//                   because the OS has no reason to trim.
//   HARD WS CAP     SetProcessWorkingSetSizeEx(..., QUOTA_LIMITS_HARDWS_MAX_ENABLE)
//                   or a Job Object with JOB_OBJECT_LIMIT_WORKINGSET. This is the
//                   only thing that bounds PHYSICAL residency.
//
// This runs the same hostile shuffled traversal under both and reports the peak
// working set, so the difference is measured rather than asserted.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <functional>
#include <numeric>
#include <random>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")

struct Range { std::uint64_t off, len; };
struct Mem { std::uint64_t ws = 0, priv = 0, va = 0; };

static Mem probe() {
    Mem m;
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
    m.ws = pmc.WorkingSetSize;
    m.priv = pmc.PrivateUsage;
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    m.va = ms.ullAvailVirtual;
    return m;
}

static std::uint64_t g_peakWs = 0, g_peakPriv = 0;
static void sample(const Mem& m0) {
    const Mem m = probe();
    if (m.ws > g_peakWs) g_peakWs = m.ws;
    if (m.priv > g_peakPriv) g_peakPriv = m.priv;
    (void)m0;
}

// ---- GGUF tensor table -> ranges -------------------------------------------
static bool loadRanges(const char* path, std::uint64_t* fileSize,
                       std::vector<Range>& out) {
    std::FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    char magic[4] = {}; std::uint32_t ver = 0; std::uint64_t nt = 0, nkv = 0;
    if (std::fread(magic, 1, 4, f) != 4) { std::fclose(f); return false; }
    std::fread(&ver, 4, 1, f); std::fread(&nt, 8, 1, f); std::fread(&nkv, 8, 1, f);
    auto rdstr = [&](std::string& s) -> bool {
        std::uint64_t n = 0; if (std::fread(&n, 8, 1, f) != 1) return false;
        s.resize(n); return !n || std::fread(&s[0], 1, n, f) == n; };
    std::function<bool(std::uint32_t)> skip = [&](std::uint32_t t) -> bool {
        switch (t) {
            case 0: case 1: case 7: return std::fseek(f, 1, SEEK_CUR) == 0;
            case 2: case 3: return std::fseek(f, 2, SEEK_CUR) == 0;
            case 4: case 5: case 6: return std::fseek(f, 4, SEEK_CUR) == 0;
            case 10: case 11: case 12: return std::fseek(f, 8, SEEK_CUR) == 0;
            case 8: { std::string s; return rdstr(s); }
            case 9: { std::uint32_t et = 0; std::uint64_t c = 0;
                if (std::fread(&et, 4, 1, f) != 1 || std::fread(&c, 8, 1, f) != 1) return false;
                for (std::uint64_t i = 0; i < c; ++i) if (!skip(et)) return false;
                return true; }
            default: return false; } };
    for (std::uint64_t i = 0; i < nkv; ++i) {
        std::string k; std::uint32_t t = 0;
        if (!rdstr(k) || std::fread(&t, 4, 1, f) != 1 || !skip(t)) { std::fclose(f); return false; } }
    const long long tableEnd = _ftelli64(f);   // record position, do NOT seek yet
    const std::uint64_t dataStart = std::uint64_t(((tableEnd + 31) / 32) * 32);
    // Parse the tensor table from the current position FIRST; seeking to EOF for
    // the file size before this is what broke the earlier build.
    for (std::uint64_t i = 0; i < nt; ++i) {
        std::string nm; std::uint32_t nd = 0, ty = 0; std::uint64_t off = 0;
        if (!rdstr(nm) || std::fread(&nd, 4, 1, f) != 1) { std::fclose(f); return false; }
        for (std::uint32_t d = 0; d < nd; ++d) { std::uint64_t dim = 0;
            if (std::fread(&dim, 8, 1, f) != 1) { std::fclose(f); return false; } }
        if (std::fread(&ty, 4, 1, f) != 1 || std::fread(&off, 8, 1, f) != 1) { std::fclose(f); return false; }
        out.push_back(Range{dataStart + off, 0});
    }
    std::fseek(f, 0, SEEK_END);
    *fileSize = std::uint64_t(_ftelli64(f));
    std::fclose(f);
    for (std::size_t i = 0; i + 1 < out.size(); ++i) out[i].len = out[i + 1].off - out[i].off;
    if (!out.empty()) out.back().len = *fileSize - out.back().off;
    return true;
}

// ---- traversal variants -----------------------------------------------------
static std::uint64_t traverseWholeFile(const std::uint8_t* base, std::uint64_t size,
                                       const std::vector<std::size_t>& order,
                                       const std::vector<Range>& r,
                                       std::uint64_t window, std::uint64_t& cks) {
    std::uint64_t n = 0;
    for (std::size_t k = 0; k < order.size(); ++k) {
        for (std::uint64_t o = 0; o < r[order[k]].len; o += window) {
            const std::uint64_t take = std::min(window, r[order[k]].len - o);
            const std::uint8_t* p = base + r[order[k]].off + o;
            for (std::uint64_t j = 0; j < take; j += 64) cks += p[j];
            n += take;
        }
        sample(probe());
    }
    (void)size;
    return n;
}

static std::uint64_t traverseWindowed(HANDLE hm, std::uint64_t fileSize,
                                     const std::vector<std::size_t>& order,
                                     const std::vector<Range>& r,
                                     std::uint64_t window, std::uint64_t& cks,
                                     std::uint64_t* peakViewBytes) {
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    const std::uint64_t gran = si.dwAllocationGranularity;
    std::uint64_t peakView = 0;
    std::uint64_t n = 0;
    std::vector<std::uint8_t> hold(window + gran, 0);

    for (std::size_t k = 0; k < order.size(); ++k) {
        const Range& rr = r[order[k]];
        for (std::uint64_t o = 0; o < rr.len; o += window) {
            const std::uint64_t take = std::min(window, rr.len - o);
            const std::uint64_t want = rr.off + o;
            const std::uint64_t aligned = want & ~(gran - 1);
            const std::uint64_t delta = want - aligned;
            const std::uint64_t viewBytes = delta + take;
            std::uint8_t* v = static_cast<std::uint8_t*>(
                MapViewOfFile(hm, FILE_MAP_READ,
                              (DWORD)(aligned >> 32), (DWORD)(aligned & 0xFFFFFFFFu),
                              viewBytes));
            if (!v) { std::printf("  view failed at off=%llu err=%lu\n",
                                  (unsigned long long)want, GetLastError()); continue; }
            peakView = std::max(peakView, viewBytes);
            const std::uint8_t* p = v + delta;
            for (std::uint64_t j = 0; j < take; j += 64) cks += p[j];
            UnmapViewOfFile(v);
            n += take;
        }
        sample(probe());
    }
    (void)fileSize; (void)hold;
    if (peakViewBytes) *peakViewBytes = peakView;
    return n;
}

int main(int argc, char** argv) {
    if (argc < 2) { std::printf("usage: %s <model.gguf> [window_bytes] [cap_MB]\n", argv[0]); return 1; }
    const std::uint64_t window = (argc > 2) ? std::strtoull(argv[2], nullptr, 10) : (512ull * 1024);
    const std::uint64_t capMB = (argc > 3) ? std::strtoull(argv[3], nullptr, 10) : 0;

    std::vector<Range> ranges; std::uint64_t fileSize = 0;
    if (!loadRanges(argv[1], &fileSize, ranges)) { std::printf("GGUF_PARSE_FAILED\n"); return 1; }

    std::printf("RAWRXD_BEACON_WINDOWED_002\n");
    std::printf("model %s\n  tensors %zu  bytes %llu  window %llu  cap %llu MB\n\n",
                argv[1], ranges.size(), (unsigned long long)fileSize,
                (unsigned long long)window, (unsigned long long)capMB);

    HANDLE hf = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    HANDLE hm = CreateFileMappingA(hf, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hm) { std::printf("MAPPING_FAILED\n"); return 1; }

    std::vector<std::size_t> order(ranges.size());
    std::iota(order.begin(), order.end(), std::size_t(0));
    std::mt19937_64 rng(0xB34C05A11ULL);
    std::shuffle(order.begin(), order.end(), rng);

    std::uint64_t cks1 = 0, cks2 = 0;

    // ---------- PHASE A: whole-file view, no cap (the current server) ------
    {
        std::uint8_t* base = static_cast<std::uint8_t*>(MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0));
        if (!base) { std::printf("WHOLE_VIEW_FAILED\n"); return 1; }
        const Mem m0 = probe();
        g_peakWs = 0; g_peakPriv = 0;
        std::printf("PHASE A  whole-file view, no cap\n");
        std::printf("  before  ws=%.2f MB  priv=%.2f MB\n",
                    m0.ws / 1048576.0, m0.priv / 1048576.0);
        traverseWholeFile(base, fileSize, order, ranges, window, cks1);
        const Mem m1 = probe();
        std::printf("  after   ws=%.2f MB  priv=%.2f MB  PEAK_WS=%.2f MB  PEAK_PRIV_DELTA=%.3f MB\n",
                    m1.ws / 1048576.0, m1.priv / 1048576.0,
                    g_peakWs / 1048576.0, (double(g_peakPriv) - m0.priv) / 1048576.0);
        UnmapViewOfFile(base);
        std::printf("  A_WORKING_SET_BOUNDED=%s\n\n",
                    g_peakWs < 64ull * 1048576 ? "YES" : "NO");
    }

    // ---------- PHASE B: windowed views, same traversal --------------------
    {
        std::uint64_t peakView = 0;
        const Mem m0 = probe();
        g_peakWs = 0; g_peakPriv = 0;
        std::printf("PHASE B  windowed views (map %llu B at a time, unmap after)\n",
                    (unsigned long long)window);
        traverseWindowed(hm, fileSize, order, ranges, window, cks2, &peakView);
        const Mem m1 = probe();
        std::printf("  after   ws=%.2f MB  priv=%.2f MB  PEAK_WS=%.2f MB  PEAK_VIEW=%.2f MB\n",
                    m1.ws / 1048576.0, m1.priv / 1048576.0,
                    g_peakWs / 1048576.0, peakView / 1048576.0);
        std::printf("  B_VIRTUAL_VIEW_BOUNDED=YES (peak view %.2f MB, never whole model)\n",
                    peakView / 1048576.0);
        std::printf("  B_WORKING_SET_BOUNDED=%s  <-- UnmapViewOfFile does NOT evict\n\n",
                    g_peakWs < 64ull * 1048576 ? "YES" : "NO");
    }

    // ---------- PHASE C: windowed views + hard working-set cap -----------
    if (capMB) {
        const SIZE_T cap = SIZE_T(capMB) * 1024 * 1024;
        if (!SetProcessWorkingSetSizeEx(GetCurrentProcess(), 64 * 1024 * 1024, cap,
                                        QUOTA_LIMITS_HARDWS_MAX_ENABLE))
            std::printf("  CAP_SET_FAILED err=%lu\n", GetLastError());
        else std::printf("PHASE C  windowed views + hard WS cap %llu MB\n",
                         (unsigned long long)capMB);
        std::uint64_t peakView = 0, cks3 = 0;
        const Mem m0 = probe();
        g_peakWs = 0; g_peakPriv = 0;
        traverseWindowed(hm, fileSize, order, ranges, window, cks3, &peakView);
        const Mem m1 = probe();
        std::printf("  after   ws=%.2f MB  priv=%.2f MB  PEAK_WS=%.2f MB  PEAK_VIEW=%.2f MB\n",
                    m1.ws / 1048576.0, m1.priv / 1048576.0,
                    g_peakWs / 1048576.0, peakView / 1048576.0);
        std::printf("  C_CHECKSUM_MATCHES_A=%d  (bytes still served correctly under cap: %d)\n",
                    cks3 == cks1 ? 1 : 0, cks3 == cks1 ? 1 : 0);
        std::printf("  C_WORKING_SET_CAPPED=%s (cap %llu MB, peak %.2f MB)\n\n",
                    g_peakWs <= cap ? "YES" : "NO",
                    (unsigned long long)capMB, g_peakWs / 1048576.0);
    }

    CloseHandle(hm); CloseHandle(hf);
    return 0;
}
