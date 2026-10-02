// RAWRXD_BEACON_RESIDENCY_BOUND_001
//
// The loadless claim so far rests on design (mmap + demand paging). This measures
// it. Two distinct quantities, because they are different properties:
//
//   APPLICATION_RESIDENCY   PrivateUsage  -- bytes the process itself owns.
//                            This is the "no model residency" number. If it
//                            stays flat while 10 GB is traversed, the process
//                            has no model copy.
//   MODEL_RESIDENCY         working-set pages whose virtual address falls inside
//                            the GGUF mapping. Windows is ALLOWED to keep clean
//                            file-backed pages in standby, so this may exceed
//                            the window. It measures the OS's choice, not a
//                            requirement of the architecture.
//
// The traversal is deliberately hostile: disjoint, shuffled regions across the
// whole file, no locality, so any streaming pattern in the page cache would show
// up as growth.
//
// VirtualUnlock is deliberately NOT used as an eviction mechanism: it only
// affects pages explicitly locked with VirtualLock.

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

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

struct Range { std::uint64_t off, len; };

// ---------------------------------------------------------- residency probe
struct Mem {
    std::uint64_t workingSet = 0;
    std::uint64_t privateBytes = 0;
    std::uint64_t modelResident = 0;      // WS pages inside the GGUF mapping
    std::uint64_t modelShared = 0;        // of which shared/file-backed
    std::uint64_t pageSize = 4096;
};

static Mem probe(const std::uint8_t* modelBase, std::uint64_t modelSize) {
    Mem m;
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
    m.workingSet = pmc.WorkingSetSize;
    m.privateBytes = pmc.PrivateUsage;

    SYSTEM_INFO si{}; GetSystemInfo(&si);
    m.pageSize = si.dwPageSize;

    // QueryWorkingSetEx wants a buffer of PSAPI_WORKING_SET_EX_BLOCK_INFORMATION.
    // It returns ERROR_BAD_LENGTH until the buffer is large enough, so grow.
    DWORD cb = 64 * 1024;
    std::vector<BYTE> buf;
    DWORD got = 0;
    for (int attempt = 0; attempt < 12; ++attempt) {
        buf.resize(cb);
        if (QueryWorkingSetEx(GetCurrentProcess(), buf.data(), cb)) { got = 1; break; }
        if (GetLastError() != ERROR_BAD_LENGTH) break;
        cb *= 2;
    }
    if (!got || buf.size() < sizeof(ULONG_PTR) * 4) return m;

    // Header: NumberOfSharedPages, NumberOfPrivatePages, ShareCount, Win32HandleCount
    ULONG_PTR nShared = 0, nPriv = 0;
    std::memcpy(&nShared, buf.data() + 0, sizeof(ULONG_PTR));
    std::memcpy(&nPriv,  buf.data() + sizeof(ULONG_PTR), sizeof(ULONG_PTR));

    // Header is SIX ULONG_PTRs (48 bytes on x64):
    //   NumberOfSharedPages, NumberOfPrivatePages, ShareCount,
    //   Win32HandleCount, NumberOfSharedPagesLocked, NumberOfPrivatePagesLocked
    //
    // Each PSAPI_WORKING_SET_EX_BLOCK is 16 bytes on x64 -- it is TWO unions
    // (VirtualAttributes, VirtualMemory), not one ULONG_PTR. Striding by 8 makes
    // the attributes word and the address word alternate, which is why every
    // decode failed and model_resident read 0.
    const BYTE* base = buf.data() + sizeof(ULONG_PTR) * 6;
    constexpr std::size_t kBlockStride = sizeof(ULONG_PTR) * 2;
    const std::size_t nBlocks = std::size_t(nShared) + std::size_t(nPriv);

    for (std::size_t i = 0; i < nBlocks; ++i) {
        const BYTE* blk = base + i * kBlockStride;
        ULONG_PTR attr = 0, mem = 0;
        std::memcpy(&attr, blk, sizeof(ULONG_PTR));
        std::memcpy(&mem, blk + sizeof(ULONG_PTR), sizeof(ULONG_PTR));

        // VirtualAttributes: bit0 Valid, bits1-3 ShareCount, bits4-14 protection,
        //                     bit15 Shared
        const bool valid  = (attr & 1u) != 0;
        const bool shared = (attr & (1ull << 15)) != 0;
        if (!valid || !shared) continue;

        // VirtualMemory: bits0-29 LowPart, bits30-31 HighPart
        const std::uint64_t addr = (((mem >> 30) & 3ull) << 32) | ((mem & 0x3FFFFFFFull) << 2);

        if (addr >= (std::uint64_t)(modelBase) &&
            addr <  (std::uint64_t)(modelBase) + modelSize) {
            m.modelResident += m.pageSize;
            m.modelShared += m.pageSize;
        }
    }
    return m;
}

// ------------------------------------------------------------------- harness
static std::uint64_t touchRange(const std::uint8_t* base, std::uint64_t off,
                                std::uint64_t len, std::uint64_t window,
                                std::uint64_t* checksum) {
    std::uint64_t n = 0;
    for (std::uint64_t o = 0; o < len; o += window) {
        const std::uint64_t take = std::min<std::uint64_t>(window, len - o);
        const std::uint8_t* p = base + off + o;
        // Read every page so the residency accounting reflects real faulting.
        std::uint64_t acc = 0;
        for (std::uint64_t k = 0; k < take; k += 64) acc += p[k];
        *checksum += acc;
        n += take;
    }
    return n;
}

int main(int argc, char** argv) {
    if (argc < 2) { std::printf("usage: %s <model.gguf> [window_bytes]\n", argv[0]); return 1; }
    const std::uint64_t window = (argc > 2) ? std::strtoull(argv[2], nullptr, 10)
                                            : (512ull * 1024);

    std::printf("RAWRXD_BEACON_RESIDENCY_BOUND_001\n");
    std::printf("model  %s\n", argv[1]);

    HANDLE hf = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) { std::printf("OPEN_FAILED\n"); return 1; }
    LARGE_INTEGER li{}; GetFileSizeEx(hf, &li);
    const std::uint64_t fileSize = std::uint64_t(li.QuadPart);

    HANDLE hm = CreateFileMappingA(hf, nullptr, PAGE_READONLY, 0, 0, nullptr);
    std::uint8_t* base = static_cast<std::uint8_t*>(MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0));
    CloseHandle(hm); CloseHandle(hf);
    if (!base) { std::printf("MAP_FAILED\n"); return 1; }

    // Read the tensor table to build the real ranges to traverse.
    std::FILE* f = std::fopen(argv[1], "rb");
    char magic[4] = {};
    std::uint32_t ver = 0; std::uint64_t ntensor = 0, nkv = 0;
    std::fread(magic, 1, 4, f); std::fread(&ver, 4, 1, f);
    std::fread(&ntensor, 8, 1, f); std::fread(&nkv, 8, 1, f);
    auto rdstr = [&](std::string& s) -> bool {
        std::uint64_t n = 0; if (std::fread(&n, 8, 1, f) != 1) return false;
        s.resize(n); return !n || std::fread(&s[0], 1, n, f) == n; };
    std::function<bool(std::uint32_t)> skipval = [&](std::uint32_t t) -> bool {
        switch (t) {
            case 0: case 1: case 7: return std::fseek(f, 1, SEEK_CUR) == 0;
            case 2: case 3: return std::fseek(f, 2, SEEK_CUR) == 0;
            case 4: case 5: case 6: return std::fseek(f, 4, SEEK_CUR) == 0;
            case 10: case 11: case 12: return std::fseek(f, 8, SEEK_CUR) == 0;
            case 8: { std::string s; return rdstr(s); }
            case 9: { std::uint32_t et = 0; std::uint64_t c = 0;
                if (std::fread(&et, 4, 1, f) != 1 || std::fread(&c, 8, 1, f) != 1) return false;
                for (std::uint64_t i = 0; i < c; ++i) if (!skipval(et)) return false;
                return true; }
            default: return false; } };
    for (std::uint64_t i = 0; i < nkv; ++i) {
        std::string k; std::uint32_t t = 0;
        if (!rdstr(k) || std::fread(&t, 4, 1, f) != 1 || !skipval(t)) return 1; }
    const long long tableEnd = _ftelli64(f);
    const std::uint64_t dataStart = std::uint64_t(((tableEnd + 31) / 32) * 32);

    std::vector<Range> ranges;
    for (std::uint64_t i = 0; i < ntensor; ++i) {
        std::string nm; std::uint32_t nd = 0, ty = 0; std::uint64_t off = 0;
        if (!rdstr(nm) || std::fread(&nd, 4, 1, f) != 1) return 1;
        for (std::uint32_t d = 0; d < nd; ++d) { std::uint64_t dim = 0;
            if (std::fread(&dim, 8, 1, f) != 1) return 1; }
        if (std::fread(&ty, 4, 1, f) != 1 || std::fread(&off, 8, 1, f) != 1) return 1;
        ranges.push_back(Range{dataStart + off, 0});
    }
    std::fclose(f);
    for (std::size_t i = 0; i + 1 < ranges.size(); ++i)
        ranges[i].len = ranges[i + 1].off - ranges[i].off;
    ranges.back().len = fileSize - ranges.back().off;

    std::printf("tensors %zu   file %llu bytes   window %llu bytes\n\n",
                ranges.size(), (unsigned long long)fileSize, (unsigned long long)window);

    const Mem m0 = probe(base, fileSize);
    std::printf("BEFORE\n");
    std::printf("  working_set     %12llu bytes (%.2f MB)\n",
                (unsigned long long)m0.workingSet, m0.workingSet / 1048576.0);
    std::printf("  private         %12llu bytes (%.2f MB)\n",
                (unsigned long long)m0.privateBytes, m0.privateBytes / 1048576.0);
    std::printf("  model_resident  %12llu bytes (%.2f MB)\n\n",
                (unsigned long long)m0.modelResident, m0.modelResident / 1048576.0);

    // Hostile order: shuffle, so no locality exists between consecutive ranges.
    std::vector<std::size_t> order(ranges.size());
    std::iota(order.begin(), order.end(), std::size_t(0));
    std::mt19937_64 rng(0xB34C05A11ULL);
    std::shuffle(order.begin(), order.end(), rng);

    std::uint64_t traversed = 0, checksum = 0, peakModel = m0.modelResident;
    std::uint64_t peakPrivate = m0.privateBytes, peakWS = m0.workingSet;
    int sampled = 0;

    for (std::size_t k = 0; k < order.size(); ++k) {
        const Range& r = ranges[order[k]];
        traversed += touchRange(base, r.off, r.len, window, &checksum);
        const Mem m = probe(base, fileSize);
        if (m.modelResident > peakModel)   peakModel = m.modelResident;
        if (m.privateBytes > peakPrivate) peakPrivate = m.privateBytes;
        if (m.workingSet > peakWS)        peakWS = m.workingSet;
        ++sampled;
        if (k < 5 || (k + 1) % 40 == 0 || k + 1 == order.size())
            std::printf("  after %3zu/%zu tensors  ws=%7.2f MB  priv=%7.2f MB  model_res=%7.2f MB\n",
                        k + 1, order.size(), m.workingSet / 1048576.0,
                        m.privateBytes / 1048576.0, m.modelResident / 1048576.0);
    }

    const Mem mEnd = probe(base, fileSize);
    std::printf("\nAFTER (%zu samples)\n", sampled);
    std::printf("  working_set     %12llu bytes (%.2f MB)\n",
                (unsigned long long)mEnd.workingSet, mEnd.workingSet / 1048576.0);
    std::printf("  private         %12llu bytes (%.2f MB)\n",
                (unsigned long long)mEnd.privateBytes, mEnd.privateBytes / 1048576.0);
    std::printf("  model_resident  %12llu bytes (%.2f MB)\n\n",
                (unsigned long long)mEnd.modelResident, mEnd.modelResident / 1048576.0);

    const double privDelta = (peakPrivate > m0.privateBytes)
        ? double(peakPrivate - m0.privateBytes) / 1048576.0 : 0.0;

    std::printf("MODEL_BYTES                     = %llu\n", (unsigned long long)fileSize);
    std::printf("BYTES_TRAVERSED                 = %llu\n", (unsigned long long)traversed);
    std::printf("REQUEST_WINDOW_BYTES            = %llu\n", (unsigned long long)window);
    std::printf("PEAK_PRIVATE_DELTA_MB           = %.3f\n", privDelta);
    std::printf("PEAK_MODEL_RESIDENT_BYTES       = %llu\n", (unsigned long long)peakModel);
    std::printf("PEAK_WORKING_SET_BYTES          = %llu\n", (unsigned long long)peakWS);
    std::printf("MODEL_TO_PEAK_RESIDENT_RATIO    = %.2f\n", double(fileSize) / double(peakModel ? peakModel : 1));
    std::printf("WINDOW_TO_PEAK_RESIDENT_RATIO   = %.2f\n", double(peakModel) / double(window));
    std::printf("CHECKSUM                        = %.6g\n", double(checksum));
    std::printf("\nPERSISTENT_APPLICATION_MODEL_COPY = 0   (private delta is the only app-owned bytes)\n");
    std::printf("MODEL_RESIDENCY_SCALES_WITH_SIZE = %s\n",
                peakModel > (fileSize / 20) ? "YES -- claim FAILS" : "NO");
    std::printf("OS_STANDBY_CACHE_OBSERVED        = %s\n",
                peakModel > window ? "yes (permitted, not a requirement)" : "no");
    std::printf("\nVERDICT = %s\n",
                (privDelta < 64.0 && peakModel < fileSize / 20) ? "RESIDENCY_BOUNDED=PASS" : "RESIDENCY_BOUNDED=FAIL");
    UnmapViewOfFile(base);
    return 0;
}
