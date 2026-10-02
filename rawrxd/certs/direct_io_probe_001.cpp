// ============================================================================
// direct_io_probe_001.cpp
// RAWRXD_DIRECT_IO_PROBE_001
//
// TRY IT, DON'T ARGUE IT.
//
// The architectural proposal is that mmap "builds virtual ranges and does not
// make the bytes free", and that Explicit Direct I/O into a fixed, sector-aligned
// compute arena is the only sound path for models far larger than RAM.
//
// This probe tests that premise instead of asserting it. It takes ONE real GGUF
// and measures, on this machine:
//
//   (A) mmap    : touch every page of a real tensor region (what the current
//                 loader defers to page-fault time)
//   (B) direct  : FILE_FLAG_NO_BUFFERING read of the SAME bytes into a
//                 4096-aligned arena, with sector-aligned offset and length
//
// and reports effective bandwidth for each. The proposal's own claim is that
// direct I/O wins. If it does not, that is worth knowing before the engine's
// compute core is rewritten around it.
//
// SECTOR ALIGNMENT IS NOT OPTIONAL.
//   Windows rejects an unbuffered ReadFile unless the file offset, the length
//   AND the buffer address are all multiples of the volume's sector size.
//   GGUF tensor offsets come from the metadata dictionary and are arbitrary,
//   so the real unit of transfer is an aligned BLOCK, never a tensor. This
//   probe rounds down the offset and up the length, and records the delta --
//   the same arithmetic any real direct-I/O scheduler would need.
// ============================================================================

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kSector = 4096;

struct Stat {
    double seconds = 0.0;
    uint64_t bytes = 0;
    double gbps() const { return seconds > 0 ? (bytes / (1024.0 * 1024 * 1024)) / seconds : 0.0; }
};

const char* Err(DWORD e) {
    static char buf[64];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, e, 0, buf, sizeof(buf), nullptr);
    return buf;
}

// (A) mmap, then force residency by touching every page -- the work the current
// loader defers into prefill, measured here explicitly.
Stat TimeMmapResident(const std::string& path, uint64_t offset, uint64_t length) {
    Stat s;
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return s;

    HANDLE map = CreateFileMappingA(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map) { CloseHandle(h); return s; }

    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(offset);
    uint8_t* base = static_cast<uint8_t*>(
        MapViewOfFile(map, FILE_MAP_READ, li.HighPart, li.LowPart, length));
    if (!base) { CloseHandle(map); CloseHandle(h); return s; }

    auto t0 = std::chrono::steady_clock::now();
    volatile uint8_t sink = 0;
    for (uint64_t off = 0; off < length; off += 4096) sink ^= base[off];
    // Touch the tail too: the final partial page is a real byte we must fetch.
    sink ^= base[length - 1];
    auto t1 = std::chrono::steady_clock::now();
    (void)sink;

    s.seconds = std::chrono::duration<double>(t1 - t0).count();
    s.bytes = length;

    UnmapViewOfFile(base);
    CloseHandle(map);
    CloseHandle(h);
    return s;
}

// (B) Explicit unbuffered I/O into a sector-aligned arena. No page cache, no
// page faults, no VMA for the payload.
Stat TimeDirectIO(const std::string& path, uint64_t offset, uint64_t length,
                  void*& arenaOut) {
    Stat s;
    const uint64_t alignedOff = (offset / kSector) * kSector;
    const uint64_t delta      = offset - alignedOff;
    uint64_t padded = length + delta;
    padded = ((padded + kSector - 1) / kSector) * kSector;   // round UP

    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        std::printf("  direct: CreateFile(NO_BUFFERING) failed: %s\n", Err(GetLastError()));
        return s;
    }

    void* arena = _aligned_malloc(static_cast<size_t>(padded), kSector);
    if (!arena) { CloseHandle(h); return s; }
    arenaOut = arena;

    // A single aligned read of the whole region. A real scheduler would issue
    // this per expert block; the syscall and alignment contract are identical.
    OVERLAPPED ov{};
    DWORD got = 0;
    auto t0 = std::chrono::steady_clock::now();
    BOOL ok = ReadFile(h, arena, static_cast<DWORD>(padded),
                       &got, &ov);
    auto t1 = std::chrono::steady_clock::now();

    if (!ok) {
        DWORD e = GetLastError();
        std::printf("  direct: ReadFile failed (offset=%llu len=%llu buf=%p): %s\n",
                    (unsigned long long)alignedOff, (unsigned long long)padded,
                    arena, Err(e));
        if (e == ERROR_INVALID_PARAMETER)
            std::printf("  -> ERROR_INVALID_PARAMETER is the expected first failure when\n"
                        "     offset/length/buffer are not all sector-aligned.\n");
        CloseHandle(h);
        return s;
    }

    s.seconds = std::chrono::duration<double>(t1 - t0).count();
    s.bytes = got;
    CloseHandle(h);
    return s;
}

} // namespace

int main(int argc, char** argv) {
    const std::string path = (argc > 1) ? argv[1]
                                        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    uint64_t regionOff = (argc > 2) ? _strtoui64(argv[2], nullptr, 10) : 0;
    uint64_t regionLen = (argc > 3) ? _strtoui64(argv[3], nullptr, 10) : (256ull * 1024 * 1024);

    // Never read past EOF: the probe must describe a real, legal region.
    HANDLE probe = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (probe == INVALID_HANDLE_VALUE) {
        std::printf("cannot open %s: %s\n", path.c_str(), Err(GetLastError()));
        return 2;
    }
    LARGE_INTEGER fileSize{};
    GetFileSizeEx(probe, &fileSize);
    CloseHandle(probe);

    if (regionOff + regionLen > static_cast<uint64_t>(fileSize.QuadPart)) {
        if (static_cast<uint64_t>(fileSize.QuadPart) > regionLen)
            regionOff = static_cast<uint64_t>(fileSize.QuadPart) - regionLen;
        else
            regionLen = static_cast<uint64_t>(fileSize.QuadPart);
    }
    regionLen = (regionLen / kSector) * kSector;   // keep the region aligned

    std::printf("RAWRXD_DIRECT_IO_PROBE_001\n");
    std::printf("file        = %s\n", path.c_str());
    std::printf("file_size   = %llu bytes (%.2f GB)\n",
                (unsigned long long)fileSize.QuadPart,
                fileSize.QuadPart / (1024.0 * 1024 * 1024));
    std::printf("region      = offset %llu, length %llu (%.0f MB)\n",
                (unsigned long long)regionOff, (unsigned long long)regionLen,
                regionLen / (1024.0 * 1024));
    std::printf("sector      = %u\n\n", kSector);

    const Stat mmapStat = TimeMmapResident(path, regionOff, regionLen);
    std::printf("(A) MMAP + force residency (what prefill pays today)\n");
    std::printf("    bytes=%llu  seconds=%.4f  effective=%.2f GB/s\n",
                (unsigned long long)mmapStat.bytes, mmapStat.seconds, mmapStat.gbps());

    void* arena = nullptr;
    const Stat directStat = TimeDirectIO(path, regionOff, regionLen, arena);
    std::printf("\n(B) DIRECT I/O (FILE_FLAG_NO_BUFFERING -> aligned arena)\n");
    if (directStat.bytes == 0) {
        std::printf("    FAILED -- no transfer completed; see error above.\n");
        std::printf("    VERDICT=DIRECT_IO_UNAVAILABLE_ON_THIS_PATH\n");
    } else {
        std::printf("    bytes=%llu  seconds=%.4f  effective=%.2f GB/s\n",
                    (unsigned long long)directStat.bytes, directStat.seconds,
                    directStat.gbps());
        std::printf("    ratio direct/mmap = %.2fx\n",
                    mmapStat.seconds > 0 ? directStat.seconds / mmapStat.seconds : 0.0);
        std::printf("    VERDICT=%s\n",
                    directStat.seconds <= mmapStat.seconds
                        ? "DIRECT_IO_WORTH_IT" : "DIRECT_IO_SLOWER_THAN_MMAP");
    }
    if (arena) _aligned_free(arena);
    return 0;
}
