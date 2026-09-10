#pragma once
// D2hExchangeMirror — write-only discovery of host↔device exchanges.
// Compare dump vs D2H_CLASSIFICATION_001 mirror; log UNMIRRORED objects.
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace rawrxd::runtime {

enum class ExchangeDir : uint8_t { D2H = 1, H2D = 2 };

#pragma pack(push, 1)
struct D2hExchangeRec {
    uint64_t qpc_ns;
    uint64_t bytes;
    uint32_t site_id;   // stable id matching D2H_XX when known; 0 = unknown
    uint32_t token_step;
    uint32_t layer;
    uint8_t  dir;       // ExchangeDir
    uint8_t  in_mirror; // 1 if site_id was in classification mirror
    uint16_t _pad;
    char     site[48];  // short site tag, no heap
};
#pragma pack(pop)

inline constexpr uint32_t kD2hExCap = 1u << 14;

struct D2hExchangeRing {
    D2hExchangeRec slots[kD2hExCap];
    std::atomic<uint32_t> write{0};
    std::atomic<uint32_t> dropped{0};
    std::atomic<uint64_t> bytes_d2h{0};
    std::atomic<uint64_t> bytes_h2d{0};
    std::atomic<uint32_t> unmirrored{0};
};

inline D2hExchangeRing& D2hExRing() {
    static D2hExchangeRing r{};
    return r;
}

inline uint64_t D2hExQpcNs() {
    static LARGE_INTEGER f{};
    static int init = 0;
    if (!init) { QueryPerformanceFrequency(&f); init = 1; }
    LARGE_INTEGER c; QueryPerformanceCounter(&c);
    return (uint64_t)((c.QuadPart * 1000000000ull) / (uint64_t)f.QuadPart);
}

// site_id: 1=q_b GemvHostReadOut, 2=GemvHostWriteIn, 0=unknown live
inline void D2hExNote(ExchangeDir dir, uint64_t bytes, uint32_t site_id,
                      const char* site, uint32_t layer, uint32_t step,
                      bool in_mirror) {
    auto& r = D2hExRing();
    const uint32_t i = r.write.fetch_add(1, std::memory_order_relaxed);
    if (i >= kD2hExCap) {
        r.dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    D2hExchangeRec& e = r.slots[i];
    e.qpc_ns = D2hExQpcNs();
    e.bytes = bytes;
    e.site_id = site_id;
    e.token_step = step;
    e.layer = layer;
    e.dir = (uint8_t)dir;
    e.in_mirror = in_mirror ? 1u : 0u;
    e._pad = 0;
    if (site) {
        std::strncpy(e.site, site, sizeof(e.site) - 1);
        e.site[sizeof(e.site) - 1] = 0;
    } else {
        e.site[0] = 0;
    }
    if (dir == ExchangeDir::D2H)
        r.bytes_d2h.fetch_add(bytes, std::memory_order_relaxed);
    else
        r.bytes_h2d.fetch_add(bytes, std::memory_order_relaxed);
    if (!in_mirror)
        r.unmirrored.fetch_add(1, std::memory_order_relaxed);
}

inline void D2hExEmit(FILE* f) {
    if (!f) return;
    auto& r = D2hExRing();
    const uint32_t n = r.write.load(std::memory_order_relaxed);
    const uint32_t lim = n < kD2hExCap ? n : kD2hExCap;
    std::fprintf(f,
        "D2H_EXCHANGE_MIRROR_BEGIN records=%u dropped=%u "
        "bytes_d2h=%llu bytes_h2d=%llu unmirrored=%u\n",
        lim, r.dropped.load(),
        (unsigned long long)r.bytes_d2h.load(),
        (unsigned long long)r.bytes_h2d.load(),
        r.unmirrored.load());
    std::fprintf(f, "qpc_ns\tdir\tsite_id\tin_mirror\tlayer\tstep\tbytes\tsite\n");
    for (uint32_t i = 0; i < lim; ++i) {
        const auto& e = r.slots[i];
        std::fprintf(f, "%llu\t%s\t%u\t%u\t%u\t%u\t%llu\t%s\n",
            (unsigned long long)e.qpc_ns,
            e.dir == (uint8_t)ExchangeDir::H2D ? "H2D" : "D2H",
            e.site_id, e.in_mirror, e.layer, e.token_step,
            (unsigned long long)e.bytes, e.site);
    }
    std::fprintf(f, "D2H_EXCHANGE_MIRROR_END\n");
}

inline void D2hExReset() {
    auto& r = D2hExRing();
    r.write.store(0); r.dropped.store(0);
    r.bytes_d2h.store(0); r.bytes_h2d.store(0); r.unmirrored.store(0);
}

} // namespace rawrxd::runtime
