#pragma once
// Bounded, allocation-free per-request streaming telemetry.
#include <cstdint>
#include <cstdio>
namespace Deep2::ReapRom {
struct StreamTrace {
    uint64_t tokens=0, storageBytes=0, hostToGpuBytes=0, packedBytes=0;
    uint64_t residentHits=0, misses=0, failures=0;
    void Token() noexcept { ++tokens; }
    void Storage(uint64_t n) noexcept { storageBytes+=n; ++misses; }
    void Upload(uint64_t n) noexcept { hostToGpuBytes+=n; }
    void Packed(uint64_t n) noexcept { packedBytes+=n; }
    void Hit() noexcept { ++residentHits; }
    void Fail() noexcept { ++failures; }
    void Emit(FILE* f) const {
        if(!f) return;
        std::fprintf(f,"REAP_ROM_TOKENS=%llu\nREAP_ROM_STORAGE_BYTES=%llu\n"
            "REAP_ROM_H2D_BYTES=%llu\nREAP_ROM_PACKED_BYTES=%llu\n"
            "REAP_ROM_HITS=%llu\nREAP_ROM_MISSES=%llu\nREAP_ROM_FAILURES=%llu\n",
            (unsigned long long)tokens,(unsigned long long)storageBytes,
            (unsigned long long)hostToGpuBytes,(unsigned long long)packedBytes,
            (unsigned long long)residentHits,(unsigned long long)misses,
            (unsigned long long)failures);
    }
};
} // namespace Deep2::ReapRom
