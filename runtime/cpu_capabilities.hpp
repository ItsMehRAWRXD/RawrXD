#pragma once
#include <cstdint>
#include <cpuid.h>

namespace rawrxd {
namespace runtime {

// CPU capability detection for RawrXD
// Detects AVX, AVX2, AVX-512, and other features

struct CpuCapabilities {
    bool has_sse;
    bool has_sse2;
    bool has_sse3;
    bool has_ssse3;
    bool has_sse41;
    bool has_sse42;
    bool has_avx;
    bool has_avx2;
    bool has_avx512f;
    bool has_avx512dq;
    bool has_avx512bw;
    bool has_avx512vl;
    bool has_fma;
    bool has_bmi1;
    bool has_bmi2;
    bool has_lzcnt;
    bool has_popcnt;
    
    // Cache info
    uint32_t l1d_cache_size;
    uint32_t l2_cache_size;
    uint32_t l3_cache_size;
    uint32_t cache_line_size;
    
    static CpuCapabilities Detect();
    static const CpuCapabilities& Get();
    
    bool HasAVX2() const { return has_avx2; }
    bool HasAVX512() const { return has_avx512f && has_avx512dq && has_avx512bw && has_avx512vl; }
};

// Runtime dispatch helper
template<typename ScalarFn, typename Avx2Fn, typename Avx512Fn>
inline auto Dispatch(ScalarFn scalar_fn, Avx2Fn avx2_fn, Avx512Fn avx512_fn) {
    const auto& caps = CpuCapabilities::Get();
    if (caps.HasAVX512()) {
        return avx512_fn;
    } else if (caps.HasAVX2()) {
        return avx2_fn;
    }
    return scalar_fn;
}

} // namespace runtime
} // namespace rawrxd
