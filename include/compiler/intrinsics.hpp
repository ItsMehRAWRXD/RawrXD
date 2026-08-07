// intrinsics.hpp - Compiler-neutral SIMD/intrinsics abstraction
// RawrXD Sovereign Build System

#pragma once

#include "platform.hpp"

// Include appropriate intrinsics headers based on compiler
#if RAWRXD_COMPILER_MSVC
    #include <intrin.h>
    #include <immintrin.h>
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #include <x86intrin.h>
    #include <cpuid.h>
#endif

namespace rawrxd {
namespace intrinsics {

// CPU feature detection
struct CpuFeatures {
    bool sse = false;
    bool sse2 = false;
    bool sse3 = false;
    bool ssse3 = false;
    bool sse41 = false;
    bool sse42 = false;
    bool avx = false;
    bool avx2 = false;
    bool fma = false;
    bool avx512f = false;
    bool avx512dq = false;
    bool avx512bw = false;
    bool avx512vl = false;
    bool avx512vnni = false;
    bool bmi1 = false;
    bool bmi2 = false;
    bool lzcnt = false;
    bool popcnt = false;

    static CpuFeatures detect() {
        CpuFeatures features;
        
#if RAWRXD_COMPILER_MSVC
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 0);
        int nIds = cpuInfo[0];
        
        if (nIds >= 1) {
            __cpuid(cpuInfo, 1);
            features.sse = (cpuInfo[3] & (1 << 25)) != 0;
            features.sse2 = (cpuInfo[3] & (1 << 26)) != 0;
            features.sse3 = (cpuInfo[2] & (1 << 0)) != 0;
            features.ssse3 = (cpuInfo[2] & (1 << 9)) != 0;
            features.sse41 = (cpuInfo[2] & (1 << 19)) != 0;
            features.sse42 = (cpuInfo[2] & (1 << 20)) != 0;
            features.avx = (cpuInfo[2] & (1 << 28)) != 0;
            features.fma = (cpuInfo[2] & (1 << 12)) != 0;
            features.popcnt = (cpuInfo[2] & (1 << 23)) != 0;
        }
        
        if (nIds >= 7) {
            __cpuidex(cpuInfo, 7, 0);
            features.avx2 = (cpuInfo[1] & (1 << 5)) != 0;
            features.avx512f = (cpuInfo[1] & (1 << 16)) != 0;
            features.avx512dq = (cpuInfo[1] & (1 << 17)) != 0;
            features.avx512bw = (cpuInfo[1] & (1 << 30)) != 0;
            features.avx512vl = (cpuInfo[1] & (1 << 31)) != 0;
            features.avx512vnni = (cpuInfo[2] & (1 << 11)) != 0;
            features.bmi1 = (cpuInfo[1] & (1 << 3)) != 0;
            features.bmi2 = (cpuInfo[1] & (1 << 8)) != 0;
        }
        
        __cpuid(cpuInfo, 0x80000001);
        features.lzcnt = (cpuInfo[2] & (1 << 5)) != 0;
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
        unsigned int eax, ebx, ecx, edx;
        
        if (__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
            int nIds = eax;
            
            if (nIds >= 1) {
                __get_cpuid(1, &eax, &ebx, &ecx, &edx);
                features.sse = (edx & bit_SSE) != 0;
                features.sse2 = (edx & bit_SSE2) != 0;
                features.sse3 = (ecx & bit_SSE3) != 0;
                features.ssse3 = (ecx & bit_SSSE3) != 0;
                features.sse41 = (ecx & bit_SSE4_1) != 0;
                features.sse42 = (ecx & bit_SSE4_2) != 0;
                features.avx = (ecx & bit_AVX) != 0;
                features.fma = (ecx & bit_FMA) != 0;
                features.popcnt = (ecx & bit_POPCNT) != 0;
            }
            
            if (nIds >= 7) {
                __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
                features.avx2 = (ebx & bit_AVX2) != 0;
                features.avx512f = (ebx & bit_AVX512F) != 0;
                features.bmi1 = (ebx & bit_BMI) != 0;
                features.bmi2 = (ebx & bit_BMI2) != 0;
            }
        }
        
        __get_cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
        features.lzcnt = (ecx & bit_LZCNT) != 0;
#endif
        
        return features;
    }
};

// Cache line size (common values)
constexpr size_t CACHE_LINE_SIZE = 64;

// Prefetch hints
#if RAWRXD_COMPILER_MSVC
    #define RAWRXD_PREFETCH_T0(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T0)
    #define RAWRXD_PREFETCH_T1(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T1)
    #define RAWRXD_PREFETCH_T2(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T2)
    #define RAWRXD_PREFETCH_NTA(addr) _mm_prefetch((const char*)(addr), _MM_HINT_NTA)
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_PREFETCH_T0(addr) __builtin_prefetch((addr), 0, 3)
    #define RAWRXD_PREFETCH_T1(addr) __builtin_prefetch((addr), 0, 2)
    #define RAWRXD_PREFETCH_T2(addr) __builtin_prefetch((addr), 0, 1)
    #define RAWRXD_PREFETCH_NTA(addr) __builtin_prefetch((addr), 0, 0)
#else
    #define RAWRXD_PREFETCH_T0(addr)
    #define RAWRXD_PREFETCH_T1(addr)
    #define RAWRXD_PREFETCH_T2(addr)
    #define RAWRXD_PREFETCH_NTA(addr)
#endif

// Memory fence/barrier
#if RAWRXD_COMPILER_MSVC
    #define RAWRXD_MEMORY_FENCE() _mm_mfence()
    #define RAWRXD_READ_FENCE() _mm_lfence()
    #define RAWRXD_WRITE_FENCE() _mm_sfence()
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_MEMORY_FENCE() __atomic_thread_fence(__ATOMIC_SEQ_CST)
    #define RAWRXD_READ_FENCE() __atomic_thread_fence(__ATOMIC_ACQUIRE)
    #define RAWRXD_WRITE_FENCE() __atomic_thread_fence(__ATOMIC_RELEASE)
#else
    #define RAWRXD_MEMORY_FENCE()
    #define RAWRXD_READ_FENCE()
    #define RAWRXD_WRITE_FENCE()
#endif

// Pause instruction (for spin loops)
#if RAWRXD_COMPILER_MSVC
    #define RAWRXD_PAUSE() _mm_pause()
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_PAUSE() __builtin_ia32_pause()
#else
    #define RAWRXD_PAUSE()
#endif

// Bit manipulation
#if RAWRXD_COMPILER_MSVC
    #include <stdint.h>
    inline uint32_t rawrxd_popcnt32(uint32_t x) { return __popcnt(x); }
    inline uint64_t rawrxd_popcnt64(uint64_t x) { return __popcnt64(x); }
    inline uint32_t rawrxd_clz32(uint32_t x) { unsigned long idx; _BitScanReverse(&idx, x); return 31 - idx; }
    inline uint64_t rawrxd_clz64(uint64_t x) { unsigned long idx; _BitScanReverse64(&idx, x); return 63 - idx; }
    inline uint32_t rawrxd_ctz32(uint32_t x) { unsigned long idx; _BitScanForward(&idx, x); return idx; }
    inline uint64_t rawrxd_ctz64(uint64_t x) { unsigned long idx; _BitScanForward64(&idx, x); return idx; }
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    inline uint32_t rawrxd_popcnt32(uint32_t x) { return __builtin_popcount(x); }
    inline uint64_t rawrxd_popcnt64(uint64_t x) { return __builtin_popcountll(x); }
    inline uint32_t rawrxd_clz32(uint32_t x) { return __builtin_clz(x); }
    inline uint64_t rawrxd_clz64(uint64_t x) { return __builtin_clzll(x); }
    inline uint32_t rawrxd_ctz32(uint32_t x) { return __builtin_ctz(x); }
    inline uint64_t rawrxd_ctz64(uint64_t x) { return __builtin_ctzll(x); }
#else
    inline uint32_t rawrxd_popcnt32(uint32_t x) { int c = 0; while (x) { c++; x &= x - 1; } return c; }
    inline uint64_t rawrxd_popcnt64(uint64_t x) { int c = 0; while (x) { c++; x &= x - 1; } return c; }
    inline uint32_t rawrxd_clz32(uint32_t x) { uint32_t n = 0; while (x < (1u << 31)) { n++; x <<= 1; } return n; }
    inline uint64_t rawrxd_clz64(uint64_t x) { uint64_t n = 0; while (x < (1ull << 63)) { n++; x <<= 1; } return n; }
    inline uint32_t rawrxd_ctz32(uint32_t x) { uint32_t n = 0; while (!(x & 1)) { n++; x >>= 1; } return n; }
    inline uint64_t rawrxd_ctz64(uint64_t x) { uint64_t n = 0; while (!(x & 1)) { n++; x >>= 1; } return n; }
#endif

// Byte swap
#if RAWRXD_COMPILER_MSVC
    inline uint16_t rawrxd_bswap16(uint16_t x) { return _byteswap_ushort(x); }
    inline uint32_t rawrxd_bswap32(uint32_t x) { return _byteswap_ulong(x); }
    inline uint64_t rawrxd_bswap64(uint64_t x) { return _byteswap_uint64(x); }
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    inline uint16_t rawrxd_bswap16(uint16_t x) { return __builtin_bswap16(x); }
    inline uint32_t rawrxd_bswap32(uint32_t x) { return __builtin_bswap32(x); }
    inline uint64_t rawrxd_bswap64(uint64_t x) { return __builtin_bswap64(x); }
#else
    inline uint16_t rawrxd_bswap16(uint16_t x) { return (x >> 8) | (x << 8); }
    inline uint32_t rawrxd_bswap32(uint32_t x) { 
        return ((x & 0xFF000000) >> 24) | ((x & 0x00FF0000) >> 8) |
               ((x & 0x0000FF00) << 8) | ((x & 0x000000FF) << 24);
    }
    inline uint64_t rawrxd_bswap64(uint64_t x) {
        return ((x & 0xFF00000000000000ull) >> 56) | ((x & 0x00FF000000000000ull) >> 40) |
               ((x & 0x0000FF0000000000ull) >> 24) | ((x & 0x000000FF00000000ull) >> 8) |
               ((x & 0x00000000FF000000ull) << 8) | ((x & 0x0000000000FF0000ull) << 24) |
               ((x & 0x000000000000FF00ull) << 40) | ((x & 0x00000000000000FFull) << 56);
    }
#endif

} // namespace intrinsics
} // namespace rawrxd
