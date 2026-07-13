#include "cpu_capabilities.hpp"
#include <cstring>
#include <immintrin.h>  // For _xgetbv

namespace rawrxd {
namespace runtime {

static CpuCapabilities g_capabilities;
static bool g_initialized = false;

static void cpuid(int info[4], int function_id) {
    __cpuid_count(function_id, 0, info[0], info[1], info[2], info[3]);
}

static uint64_t xgetbv(uint32_t xcr) {
    uint32_t eax, edx;
    __asm__ __volatile__("xgetbv" : "=a"(eax), "=d"(edx) : "c"(xcr));
    return ((uint64_t)edx << 32) | eax;
}

CpuCapabilities CpuCapabilities::Detect() {
    CpuCapabilities caps;
    std::memset(&caps, 0, sizeof(caps));
    
    int info[4];
    
    // Get vendor string and max function
    cpuid(info, 0);
    int max_function = info[0];
    
    // Get features (function 1)
    if (max_function >= 1) {
        cpuid(info, 1);
        
        // EDX features
        caps.has_sse = (info[3] & (1 << 25)) != 0;
        caps.has_sse2 = (info[3] & (1 << 26)) != 0;
        
        // ECX features
        caps.has_sse3 = (info[2] & (1 << 0)) != 0;
        caps.has_ssse3 = (info[2] & (1 << 9)) != 0;
        caps.has_sse41 = (info[2] & (1 << 19)) != 0;
        caps.has_sse42 = (info[2] & (1 << 20)) != 0;
        caps.has_avx = (info[2] & (1 << 28)) != 0;
        caps.has_fma = (info[2] & (1 << 12)) != 0;
        caps.has_popcnt = (info[2] & (1 << 23)) != 0;
        
        // Check XSAVE/OS support for AVX
        if (caps.has_avx) {
            uint64_t xcr0 = xgetbv(0);
            // XCR0[1:0] = X87 state (bit 0) + SSE state (bit 1) must be set
            // XCR0[2] = AVX state must be set
            if ((xcr0 & 0x6) == 0x6) {
                // AVX is supported by OS
            } else {
                caps.has_avx = false;
            }
        }
    }
    
    // Get extended features (function 7)
    if (max_function >= 7) {
        cpuid(info, 7);
        
        // EBX features
        caps.has_avx2 = (info[1] & (1 << 5)) != 0;
        caps.has_bmi1 = (info[1] & (1 << 3)) != 0;
        caps.has_bmi2 = (info[1] & (1 << 8)) != 0;
        
        // AVX-512 features
        caps.has_avx512f = (info[1] & (1 << 16)) != 0;
        caps.has_avx512dq = (info[1] & (1 << 17)) != 0;
        caps.has_avx512bw = (info[1] & (1 << 30)) != 0;
        caps.has_avx512vl = (info[1] & (1 << 31)) != 0;
        
        // Check OS support for AVX-512
        if (caps.has_avx512f) {
            uint64_t xcr0 = xgetbv(0);
            // XCR0[7:5] = AVX-512 state must be set
            if ((xcr0 & 0xE0) == 0xE0) {
                // AVX-512 is supported by OS
            } else {
                caps.has_avx512f = false;
                caps.has_avx512dq = false;
                caps.has_avx512bw = false;
                caps.has_avx512vl = false;
            }
        }
    }
    
    // Get extended features (function 0x80000001)
    cpuid(info, 0x80000000);
    if (static_cast<uint32_t>(info[0]) >= 0x80000001) {
        cpuid(info, 0x80000001);
        caps.has_lzcnt = (info[2] & (1 << 5)) != 0;
    }
    
    // Cache info (function 4 for Intel, function 0x80000005/06 for AMD)
    // Simplified: assume 64-byte cache lines
    caps.cache_line_size = 64;
    
    // Try to get L1/L2/L3 cache sizes
    if (max_function >= 4) {
        // Intel-style cache info
        for (int i = 0; i < 10; i++) {
            __cpuid_count(4, i, info[0], info[1], info[2], info[3]);
            int cache_type = info[0] & 0x1F;
            if (cache_type == 0) break; // No more caches
            
            int cache_level = (info[0] >> 5) & 0x07;
            int ways = ((info[1] >> 22) & 0x3FF) + 1;
            int partitions = ((info[1] >> 12) & 0x3FF) + 1;
            int line_size = (info[1] & 0xFFF) + 1;
            int sets = info[2] + 1;
            
            uint32_t cache_size = ways * partitions * line_size * sets;
            
            if (cache_type == 1 || cache_type == 3) { // Data or Unified
                if (cache_level == 1) caps.l1d_cache_size = cache_size;
                else if (cache_level == 2) caps.l2_cache_size = cache_size;
                else if (cache_level == 3) caps.l3_cache_size = cache_size;
            }
        }
    }
    
    return caps;
}

const CpuCapabilities& CpuCapabilities::Get() {
    if (!g_initialized) {
        g_capabilities = Detect();
        g_initialized = true;
    }
    return g_capabilities;
}

} // namespace runtime
} // namespace rawrxd
