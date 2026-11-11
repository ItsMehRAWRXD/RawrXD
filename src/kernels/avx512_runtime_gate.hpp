//============================================================================
// avx512_runtime_gate.hpp
//
// Hard runtime gating for AVX-512 kernels
// Prevents execution on unsupported hardware with clear error messages
//============================================================================

#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif

namespace RawrXD {
namespace Kernels {

//============================================================================
// CPU Feature Detection
//============================================================================
inline bool DetectAVX512F() {
#ifdef _MSC_VER
    int cpuInfo[4] = {0};
    
    // Check max CPUID leaf
    __cpuid(cpuInfo, 0);
    int maxLeaf = cpuInfo[0];
    if (maxLeaf < 7) return false;
    
    // Check AVX-512F (leaf 7, EBX bit 16)
    __cpuidex(cpuInfo, 7, 0);
    bool hasAVX512F = (cpuInfo[1] & (1 << 16)) != 0;
    if (!hasAVX512F) return false;
    
    // Check OS support via XCR0
    uint64_t xcr0 = _xgetbv(0);
    return (xcr0 & 0xE0) == 0xE0;
#else
    unsigned int eax, ebx, ecx, edx;
    
    // Check max leaf
    if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx)) return false;
    if (eax < 7) return false;
    
    // Check AVX-512F
    if (!__get_cpuid(7, &eax, &ebx, &ecx, &edx)) return false;
    bool hasAVX512F = (ebx & (1 << 16)) != 0;
    if (!hasAVX512F) return false;
    
    // Check OS support
    unsigned int xcr0_eax, xcr0_edx;
    __asm__ __volatile__("xgetbv" : "=a"(xcr0_eax), "=d"(xcr0_edx) : "c"(0));
    uint64_t xcr0 = ((uint64_t)xcr0_edx << 32) | xcr0_eax;
    return (xcr0 & 0xE0) == 0xE0;
#endif
}

//============================================================================
// Runtime Gate Macro
//============================================================================
#define AVX512_GATE() do { \
    if (!RawrXD::Kernels::DetectAVX512F()) { \
        fprintf(stderr, "ERROR: AVX-512F not supported on this CPU\n"); \
        fprintf(stderr, "  Required: CPU with AVX-512F (CPUID leaf 7, EBX bit 16)\n"); \
        fprintf(stderr, "  Required: OS with ZMM state enabled (XCR0 bits 5-7)\n"); \
        exit(1); \
    } \
} while(0)

#define AVX512_GATE_RET(retval) do { \
    if (!RawrXD::Kernels::DetectAVX512F()) { \
        fprintf(stderr, "ERROR: AVX-512F not supported on this CPU\n"); \
        return (retval); \
    } \
} while(0)

#define AVX512_GATE_VOID() do { \
    if (!RawrXD::Kernels::DetectAVX512F()) { \
        fprintf(stderr, "ERROR: AVX-512F not supported on this CPU\n"); \
        return; \
    } \
} while(0)

} // namespace Kernels
} // namespace RawrXD
