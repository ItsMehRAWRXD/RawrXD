// ============================================================================
// deep2_cpu_state_probe.cpp — DEEP2_OS_XSAVE_STATE_001 verification.
//
// Confirms the CPUID+XGETBV gating does NOT disable a feature the OS really
// has enabled.  This is the regression risk introduced by the fix: if XCR0
// were read incorrectly, a machine with working AVX2 would silently report
// AVX2=0 and fall back to scalar kernels — a large, invisible slowdown.
//
// Reports CPUID bits, XCR0, and the resulting gated features, then asserts
// that gating never claims LESS than an explicit independent re-derivation.
// ============================================================================
#include "../deep2/QuantKernelRegistry.hpp"

#include <cstdint>
#include <cstdio>

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

// The registry's gated view.
extern "C" void Deep2_FP16_GEMV(const void*, const float*, float*,
                                unsigned int, unsigned int) {}

static uint64_t ReadXcr0() {
#if defined(_MSC_VER) && !defined(__clang__)
    // _xgetbv RETURNS the value and takes the XCR index — it is not an
    // out-parameter call. This test deliberately reads it the correct way so
    // it can catch a regression that discards the return value.
    return static_cast<uint64_t>(_xgetbv(0));
#elif (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)
    uint32_t lo = 0, hi = 0;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    return (static_cast<uint64_t>(hi) << 32) | lo;
#else
    return 0;
#endif
}

static void Cpuid7(uint32_t& ebx, uint32_t& ecx) {
    int info[4];
#if defined(_MSC_VER)
    __cpuidex(info, 7, 0);
#else
    __cpuid_count(7, 0, info[0], info[1], info[2], info[3]);
#endif
    ebx = static_cast<uint32_t>(info[1]);
    ecx = static_cast<uint32_t>(info[2]);
}

static void Cpuid1(uint32_t& ecx) {
    int info[4];
#if defined(_MSC_VER)
    __cpuid(info, 1);
#else
    __cpuid(1, info[0], info[1], info[2], info[3]);
#endif
    ecx = static_cast<uint32_t>(info[2]);
}

int main() {
    using Deep2::QuantKernelRegistry;

    // The registry's gated view.
    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();
    const auto cpu = reg.GetCPUFeatures();

    // Independent raw view.
    uint32_t ecx1 = 0;
    Cpuid1(ecx1);
    uint32_t ebx7 = 0, ecx7 = 0;
    Cpuid7(ebx7, ecx7);
    const uint64_t xcr0 = ReadXcr0();

    const bool cpuidOsxsave = (ecx1 & (1u << 27)) != 0;
    const bool cpuidAvx = (ecx1 & (1u << 28)) != 0;
    const bool cpuidAvx2 = (ebx7 & (1u << 5)) != 0;
    const bool cpuidAvx512f = (ebx7 & (1u << 16)) != 0;
    const bool cpuidAvx512bw = (ebx7 & (1u << 30)) != 0;

    const bool xcr0Ymm = ((xcr0 >> 1) & 1u) && ((xcr0 >> 2) & 1u);
    const bool xcr0Avx512 = ((xcr0 >> 5) & 1u) && ((xcr0 >> 6) & 1u) &&
                           ((xcr0 >> 7) & 1u);

    const bool expectAvx2 = cpuidOsxsave && xcr0Ymm && cpuidAvx2;
    const bool expectAvx512 = cpuidOsxsave && xcr0Ymm && xcr0Avx512 &&
                              cpuidAvx512f && cpuidAvx512bw;

    std::printf("[CPU_STATE_PROBE]\n");
    std::printf("  cpuid_osxsave=%d cpuid_avx=%d cpuid_avx2=%d "
                "cpuid_avx512f=%d cpuid_avx512bw=%d\n",
                cpuidOsxsave ? 1 : 0, cpuidAvx ? 1 : 0, cpuidAvx2 ? 1 : 0,
                cpuidAvx512f ? 1 : 0, cpuidAvx512bw ? 1 : 0);
    std::printf("  xcr0=0x%016llX ymm_enabled=%d avx512_enabled=%d\n",
                (unsigned long long)xcr0, xcr0Ymm ? 1 : 0, xcr0Avx512 ? 1 : 0);
    std::printf("  registry_avx2=%d registry_avx512=%d (expected avx2=%d "
                "avx512=%d)\n",
                cpu.avx2 ? 1 : 0,
                (cpu.avx512f && cpu.avx512bw) ? 1 : 0,
                expectAvx2 ? 1 : 0, expectAvx512 ? 1 : 0);

    bool ok = (cpu.avx2 == expectAvx2) &&
              ((cpu.avx512f && cpu.avx512bw) == expectAvx512);

    // If AVX-512 is disabled by the OS, AVX-512 MUST be off — that is the fix
    // itself, and it must be asserted so a regression is loud.
    if (cpuidOsxsave && xcr0Ymm && !xcr0Avx512) {
        if (cpu.avx512f || cpu.avx512bw) {
            std::printf("  FAIL: AVX-512 bits set but XCR0 does not allow ZMM\n");
            ok = false;
        }
    }
    // And if YMM state is disabled, nothing above scalar may be allowed.
    if (cpuidOsxsave && !xcr0Ymm) {
        if (cpu.avx2 || cpu.avx512f) {
            std::printf("  FAIL: vector memory available in CPUID but not in "
                        "XCR0\n");
            ok = false;
        }
    }

    std::printf("[DEEP2_OS_XSAVE_STATE_001_VERDICT] %s\n", ok ? "PASS" : "FAIL");
    std::printf("[DEEP2_OS_XSAVE_STATE_001_RESULT] %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
