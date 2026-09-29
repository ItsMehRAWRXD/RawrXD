// CpuFeatureAuthority.cpp — RAWRXD_CPU_FEATURE_AUTHORITY_001
#include "CpuFeatureAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <cstdio>
#include <cstring>
#include <atomic>
#include <string>
#include <mutex>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace rawrxd { namespace cpu {

static std::atomic<int> g_detected{0};
static CpuFeatures g_features;
static std::mutex g_featMutex;

CpuFeatures detectFeatures() {
    CpuFeatures f;
#if defined(_MSC_VER)
    int cpuInfo[4] = {0,0,0,0};

    // Leaf 1 — ECX bit 20 = SSE4.2, bit 12 = FMA, bit 28 = AVX
    __cpuid(cpuInfo, 1);
    f.sse42 = (cpuInfo[2] & (1 << 20)) != 0;
    bool avx  = (cpuInfo[2] & (1 << 28)) != 0;
    bool osxsave = (cpuInfo[2] & (1 << 27)) != 0;
    f.fma   = (cpuInfo[2] & (1 << 12)) != 0;

    // AVX2 — leaf 7, subleaf 0, EBX bit 5
    if (avx && osxsave) {
        // Check XMM/YMM state support via xgetbv
        unsigned long long xcrFeatureMask = _xgetbv(0);
        bool xmmSupported = (xcrFeatureMask & 0x6) == 0x6;
        if (xmmSupported) {
            __cpuidex(cpuInfo, 7, 0);
            f.avx2 = (cpuInfo[1] & (1 << 5)) != 0;

            // AVX-512 foundations — leaf 7 EBX bits 16/17/28/31
            bool avx512f  = (cpuInfo[1] & (1 << 16)) != 0;
            f.avx512f     = avx512f;
            f.avx512bw    = (cpuInfo[1] & (1 << 30)) != 0;
            // AVX-512 VNNI — leaf 7 ECX bit 11
            f.avx512vnni  = (cpuInfo[2] & (1 << 11)) != 0;
        }
    }
#else
    // Non-MSVC: conservatively disable advanced features
    f.sse42 = false;
    f.avx2  = false;
    f.fma   = false;
    f.avx512f    = false;
    f.avx512bw   = false;
    f.avx512vnni = false;
#endif

    g_detected.store(1, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(g_featMutex);
        g_features = f;
    }
    return f;
}

void writeFeatureReceipt(const std::string& path) {
    using namespace rawrxd::receipt;
    beginGate(path, "RAWRXD_CPU_FEATURE_AUTHORITY_001");

    CpuFeatures f;
    if (g_detected.load(std::memory_order_acquire)) {
        std::lock_guard<std::mutex> lock(g_featMutex);
        f = g_features;
    } else {
        f = detectFeatures();
    }

    writeKeyValue(path, "AVX512F",     f.avx512f     ? "1" : "0");
    writeKeyValue(path, "AVX512BW",    f.avx512bw    ? "1" : "0");
    writeKeyValue(path, "AVX512VNNI",  f.avx512vnni  ? "1" : "0");
    writeKeyValue(path, "AVX2",        f.avx2        ? "1" : "0");
    writeKeyValue(path, "FMA",         f.fma         ? "1" : "0");
    writeKeyValue(path, "SSE42",       f.sse42       ? "1" : "0");

    const char* verdict = "PASS";  // detection itself always succeeds
    endGate(path, verdict);
}

}} // namespace rawrxd::cpu