// K2MLA_FusedQ4KT.cpp — MLA_Gemv child: resident Q4_K → fused FMA
#include "K2MLA_FusedQ4KT.hpp"
#include "K2GpuStreamCopy.hpp"
#include "vulkan_compute.h"
#include <cstdlib>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace {
uint64_t g_calls = 0, g_ops = 0, g_fail = 0;
uint64_t g_fusedUs = 0, g_compatUs = 0;
uint64_t g_f32Exp = 0, g_tempBytes = 0;
} // namespace

uint64_t MLA_FusedQ4KT_NowUs() {
#ifdef _WIN32
    static LARGE_INTEGER f{};
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (uint64_t)((c.QuadPart * 1000000ull) / (uint64_t)f.QuadPart);
#else
    return 0;
#endif
}

bool MLA_FusedQ4KT_Wanted() {
    const char* e = std::getenv("DEEP2_MLA_FUSED_Q4KT");
    // Explicit 0 keeps BASE packed GEMV for A/B certs.
    if (e && e[0] == '0') return false;
    if (e && e[0] == '1') return true;
    // Default ON whenever GPU MLA is armed (BATCH15 #04 promote).
    const char* g = std::getenv("DEEP2_K2_GPU_MLA");
    return g && g[0] == '1';
}

void MLA_FusedQ4KT_Reset() {
    g_calls = g_ops = g_fail = 0;
    g_fusedUs = g_compatUs = 0;
    g_f32Exp = g_tempBytes = 0;
}

void MLA_NoteGemvCompatUs(uint64_t t0) {
    g_compatUs += MLA_FusedQ4KT_NowUs() - t0;
}

void MLA_NoteF32WeightExpand(uint64_t tempBytes) {
    ++g_f32Exp;
    g_tempBytes += tempBytes;
}

uint64_t MLA_FusedQ4KT_Calls() { return g_calls; }
uint64_t MLA_FusedQ4KT_Ops() { return g_ops; }
uint64_t MLA_FusedQ4KT_Fail() { return g_fail; }
uint64_t MLA_FusedQ4KT_Us() { return g_fusedUs; }
uint64_t MLA_GemvCompatUs() { return g_compatUs; }
uint64_t MLA_F32WeightExpands() { return g_f32Exp; }
uint64_t MLA_Q4KTempWeightBytes() { return g_tempBytes; }

bool MLA_FusedQ4KT(const void* packed, size_t bytes, const float* input,
                   float* output, uint32_t rows, uint32_t cols,
                   uint64_t pinKey) {
    ++g_calls;
    auto* vc = K2GpuStreamCopy_Vc();
    if (!vc || !packed || !input || !output) {
        ++g_fail;
        return false;
    }
    const uint64_t t0 = MLA_FusedQ4KT_NowUs();
    const bool ok =
        vc->DispatchGEMVFusedQ4KT(packed, bytes, input, output, rows, cols,
                                  pinKey);
    g_fusedUs += MLA_FusedQ4KT_NowUs() - t0;
    if (!ok) return false; // miss → MLA_Gemv packed compatibility
    ++g_ops;
    return true;
}

void MLA_FusedQ4KT_Emit(FILE* f) {
    if (!f) return;
    fprintf(f,
            "MLA_FUSED_Q4KT_CALLS=%llu OPS=%llu FAIL=%llu US=%llu\n"
            "MLA_GEMV_COMPAT_US=%llu F32_WEIGHT_EXPANDS=%llu "
            "Q4K_TEMP_WEIGHT_BYTES=%llu\n",
            (unsigned long long)g_calls, (unsigned long long)g_ops,
            (unsigned long long)g_fail, (unsigned long long)g_fusedUs,
            (unsigned long long)g_compatUs, (unsigned long long)g_f32Exp,
            (unsigned long long)g_tempBytes);
}

} // namespace Deep2
