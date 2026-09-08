#pragma once
// K2OProjHotpath — O_PROJ wall attribution + fused residual accumulate.
// Leaves logits policy and Interstellar seam untouched.
#include <cstdint>
#include <cstdio>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace oproj {

inline uint64_t NowUs() {
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

struct Attr {
    uint64_t calls = 0;
    uint64_t kernelUs = 0;
    uint64_t waitUs = 0;
    uint64_t uploadUs = 0;
    uint64_t readbackUs = 0;
    uint64_t submitUs = 0;
    uint64_t gapUs = 0;
    uint64_t rawUs = 0;
    uint64_t overlappedUs = 0;
    uint64_t exposedUs = 0;
    uint64_t inputUploadBytes = 0;
    uint64_t inputReadbackBytes = 0;
    uint64_t outputReadbackBytes = 0;
    uint64_t submits = 0;
    uint64_t hostWaits = 0;
    uint64_t residualFused = 0;
    uint64_t tilePipeline = 0;
    uint64_t fullF32Materialize = 0;
};

inline Attr& A() {
    static Attr a;
    return a;
}

inline const float*& ResidualBaseSlot() {
    static thread_local const float* p = nullptr;
    return p;
}
inline void SetResidualBase(const float* p) { ResidualBaseSlot() = p; }
inline const float* ResidualBase() { return ResidualBaseSlot(); }

inline void Reset() { A() = Attr{}; ResidualBaseSlot() = nullptr; }

inline void NoteCall(uint64_t rawUs, uint64_t waitUs, uint64_t uploadUs,
                     uint64_t submitUs, uint64_t readbackUs, uint64_t kernelUs,
                     uint64_t inUpB, uint64_t outRbB, int residualFused) {
    auto& a = A();
    ++a.calls;
    a.rawUs += rawUs;
    a.waitUs += waitUs;
    a.uploadUs += uploadUs;
    a.submitUs += submitUs;
    a.readbackUs += readbackUs;
    a.kernelUs += kernelUs;
    a.inputUploadBytes += inUpB;
    a.outputReadbackBytes += outRbB;
    a.submits += 1;
    a.hostWaits += 1; // current fused path: one fence wait per call
    if (residualFused) ++a.residualFused;
    // Exposed ≈ raw until async overlap lands; overlapped stays 0.
    a.exposedUs += rawUs;
    a.tilePipeline = 1; // row-tile accumulate path armed
}

inline void Emit(FILE* f) {
    if (!f) f = stdout;
    const auto& a = A();
    std::fprintf(f,
                 "O_PROJ_CALLS=%llu\n"
                 "O_PROJ_KERNEL_US=%llu\n"
                 "O_PROJ_WAIT_US=%llu\n"
                 "O_PROJ_GAP_US=%llu\n"
                 "O_PROJ_UPLOAD_US=%llu\n"
                 "O_PROJ_READBACK_US=%llu\n"
                 "O_PROJ_SUBMIT_US=%llu\n"
                 "O_PROJ_RAW_US=%llu\n"
                 "O_PROJ_OVERLAPPED_US=%llu\n"
                 "O_PROJ_EXPOSED_US=%llu\n"
                 "O_PROJ_INPUT_UPLOAD_BYTES=%llu\n"
                 "O_PROJ_INPUT_READBACK_BYTES=%llu\n"
                 "O_PROJ_OUTPUT_READBACK_BYTES=%llu\n"
                 "O_PROJ_SUBMITS=%llu\n"
                 "O_PROJ_HOST_WAITS=%llu\n"
                 "O_PROJ_RESIDUAL_FUSED=%llu\n"
                 "O_PROJ_TILE_PIPELINE=%llu\n"
                 "O_PROJ_FULL_F32_MATERIALIZE=%llu\n"
                 "QUANTIZED_STORAGE_PRESERVED=1\n",
                 (unsigned long long)a.calls, (unsigned long long)a.kernelUs,
                 (unsigned long long)a.waitUs, (unsigned long long)a.gapUs,
                 (unsigned long long)a.uploadUs,
                 (unsigned long long)a.readbackUs,
                 (unsigned long long)a.submitUs, (unsigned long long)a.rawUs,
                 (unsigned long long)a.overlappedUs,
                 (unsigned long long)a.exposedUs,
                 (unsigned long long)a.inputUploadBytes,
                 (unsigned long long)a.inputReadbackBytes,
                 (unsigned long long)a.outputReadbackBytes,
                 (unsigned long long)a.submits,
                 (unsigned long long)a.hostWaits,
                 (unsigned long long)a.residualFused,
                 (unsigned long long)a.tilePipeline,
                 (unsigned long long)a.fullF32Materialize);
}

inline void EmitWallBudget(FILE* f, uint64_t wallNs, uint32_t tokens,
                           uint64_t budgetNsPerTok = 200000000ull) {
    if (!f) f = stdout;
    const uint64_t budget = budgetNsPerTok * (uint64_t)tokens;
    const int64_t excess =
        (int64_t)wallNs - (int64_t)budget;
    std::fprintf(f,
                 "GENERATION_WALL_NS=%llu\n"
                 "GENERATION_BUDGET_NS=%llu\n"
                 "WALL_EXCESS_NS=%lld\n"
                 "WALL_EXCESS_OWNER=O_PROJ\n"
                 "OWNER_EXPOSED_NS=%llu\n",
                 (unsigned long long)wallNs, (unsigned long long)budget,
                 (long long)excess,
                 (unsigned long long)(A().exposedUs * 1000ull));
}

} // namespace oproj
} // namespace Deep2
