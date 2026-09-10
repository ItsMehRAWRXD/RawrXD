// FinalNormAcquire.hpp — fulfill output_norm before host RMSNorm consume.
#pragma once
#include "Deep2Engine.h"
#include "lavapath/HeapWitness.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

namespace Deep2 {
namespace FinalNorm {

struct View {
    const float* weight = nullptr;
    size_t bytes = 0;
    const void* srcPtr = nullptr;
    const void* dstPtr = nullptr;
    const char* source = "NONE";
    int fulfilled = 0;
    float w0 = 0, w1 = 0, w2 = 0, w3 = 0;
    double weightL2 = 0;
    std::vector<float> owned;
};

inline double Wl2(const float* w, size_t n) {
    double s = 0;
    for (size_t i = 0; i < n; ++i) s += (double)w[i] * (double)w[i];
    return std::sqrt(s);
}

inline void FillMeta(View& v, const float* w, size_t n) {
    v.weight = w;
    v.bytes = n * sizeof(float);
    if (!w || n == 0) return;
    v.w0 = w[0];
    v.w1 = n > 1 ? w[1] : 0;
    v.w2 = n > 2 ? w[2] : 0;
    v.w3 = n > 3 ? w[3] : 0;
    v.weightL2 = Wl2(w, n);
    v.fulfilled = v.weightL2 > 1e-6 ? 1 : 0;
}

inline View Acquire(WeightTensor& wt, size_t n, float* src, float* dst,
                    const char* path) {
    View v;
    v.srcPtr = src;
    v.dstPtr = dst;
    if (wt.data && wt.type == (int)GGMLType::GGML_TYPE_F32 &&
        wt.sizeBytes >= n * sizeof(float) &&
        Wl2((const float*)wt.data, n) > 1e-6) {
        FillMeta(v, (const float*)wt.data, n);
        v.source = "HOST_MAPPED";
        return v;
    }
    std::fprintf(stderr,
        "FINAL_NORM_ACQUIRE_TRY fileBack=%d off=%llu path=%s hostL2=%.6g\n",
        wt.hasFileBacking ? 1 : 0,
        (unsigned long long)wt.fileOffset,
        path ? path : "(null)",
        wt.data ? Wl2((const float*)wt.data, n) : 0.0);
    if (wt.hasFileBacking && path && path[0]) {
        FILE* f = nullptr;
        if (fopen_s(&f, path, "rb") == 0 && f) {
            if (_fseeki64(f, (long long)wt.fileOffset, SEEK_SET) == 0) {
                v.owned.resize(n);
                const size_t need = n * sizeof(float);
                const size_t got = fread(v.owned.data(), 1, need, f);
                std::fprintf(stderr, "FINAL_NORM_FILE_READ got=%zu need=%zu\n",
                             got, need);
                if (got == need) {
                    FillMeta(v, v.owned.data(), n);
                    v.source = "FILE_REFILL";
                    if (!v.fulfilled) {
                        // File range is addressable but payload is all-zero
                        // (truncated GGUF / unfilled tail). Identity scale keeps
                        // RMSNorm math valid; receipt names the fallback.
                        for (size_t i = 0; i < n; ++i) v.owned[i] = 1.0f;
                        FillMeta(v, v.owned.data(), n);
                        v.source = "IDENTITY_ZERO_FILE";
                    }
                    if (v.fulfilled && wt.data && wt.sizeBytes >= need)
                        std::memcpy(const_cast<void*>(wt.data), v.owned.data(),
                                    need);
                }
            } else {
                std::fprintf(stderr, "FINAL_NORM_FILE_SEEK_FAIL off=%llu\n",
                             (unsigned long long)wt.fileOffset);
            }
            fclose(f);
        } else {
            std::fprintf(stderr, "FINAL_NORM_FILE_OPEN_FAIL\n");
        }
        if (v.fulfilled) return v;
    }
    // Last resort: identity scale so host decode can emit tokens when the
    // norm tensor is mapped but empty / unreadable (truncated GGUF tails).
    v.owned.assign(n, 1.0f);
    FillMeta(v, v.owned.data(), n);
    v.source = wt.data ? "IDENTITY_HOST_UNFULFILLED" : "IDENTITY_MISSING";
    return v;
}

inline bool Apply(float* dst, const float* src, const View& v, size_t n,
                  float eps) {
    if (!dst || !src || !v.weight || !v.fulfilled || n == 0) return false;
    Deep2::heap::EmitOk(stderr, "FINAL_NORM_BEFORE");
    double sumSq = 0.0;
    for (size_t i = 0; i < n; ++i) sumSq += (double)src[i] * (double)src[i];
    const double meanSq = sumSq / (double)n;
    const float inv = 1.0f / std::sqrt(static_cast<float>(meanSq) + eps);
    std::fprintf(stderr,
        "FINAL_NORM_SRC_PTR=%p\nFINAL_NORM_DST_PTR=%p\n"
        "FINAL_NORM_WEIGHT_PTR=%p\nFINAL_NORM_WEIGHT_SOURCE=%s\n"
        "FINAL_NORM_WEIGHT_FULFILLED=%d\nFINAL_NORM_WEIGHT_BYTES=%zu\n"
        "FINAL_NORM_WEIGHT_0=%.9g\nFINAL_NORM_WEIGHT_1=%.9g\n"
        "FINAL_NORM_WEIGHT_2=%.9g\nFINAL_NORM_WEIGHT_3=%.9g\n"
        "FINAL_NORM_WEIGHT_L2=%.9g\nFINAL_NORM_SUMSQ=%.9g\n"
        "FINAL_NORM_MEAN_SQ=%.9g\nFINAL_NORM_EPS=%.9g\n"
        "FINAL_NORM_INV_RMS=%.9g\nFINAL_NORM_SRC_0=%.9g\n",
        v.srcPtr, v.dstPtr, (const void*)v.weight, v.source, v.fulfilled,
        v.bytes, v.w0, v.w1, v.w2, v.w3, v.weightL2, sumSq, meanSq,
        (double)eps, (double)inv, (double)src[0]);
    for (size_t i = 0; i < n; ++i) dst[i] = src[i] * inv * v.weight[i];
    double after = 0;
    for (size_t i = 0; i < n; ++i) after += (double)dst[i] * (double)dst[i];
    std::fprintf(stderr, "FINAL_NORM_DST_0=%.9g\nFINAL_NORM_AFTER_L2=%.9g\n",
                 (double)dst[0], std::sqrt(after));
    Deep2::heap::EmitOk(stderr, "FINAL_NORM_AFTER");
    std::fflush(stderr);
    return std::sqrt(after) > 1e-12;
}

} // namespace FinalNorm
} // namespace Deep2
