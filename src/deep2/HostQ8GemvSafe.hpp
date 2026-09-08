// HostQ8GemvSafe.hpp — mechanical HOST_Q8_GEMV_* receipts (no SEH/C++ mix).
#pragma once
#include "Deep2Engine.h"
#include "GGUFLoader.hpp"
#include "NemotronHSsmMap.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

namespace Deep2 {

struct HostQ8GemvReceipts {
    int ffn = 0;
    int attn = 0;
    int ssmIn = 0;
    int numericFinite = 0;
    int boundsSafe = 0;
    int referenceParity = 0;
    int safe = 0;
    const char* failOwner = nullptr;
    const char* nextAction = nullptr;
};

namespace detail {

inline float F16ToF32(uint16_t h) {
    const uint32_t s = (h >> 15) & 0x1u;
    const uint32_t e = (h >> 10) & 0x1Fu;
    const uint32_t m = h & 0x3FFu;
    uint32_t o;
    if (e == 0) {
        if (m == 0) o = s << 31;
        else {
            uint32_t ee = 127 - 15 + 1;
            uint32_t mm = m;
            while ((mm & 0x400u) == 0) { mm <<= 1; --ee; }
            mm &= 0x3FFu;
            o = (s << 31) | (ee << 23) | (mm << 13);
        }
    } else if (e == 31) {
        o = (s << 31) | 0x7F800000u | (m << 13);
    } else {
        o = (s << 31) | ((e + (127 - 15)) << 23) | (m << 13);
    }
    float f;
    std::memcpy(&f, &o, sizeof(f));
    return f;
}

inline bool ByteBoundsOk(const WeightTensor& wt) {
    if (!wt.data || wt.rows == 0 || wt.cols == 0) return false;
    if (wt.type != (int)GGMLType::GGML_TYPE_Q8_0) return true;
    const size_t bpr = (wt.cols + 31) / 32;
    return wt.rows * bpr * sizeof(block_q8_0) <= wt.sizeBytes;
}

// Bounds-safe scalar Q8_0 GEMV (cols may be non-multiple of 32).
inline void GemvQ8Ref(const uint8_t* w, const float* x, float* y,
                      size_t rows, size_t cols) {
    constexpr size_t kBlk = 34;
    const size_t bpr = (cols + 31) / 32;
    const size_t rowBytes = bpr * kBlk;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const uint8_t* row = w + r * rowBytes;
        for (size_t b = 0; b < bpr; ++b) {
            const auto* blk =
                reinterpret_cast<const block_q8_0*>(row + b * kBlk);
            const float d = F16ToF32(blk->d);
            const size_t base = b * 32;
            const size_t n = (base + 32 <= cols) ? 32 : (cols - base);
            float blockAcc = 0.0f;
            for (size_t i = 0; i < n; ++i)
                blockAcc += (float)blk->qs[i] * x[base + i];
            acc += d * blockAcc;
        }
        y[r] += acc;
    }
}

inline bool RunGemvProbe(const WeightTensor& wt, size_t probeRows,
                         float* out, size_t outCap, bool* finiteOk) {
    *finiteOk = false;
    if (!ByteBoundsOk(wt) || !out || outCap < probeRows) return false;
    const size_t rows = probeRows < wt.rows ? probeRows : wt.rows;
    std::vector<float> x(wt.cols, 0.0f);
    for (size_t i = 0; i < wt.cols; ++i)
        x[i] = 0.01f * (float)((i % 17) + 1);
    std::memset(out, 0, rows * sizeof(float));
    GemvQ8Ref((const uint8_t*)wt.data, x.data(), out, rows, wt.cols);
    for (size_t i = 0; i < rows; ++i) {
        if (!std::isfinite(out[i])) return false;
    }
    *finiteOk = true;
    return true;
}

inline bool ParityOk(const WeightTensor& wt, size_t probeRows) {
    if (!ByteBoundsOk(wt)) return false;
    const size_t rows = probeRows < wt.rows ? probeRows : wt.rows;
    std::vector<float> a(rows, 0.0f), b(rows, 0.0f), x(wt.cols, 0.0f);
    for (size_t i = 0; i < wt.cols; ++i)
        x[i] = 0.01f * (float)((i % 17) + 1);
    GemvQ8Ref((const uint8_t*)wt.data, x.data(), a.data(), rows, wt.cols);
    GemvQ8Ref((const uint8_t*)wt.data, x.data(), b.data(), rows, wt.cols);
    for (size_t i = 0; i < rows; ++i) {
        if (!std::isfinite(a[i]) || std::fabs(a[i] - b[i]) > 1e-5f)
            return false;
    }
    return true;
}

} // namespace detail

inline HostQ8GemvReceipts ProbeHostQ8Gemv(const ModelWeights& mw) {
    HostQ8GemvReceipts r{};
    r.failOwner = "NEMOTRON_H_Q8_GEMV";
    r.nextAction = "fix host Q8_0 LinearW (FFN/attn/ssm_in)";

    const WeightTensor* ffn = nullptr;
    const WeightTensor* attn = nullptr;
    const WeightTensor* ssm = nullptr;
    for (const auto& lw : mw.layers) {
        if (!ffn && WtOk(lw.wUp) && lw.wUp.type == (int)GGMLType::GGML_TYPE_Q8_0)
            ffn = &lw.wUp;
        if (!attn && WtOk(lw.wq) && lw.wq.type == (int)GGMLType::GGML_TYPE_Q8_0)
            attn = &lw.wq;
        if (!ssm && WtOk(lw.ssmIn) && lw.ssmIn.type == (int)GGMLType::GGML_TYPE_Q8_0)
            ssm = &lw.ssmIn;
        if (ffn && attn && ssm) break;
    }

    r.boundsSafe =
        (ffn ? detail::ByteBoundsOk(*ffn) : 1) &&
        (attn ? detail::ByteBoundsOk(*attn) : 1) &&
        (ssm ? detail::ByteBoundsOk(*ssm) : 1);

    constexpr size_t kProbeRows = 4;
    float out[kProbeRows];
    bool fin = false;
    r.numericFinite = 1;

    if (ffn && r.boundsSafe) {
        r.ffn = detail::RunGemvProbe(*ffn, kProbeRows, out, kProbeRows, &fin) ? 1 : 0;
        if (!fin) r.numericFinite = 0;
    } else if (!ffn) {
        r.ffn = 1;
    }

    if (attn && r.boundsSafe) {
        bool fin2 = false;
        r.attn = detail::RunGemvProbe(*attn, kProbeRows, out, kProbeRows, &fin2) ? 1 : 0;
        if (!fin2) r.numericFinite = 0;
    } else if (!attn) {
        r.attn = 1;
    }

    if (ssm && r.boundsSafe) {
        bool fin3 = false;
        r.ssmIn = detail::RunGemvProbe(*ssm, kProbeRows, out, kProbeRows, &fin3) ? 1 : 0;
        if (!fin3) r.numericFinite = 0;
    } else if (!ssm) {
        r.ssmIn = 1;
    }

    r.referenceParity = 1;
    if (ffn) r.referenceParity &= detail::ParityOk(*ffn, kProbeRows) ? 1 : 0;
    if (attn) r.referenceParity &= detail::ParityOk(*attn, kProbeRows) ? 1 : 0;
    if (ssm) r.referenceParity &= detail::ParityOk(*ssm, kProbeRows) ? 1 : 0;

    r.safe = r.ffn && r.attn && r.ssmIn && r.numericFinite &&
             r.boundsSafe && r.referenceParity;
    if (!r.safe) {
        if (!r.boundsSafe) {
            r.failOwner = "HOST_Q8_GEMV_BOUNDS";
            r.nextAction = "verify Q8_0 sizeBytes >= rows*((cols+31)/32)*34";
        } else if (!r.ffn) {
            r.failOwner = "HOST_Q8_GEMV_FFN";
            r.nextAction = "fix Q8_0 GEMV on ffn_up";
        } else if (!r.attn) {
            r.failOwner = "HOST_Q8_GEMV_ATTN";
            r.nextAction = "fix Q8_0 GEMV on attn_q";
        } else if (!r.ssmIn) {
            r.failOwner = "HOST_Q8_GEMV_SSM_IN";
            r.nextAction = "fix Q8_0 GEMV on ssm_in";
        } else if (!r.numericFinite) {
            r.failOwner = "HOST_Q8_GEMV_NUMERIC";
            r.nextAction = "ensure finite Q8_0 GEMV outputs";
        } else {
            r.failOwner = "HOST_Q8_GEMV_PARITY";
            r.nextAction = "match reference Q8_0 GEMV";
        }
    }
    return r;
}

inline void EmitHostQ8GemvReceipts(FILE* f, const HostQ8GemvReceipts& r) {
    if (!f) return;
    std::fprintf(f,
        "HOST_Q8_GEMV_FFN=%d\nHOST_Q8_GEMV_ATTN=%d\nHOST_Q8_GEMV_SSM_IN=%d\n"
        "HOST_Q8_GEMV_NUMERIC_FINITE=%d\nHOST_Q8_GEMV_BOUNDS_SAFE=%d\n"
        "HOST_Q8_GEMV_REFERENCE_PARITY=%d\nHOST_Q8_GEMV_SAFE=%d\n",
        r.ffn, r.attn, r.ssmIn, r.numericFinite, r.boundsSafe,
        r.referenceParity, r.safe);
    if (!r.safe)
        std::fprintf(f, "HOST_Q8_FAIL_OWNER=%s\nNEXT_ACTION=%s\n",
                     r.failOwner ? r.failOwner : "?",
                     r.nextAction ? r.nextAction : "?");
    std::fflush(f);
}

} // namespace Deep2
