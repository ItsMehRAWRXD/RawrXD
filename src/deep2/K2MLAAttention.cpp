// K2MLAAttention.cpp — Gate 12 RoPE + softmax + KV attention
#include "K2MLAAttention.hpp"
#include "K2KVCache.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace Deep2 {
namespace {

bool MlaDiagEnabled() {
    static const bool enabled = [] {
        const char* value = std::getenv("RAWRXD_MLA_DIAGNOSTICS");
        return value && (std::strcmp(value, "1") == 0 ||
                         std::strcmp(value, "true") == 0 ||
                         std::strcmp(value, "TRUE") == 0);
    }();
    return enabled;
}

template <typename... Args>
void MlaDiag(const char* format, Args... args) {
    if (!MlaDiagEnabled()) return;
    std::fprintf(stderr, format, args...);
    std::fflush(stderr);
}

void ropeNeoXInplace(float* x, size_t dim, uint32_t pos,
                     float theta, float scale) {
    if (dim < 2 || (dim & 1u)) return;
    const size_t half = dim / 2;
    const float invScale = (scale > 0.0f) ? (1.0f / scale) : 1.0f;
    const float effectivePos = static_cast<float>(pos) * invScale;
    for (size_t i = 0; i < half; ++i) {
        const float freq = 1.0f / powf(theta, (2.0f * static_cast<float>(i)) /
                                              static_cast<float>(dim));
        const float angle = effectivePos * freq;
        const float c = cosf(angle);
        const float s = sinf(angle);
        const float x0 = x[i];
        const float x1 = x[i + half];
        x[i] = x0 * c - x1 * s;
        x[i + half] = x0 * s + x1 * c;
    }
}

bool softmaxInplaceFinite(float* x, size_t n) {
    if (!x || n == 0) return false;
    float mx = x[0];
    for (size_t i = 1; i < n; ++i) if (x[i] > mx) mx = x[i];
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) {
        x[i] = expf(x[i] - mx);
        sum += static_cast<double>(x[i]);
    }
    if (!(sum > 0.0) || !std::isfinite(sum)) return false;
    const float inv = static_cast<float>(1.0 / sum);
    for (size_t i = 0; i < n; ++i) {
        x[i] *= inv;
        if (!std::isfinite(x[i])) return false;
    }
    return true;
}

bool reportNonFinite(const char* stage, const float* values, size_t count,
                    uint32_t layer, uint32_t position, size_t head = SIZE_MAX) {
    if (!values) return true;
    for (size_t i = 0; i < count; ++i) {
        if (!std::isfinite(values[i])) {
            std::fprintf(stderr,
                         "[MLA_NONFINITE] stage=%s layer=%u position=%u head=%s index=%zu value=%g count=%zu\n",
                         stage, layer, position,
                         head == SIZE_MAX ? "all" : std::to_string(head).c_str(),
                         i, static_cast<double>(values[i]), count);
            std::fflush(stderr);
            return false;
        }
    }
    return true;
}

} // namespace

bool MlaAttentionComplete(
    const float* q_b, const float* k_b, const float* v_b, float* k_pe,
    float* attnOut,
    size_t numHeads, size_t qkNopeHeadDim, size_t qkRopeHeadDim,
    size_t vHeadDim, size_t qHeadDim,
    uint32_t position, float ropeTheta, float ropeScale,
    rawrxd::deep2::K2KVCache* kvCache, uint32_t layerIdx,
    MlaCompleteStats* stats, std::string& error) {
    if (!q_b || !k_b || !v_b || !k_pe || !attnOut || !kvCache) {
        error = "MlaAttentionComplete: null argument";
        return false;
    }
    if (numHeads == 0 || qkNopeHeadDim == 0 || qkRopeHeadDim == 0 || vHeadDim == 0) {
        error = "MlaAttentionComplete: zero dimension";
        return false;
    }
    if (qHeadDim < qkNopeHeadDim + qkRopeHeadDim) {
        error = "MlaAttentionComplete: q head too small for nope+rope";
        return false;
    }

    const size_t qkDim = qkNopeHeadDim + qkRopeHeadDim;
    const size_t kPack = numHeads * qkDim;
    const size_t vPack = numHeads * vHeadDim;
    const size_t kvDim = (std::max)(kPack, vPack);
    MlaDiag(
        "[MLA_KV_GEOMETRY] cacheDim=%zu expectedDim=%zu heads=%zu nope=%zu rope=%zu vDim=%zu "
        "qkDim=%zu kPack=%zu vPack=%zu layerIdx=%zu numLayers=%zu\n",
        kvCache->kvDim(), kvDim, numHeads, qkNopeHeadDim, qkRopeHeadDim, vHeadDim,
        qkDim, kPack, vPack, layerIdx, kvCache->numLayers());
    if (kvCache->kvDim() != kvDim || layerIdx >= kvCache->numLayers()) {
        error = "MlaAttentionComplete: KV cache geometry mismatch";
        return false;
    }
    if (!reportNonFinite("q_b", q_b, numHeads * qHeadDim, layerIdx, position) ||
        !reportNonFinite("k_b", k_b, numHeads * qkNopeHeadDim, layerIdx, position) ||
        !reportNonFinite("v_b", v_b, numHeads * vHeadDim, layerIdx, position) ||
        !reportNonFinite("k_pe", k_pe, qkRopeHeadDim, layerIdx, position)) {
        error = "MlaAttentionComplete: non-finite input";
        return false;
    }
    if (!kvCache->CanAppend()) {
        error = "MlaAttentionComplete: KV cache full";
        return false;
    }

    MlaDiag("[MLA_ATTENTION] layer=%u pos=%u heads=%zu qkDim=%zu kvDim=%zu seqLen=%zu\n",
            layerIdx, position, numHeads, qkDim, kvDim, kvCache->currentLength() + 1);

    ropeNeoXInplace(k_pe, qkRopeHeadDim, position, ropeTheta, ropeScale);
    if (!reportNonFinite("k_pe_rope", k_pe, qkRopeHeadDim, layerIdx, position)) {
        error = "MlaAttentionComplete: non-finite rotary key";
        return false;
    }
    MlaDiag("[MLA_ATTENTION] layer=%u rope done\n", layerIdx);

    std::vector<float> qFull(numHeads * qkDim);
    std::vector<float> kCur(kvDim, 0.0f);
    std::vector<float> vCur(kvDim, 0.0f);
    MlaDiag("[MLA_ATTENTION] layer=%u buffers allocated\n", layerIdx);

    for (size_t h = 0; h < numHeads; ++h) {
        const float* qh = q_b + h * qHeadDim;
        float* qd = qFull.data() + h * qkDim;
        memcpy(qd, qh, qkNopeHeadDim * sizeof(float));
        memcpy(qd + qkNopeHeadDim, qh + qkNopeHeadDim, qkRopeHeadDim * sizeof(float));
        ropeNeoXInplace(qd + qkNopeHeadDim, qkRopeHeadDim, position, ropeTheta, ropeScale);

        if (!reportNonFinite("q_full", qd, qkDim, layerIdx, position, h)) {
            error = "MlaAttentionComplete: non-finite query";
            return false;
        }

        float* kh = kCur.data() + h * qkDim;
        memcpy(kh, k_b + h * qkNopeHeadDim, qkNopeHeadDim * sizeof(float));
        memcpy(kh + qkNopeHeadDim, k_pe, qkRopeHeadDim * sizeof(float));
        memcpy(vCur.data() + h * vHeadDim, v_b + h * vHeadDim, vHeadDim * sizeof(float));
    }

    try {
        kvCache->Write(layerIdx, kCur.data(), vCur.data());
    } catch (const std::exception& ex) {
        error = std::string("MlaAttentionComplete: KV write: ") + ex.what();
        return false;
    }
    if (!reportNonFinite("k_cache_write", kCur.data(), kPack, layerIdx, position) ||
        !reportNonFinite("v_cache_write", vCur.data(), vPack, layerIdx, position)) {
        error = "MlaAttentionComplete: non-finite KV write";
        return false;
    }
    MlaDiag("[MLA_ATTENTION] layer=%u KV write done\n", layerIdx);

    const size_t seqLen = kvCache->currentLength() + 1;
    const float scale = 1.0f / sqrtf(static_cast<float>(qkDim));
    std::vector<float> scores(seqLen);
    memset(attnOut, 0, vPack * sizeof(float));

    for (size_t h = 0; h < numHeads; ++h) {
        const float* qh = qFull.data() + h * qkDim;
        for (size_t t = 0; t < seqLen; ++t) {
            const float* kh = kvCache->Key(layerIdx, t) + h * qkDim;
            double dot = 0.0;
            for (size_t d = 0; d < qkDim; ++d)
                dot += static_cast<double>(qh[d]) * static_cast<double>(kh[d]);
            scores[t] = static_cast<float>(dot) * scale;
        }
        if (!reportNonFinite("scores", scores.data(), seqLen, layerIdx, position, h)) {
            error = "MlaAttentionComplete: non-finite attention score";
            return false;
        }
        if (h % 16 == 0) {
            MlaDiag("[MLA_ATTENTION] layer=%u head %zu done, seqLen=%zu\n",
                    layerIdx, h, seqLen);
        }
        if (!softmaxInplaceFinite(scores.data(), seqLen)) {
            error = "MlaAttentionComplete: softmax non-finite";
            return false;
        }
        float* oh = attnOut + h * vHeadDim;
        for (size_t t = 0; t < seqLen; ++t) {
            const float* vh = kvCache->Value(layerIdx, t) + h * vHeadDim;
            const float a = scores[t];
            for (size_t d = 0; d < vHeadDim; ++d) oh[d] += a * vh[d];
        }
    }

    MlaDiag("[MLA_ATTENTION] layer=%u all %zu heads done\n",
            layerIdx, numHeads);

    if (stats) {
        stats->ropeApplied = true;
        stats->softmaxFinite = true;
        stats->kvCacheWrite = true;
        stats->kvCacheRead = true;
        stats->kvLength = static_cast<uint32_t>(seqLen);
    }
    return true;
}

} // namespace Deep2
