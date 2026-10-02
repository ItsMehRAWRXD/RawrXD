// ============================================================================
// AttnCtx2Probe.h
//   RAWRXD_ATTN_CTX2_PROBE_001
//
//   The CTX=1 -> CTX=2 transition is the smallest reproducer of the Vulkan
//   attention defect. At one visible slot the softmax collapses to probability
//   1.0, so the output is V[0] and a large class of kernel bugs is invisible:
//   score stride, K position stride, GQA head mapping after position 0,
//   reduction lanes, max reduction, denominator reduction, scratch reuse,
//   probability row indexing, and value accumulation beyond position 0.
//
//   This instrument emits the four objects the classification needs, from three
//   independent sources, so the first wrong scalar is identifiable:
//
//     side=cpu         the production CPU attention, in double-accumulated
//                      float64 (what the product is supposed to compute)
//     side=gpu_model   the Vulkan kernel's ALGORITHM, evaluated on the host in
//                      float32 with the kernel's own loop order and its own
//                      position-major cache layout, from the exact device bytes
//                      the kernel was given
//     side=gpu_arena   what the device actually produced
//
//   gpu_model is the pivot. It separates the two hypotheses that a bare
//   cpu-vs-arena comparison cannot:
//
//     gpu_model == gpu_arena, gpu_model != cpu
//         -> the kernel faithfully implements its own algorithm; the defect is
//            in the ALGORITHM or the LAYOUT it uses, and is now reduced to a
//            few lines of arithmetic.
//     gpu_model != gpu_arena
//         -> the kernel does not do what its own source says it does, which is
//            a race, a descriptor/buffer mix-up, or a fused-window publication
//            problem -- a different class of defect with a different fix.
//
//   Gated on RAWRXD_ATTN_CTX2_PROBE=1, default OFF. Performs device readbacks
//   and breaks the fused window, so it is a correctness instrument only.
// ============================================================================
#pragma once

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace Deep2 {
namespace Ctx2 {

// Positions to capture. 0 is the control (must agree) and 1 is the reproducer.
static const int kPositions[] = {0, 1};
static const int kPositionCount = 2;

inline bool envOn(const char* name) {
    const char* v = std::getenv(name);
    return v && v[0] && v[0] != '0';
}

inline std::FILE* file() {
    static std::FILE* f = nullptr;
    static bool tried = false;
    if (tried) return f;
    tried = true;
    if (!envOn("RAWRXD_ATTN_CTX2_PROBE")) return nullptr;
    const char* out = std::getenv("RAWRXD_ATTN_CTX2_PROBE_OUT");
    f = std::fopen(out && *out ? out : "attn_ctx2_probe.txt", "wb");
    if (f) {
        std::fprintf(f,
            "# RAWRXD_ATTN_CTX2_PROBE v1 positions=0,1 "
            "sides=cpu,gpu_model,gpu_arena\n");
        std::fflush(f);
        std::fprintf(stderr,
            "[CTX2] ON out=%s (device readback per head; NOT a throughput instrument)\n",
            out && *out ? out : "attn_ctx2_probe.txt");
        std::fflush(stderr);
        std::atexit([]{ if (f) { std::fflush(f); std::fclose(f); f = nullptr; } });
    } else {
        std::fprintf(stderr, "[CTX2] FAIL cannot open output file\n");
        std::fflush(stderr);
    }
    return f;
}

inline bool active() { return file() != nullptr; }

inline bool wantsPosition(int pos) {
    if (!active()) return false;
    for (int i = 0; i < kPositionCount; ++i) {
        if (kPositions[i] == pos) return true;
    }
    return false;
}

inline uint64_t fnv1a(const float* v, size_t n) {
    uint64_t h = 1469598103934665603ull;
    const auto* b = reinterpret_cast<const uint8_t*>(v);
    for (size_t i = 0; i < n * sizeof(float); ++i) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}

// One head, one position, one source.
struct Record {
    int    step = 0;
    int    ctx  = 0;
    const char* side = "";
    int    layer = 0;
    int    qHead = 0;
    int    kvHead = 0;
    int    gqaGroup = 1;
    int    headDim = 0;
    std::vector<float> scoreRaw;
    std::vector<float> scoreScaled;
    std::vector<float> prob;
    std::vector<float> out;      // headDim values
    // Which BYTES each side used, per head. A score is a function of the input
    // bytes, so when two sides disagree on a score the next question is always
    // whether they used the same Q/K/V, and these three hashes answer it
    // directly instead of by inference. Q is hashed over this head's own span;
    // K and V over this head's KV span inside the slot it read.
    uint64_t qHash = 0, kHash = 0, vHash = 0;
    // The first 8 elements of each input span, not just its hash. A hash
    // answers "are these the same bytes"; it cannot answer "how far apart are
    // they", and two sides that differ only in the last bits still produce
    // different hashes. These are what let a near-zero score be separated from
    // a genuinely wrong one.
    std::vector<float> qF8, kF8, vF8;
};

// Emits SCORE_RAW / SCORE_SCALED / SOFTMAX_PROB / ATTN_VALUE for one head, with
// the GQA identities that the classification needs to tell a head-mapping bug
// from a dot-product bug.
inline void emit(const Record& r) {
    std::FILE* f = file();
    if (!f) return;
    double l2 = 0.0;
    for (size_t i = 0; i < r.out.size(); ++i) l2 += (double)r.out[i] * (double)r.out[i];

    std::fprintf(f, "CTX2 step=%d ctx=%d side=%s layer=%d q_head=%d kv_head=%d "
                   "gqa_group=%d head_dim=%d ",
                 r.step, r.ctx, r.side, r.layer, r.qHead, r.kvHead,
                 r.gqaGroup, r.headDim);
    const char* names[3] = {"SCORE_RAW", "SCORE_SCALED", "SOFTMAX_PROB"};
    const std::vector<float>* vals[3] = {&r.scoreRaw, &r.scoreScaled, &r.prob};
    for (int k = 0; k < 3; ++k) {
        std::fprintf(f, "%s=", names[k]);
        for (size_t i = 0; i < vals[k]->size(); ++i) {
            std::fprintf(f, "%s%.9g", i ? "," : "", (double)(*vals[k])[i]);
        }
        std::fprintf(f, " ");
    }
    std::fprintf(f, "ATTN_VALUE_L2=%.9g ATTN_VALUE_HASH=%016llx ATTN_VALUE_F8=",
                 std::sqrt(l2), (unsigned long long)fnv1a(r.out.data(), r.out.size()));
    for (size_t i = 0; i < r.out.size() && i < 8; ++i) {
        std::fprintf(f, "%s%.9g", i ? "," : "", (double)r.out[i]);
    }
    std::fprintf(f, " Q_HASH=%016llx K_HASH=%016llx V_HASH=%016llx",
                 (unsigned long long)r.qHash, (unsigned long long)r.kHash,
                 (unsigned long long)r.vHash);
    const char* fn[3] = {"Q_F8", "K_F8", "V_F8"};
    const std::vector<float>* fv[3] = {&r.qF8, &r.kF8, &r.vF8};
    for (int k = 0; k < 3; ++k) {
        std::fprintf(f, " %s=", fn[k]);
        for (size_t i = 0; i < fv[k]->size(); ++i) {
            std::fprintf(f, "%s%.9g", i ? "," : "", (double)(*fv[k])[i]);
        }
    }
    std::fprintf(f, "\n");
    std::fflush(f);
}

// ---- the GPU algorithm, evaluated on the host in the kernel's own terms ----
//
// float32 accumulation, the kernel's loop order, and the kernel's
// position-major cache indexing: kb = layerBase + t*kvDim + kh*headDim.
// If this reproduces the device arena, the kernel is faithful to its source.
inline void emitGpuModelSide(int step, size_t pos, size_t layer,
                             const std::vector<float>& qArena,   // [heads][headDim]
                             const std::vector<std::vector<float>>& kBySlot,  // [slot][kvDim]
                             const std::vector<std::vector<float>>& vBySlot,  // [slot][kvDim]
                             size_t numHeads, size_t numKVHeads, size_t headDim,
                             float scale) {
    if (!wantsPosition(static_cast<int>(pos))) return;
    const size_t kvDim = numKVHeads * headDim;
    const size_t ctx = kBySlot.size();
    const size_t gqa = numHeads / (numKVHeads ? numKVHeads : 1);
    for (size_t h = 0; h < numHeads; ++h) {
        const size_t kh = h / gqa;
        Record r;
        r.step = static_cast<int>(pos);
        r.ctx = static_cast<int>(ctx);
        r.side = "gpu_model";
        r.layer = static_cast<int>(layer);
        r.qHead = static_cast<int>(h);
        r.kvHead = static_cast<int>(kh);
        r.gqaGroup = static_cast<int>(gqa);
        r.headDim = static_cast<int>(headDim);
        r.scoreRaw.resize(ctx);
        r.scoreScaled.resize(ctx);
        r.prob.resize(ctx);
        float maxScore = -3.402823466e+38f;
        for (size_t t = 0; t < ctx; ++t) {
            const float* kb = kBySlot[t].data() + kh * headDim;
            const float* qb = qArena.data() + h * headDim;
            float s = 0.0f;
            for (size_t j = 0; j < headDim; ++j) s += qb[j] * kb[j];
            r.scoreRaw[t] = s;
            r.scoreScaled[t] = s * scale;
            maxScore = r.scoreScaled[t] > maxScore ? r.scoreScaled[t] : maxScore;
        }
        float denom = 0.0f;
        float numer = 0.0f;
        std::vector<float> e(ctx);
        for (size_t t = 0; t < ctx; ++t) {
            e[t] = std::exp(r.scoreScaled[t] - maxScore);
            denom += e[t];
        }
        r.out.assign(headDim, 0.0f);
        for (size_t t = 0; t < ctx; ++t) {
            const float* vb = vBySlot[t].data() + kh * headDim;
            const float a = e[t] / denom;
            r.prob[t] = a;
            for (size_t d = 0; d < headDim; ++d) r.out[d] += a * vb[d];
        }
        (void)numer;
        // The bytes this head actually consumed, so the join can answer "did
        // the two sides use the same inputs" without inferring it from a score.
        r.qHash = fnv1a(qArena.data() + h * headDim, headDim);
        r.kHash = fnv1a(kBySlot[ctx - 1].data() + kh * headDim, headDim);
        r.vHash = fnv1a(vBySlot[ctx - 1].data() + kh * headDim, headDim);
        r.qF8.assign(qArena.begin() + h * headDim,
                     qArena.begin() + h * headDim + std::min<size_t>(8, headDim));
        r.kF8.assign(kBySlot[ctx - 1].begin() + kh * headDim,
                     kBySlot[ctx - 1].begin() + kh * headDim + std::min<size_t>(8, headDim));
        r.vF8.assign(vBySlot[ctx - 1].begin() + kh * headDim,
                     vBySlot[ctx - 1].begin() + kh * headDim + std::min<size_t>(8, headDim));
        emit(r);
    }
}

// What the device actually produced, per query head.
inline void emitGpuArenaSide(int step, size_t pos, size_t layer,
                             const std::vector<float>& attnArena, // [heads][headDim]
                             size_t numHeads, size_t numKVHeads, size_t headDim) {
    if (!wantsPosition(static_cast<int>(pos))) return;
    const size_t ctx = pos + 1;
    const size_t gqa = numHeads / (numKVHeads ? numKVHeads : 1);
    for (size_t h = 0; h < numHeads; ++h) {
        Record r;
        r.step = static_cast<int>(pos);
        r.ctx = static_cast<int>(ctx);
        r.side = "gpu_arena";
        r.layer = static_cast<int>(layer);
        r.qHead = static_cast<int>(h);
        r.kvHead = static_cast<int>(h / gqa);
        r.gqaGroup = static_cast<int>(gqa);
        r.headDim = static_cast<int>(headDim);
        // The arena carries no scores or probabilities: attention is fused, so
        // they never exist in device memory. They are emitted as the explicit
        // token UNAVAILABLE rather than as zeros, because a zero would be
        // indistinguishable from a real score.
        r.scoreRaw.assign(ctx, std::nanf(""));
        r.scoreScaled.assign(ctx, std::nanf(""));
        r.prob.assign(ctx, std::nanf(""));
        r.out.assign(attnArena.begin() + h * headDim,
                     attnArena.begin() + (h + 1) * headDim);
        // The arena carries no Q/K/V hashes: the kernel consumed them, and the
        // probe that reads them back is what supplies them, so asserting them
        // here would be circular. Emitted as 0 with a note rather than omitted.
        std::FILE* f = file();
        if (!f) return;
        double l2 = 0.0;
        for (size_t i = 0; i < r.out.size(); ++i) l2 += (double)r.out[i] * (double)r.out[i];
        std::fprintf(f,
            "CTX2 step=%d ctx=%d side=gpu_arena layer=%d q_head=%d kv_head=%d "
            "gqa_group=%d head_dim=%d SCORE_RAW=UNAVAILABLE:NO_DEVICE_ARENA "
            "SCORE_SCALED=UNAVAILABLE:NO_DEVICE_ARENA "
            "SOFTMAX_PROB=UNAVAILABLE:NO_DEVICE_ARENA "
            "ATTN_VALUE_L2=%.9g ATTN_VALUE_HASH=%016llx ATTN_VALUE_F8=",
            r.step, r.ctx, r.layer, r.qHead, r.kvHead, r.gqaGroup, r.headDim,
            std::sqrt(l2), (unsigned long long)fnv1a(r.out.data(), r.out.size()));
        for (size_t i = 0; i < r.out.size() && i < 8; ++i) {
            std::fprintf(f, "%s%.9g", i ? "," : "", (double)r.out[i]);
        }
        std::fprintf(f, " Q_HASH=UNAVAILABLE K_HASH=UNAVAILABLE V_HASH=UNAVAILABLE "
                        "Q_F8=UNAVAILABLE K_F8=UNAVAILABLE V_F8=UNAVAILABLE\n");
        std::fflush(f);
    }
}

}  // namespace Ctx2
}  // namespace Deep2
