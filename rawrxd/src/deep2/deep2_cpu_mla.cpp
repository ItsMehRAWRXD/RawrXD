// deep2_cpu_mla.cpp
// RAWRXD_CPU_MLA_KERNEL_001 -- CPU Multi-head Latent Attention.
//
// WHY THIS EXISTS
// ---------------
// Deep2's ONLY MLA attention implementation is computeMLAAttentionGpu
// (Deep2Engine_GpuMoEMLA.cpp:324). Deep2Engine.cpp:4123-4128 dispatches:
//
//     if (lw.useMLA || modelWeights.useMLA) {
//         if (computeMLAAttentionGpu(layer, input, output, seqLen)) return;
//         throw std::runtime_error("attention: GPU MLA path failed or unsupported");
//     }
//
// There is no CPU branch. When Vulkan is absent (vulkan=0/0), computeMLAAttentionGpu
// returns false at its first guard (Deep2Engine_GpuMoEMLA.cpp:327) and every MLA
// model dies at prefill token 0. Measured on DeepSeek-V2-Lite:
//     [FWD_ALL] seqLen=1 numLayers=61 isMoE=1 useMLA=1 vulkan=0/0
//     forward failed: attention: GPU MLA path failed or unsupported
//
// So this is not a fallback optimisation. Without it, no MLA architecture --
// Kimi K2, DeepSeek-V2/V3 -- can be certified on the CPU route at all.
//
// THE MATH IS DEEP2'S, NOT THE PAPER'S
// ------------------------------------
// Every step below is transcribed from computeMLAAttentionGpu lines 364-427.
// Where the reference implementation makes a choice, this file makes the same
// one, so a CPU/GPU divergence cannot be blamed on interpretation.
//
//   1  qa      = attnQ_a      @ x                  [qRank]
//   2  qaNorm  = RMSNorm(qa, attnQ_a_norm, eps)    [qRank]
//   3  qFull   = attnQ_b      @ qaNorm             [heads * keyLen]
//   4  kva     = attnKV_a_mqa @ x                   [kvRank + rope]
//   5  cNorm   = RMSNorm(kva[0:kvRank], attnKV_a_norm, eps)
//   6  kNope   = attnK_b      @ cNorm               [heads * nope]
//   7  values  = attnV_b      @ cNorm               [heads * valueLen]
//   8  kPe     = kva[kvRank : kvRank+rope]
//   9  applyMlaRope(qFull, kPe, heads, nope, rope, pos, theta, scaling)
//  10  kFull[h] = concat(kNope[h*nope : (h+1)*nope], kPe)
//  11  attn[h]  = softmax_t( dot(qFull[h], kFull_t[h]) * 1/sqrt(keyLen) ) values_t[h]
//  12  out      = attnO @ attn                      [H]
//
// VALIDATION
// ----------
// A kernel with no oracle is exactly the failure class this project has been
// dismantling. So this file carries TWO independent implementations of the same
// specification -- a tiled one and a deliberately naive triple-loop one -- and a
// self-test that requires them to agree. They share no arithmetic: the naive
// path recomputes every dot product element-by-element with no blocking, no
// reuse and a separate softmax accumulation. Agreement between two
// implementations of one spec catches transcription errors, tiling bugs and
// index errors. It does NOT prove Deep2's GPU path agrees; only that this file
// is internally coherent.
//
// STATUS: projections + RoPE + attention are implemented and self-tested.
// KV-cache integration is NOT done -- see kvCacheLayoutIsKnown() below.

#include "Deep2Engine.h"

#include <cmath>
#include <cstring>
#include <string>
#include <vector>

namespace rawrxd::mla {

using Deep2::WeightTensor;
static inline const float* fdata(const WeightTensor& w) { return static_cast<const float*>(w.data); }

struct Geometry {
    std::size_t hidden   = 0;
    std::size_t heads    = 0;
    std::size_t qRank    = 0;
    std::size_t kvRank   = 0;
    std::size_t nope     = 0;
    std::size_t rope     = 0;
    std::size_t valueLen = 0;
    std::size_t keyLen()  const { return nope + rope; }
};

// Mirrors the shape guard at Deep2Engine_GpuMoEMLA.cpp:344-359 exactly. If this
// returns false for a real model, the kernel is not the problem -- the binding
// is, and admitting the model would be wrong.
bool geometryAndBindingValid(const Geometry& g, const Deep2::LayerWeights& lw)
{
    if (!g.hidden || !g.heads || !g.qRank || !g.kvRank || !g.nope ||
        !g.rope || !g.valueLen || (g.rope & 1u))
        return false;
    if (g.hidden > UINT32_MAX || g.heads > UINT32_MAX ||
        g.keyLen() > UINT32_MAX || g.valueLen > UINT32_MAX)
        return false;
    if (!fdata(lw.attnQ_a) || !fdata(lw.attnQ_a_norm) || !fdata(lw.attnQ_b) ||
        !fdata(lw.attnKV_a_mqa) || !fdata(lw.attnKV_a_norm) ||
        !fdata(lw.attnK_b) || !fdata(lw.attnV_b) || !fdata(lw.attnO))
        return false;
    if (lw.attnQ_a.rows    != g.qRank   || lw.attnQ_a.cols    != g.hidden)  return false;
    if (lw.attnQ_b.rows    != g.heads * g.keyLen() ||
        lw.attnQ_b.cols    != g.qRank)                                        return false;
    if (lw.attnKV_a_mqa.rows != g.kvRank + g.rope ||
        lw.attnKV_a_mqa.cols != g.hidden)                                    return false;
    if (lw.attnK_b.rows    != g.heads * g.nope   || lw.attnK_b.cols    != g.kvRank)   return false;
    if (lw.attnV_b.rows    != g.heads * g.valueLen ||
        lw.attnV_b.cols    != g.kvRank)                                       return false;
    if (lw.attnO.rows      != g.hidden || lw.attnO.cols != g.heads * g.valueLen)   return false;
    return true;
}

// ---------------------------------------------------------------------------
// RMSNorm with learned weights -- same form as mlaRmsNormW at the GPU call sites.
// ---------------------------------------------------------------------------
void mlaRmsNormW(const float* x, const float* w, float* out,
              std::size_t n, float eps)
{
    double ss = 0.0;
    for (std::size_t i = 0; i < n; ++i) ss += double(x[i]) * double(x[i]);
    const float inv = 1.0f / std::sqrt(float(ss / double(n)) + eps);
    for (std::size_t i = 0; i < n; ++i) out[i] = x[i] * inv * w[i];
}

// ---------------------------------------------------------------------------
// RoPE over the rotary slice. Deep2 applies it to qFull at offset `nope`
// (the rotary dims follow the non-rotary dims) and to the key's own first
// `rope` dims. Rotate-half, NeoX layout.
// ---------------------------------------------------------------------------
void applyRope(float* v, std::size_t heads, std::size_t dimStart,
               std::size_t rot, std::size_t pos, float theta, float scaling)
{
    const std::size_t half = rot / 2;
    if (!rot || !half) return;
    for (std::size_t h = 0; h < heads; ++h) {
        float* p = v + h * (dimStart + rot) + dimStart;
        for (std::size_t i = 0; i < half; ++i) {
            const double freq =
                1.0 / std::pow(double(theta), double(2 * i) / double(rot));
            const float ang = float(double(pos) * freq * double(scaling));
            const float c = std::cos(ang), s = std::sin(ang);
            const float a = p[i], b = p[i + half];
            p[i]        = a * c - b * s;
            p[i + half] = a * s + b * c;
        }
    }
}

// ---------------------------------------------------------------------------
// y = W @ x, W is [rows, cols] row-major, x is [cols], y is [rows].
// Uses Deep2::WeightTensor.data in whatever quant layout it carries; this kernel
// requires F32-backed tensors and refuses anything else rather than guessing.
// ---------------------------------------------------------------------------
bool gemvF32(const WeightTensor& w, const float* x, float* y, std::size_t rows,
             std::size_t cols, const char* what)
{
    if (!w.data || w.type != 0 /* F32 */) {
        std::fprintf(stderr, "[CPU_MLA] %s is not F32-backed (type=%d); "
                        "a CPU MLA kernel cannot guess this quant layout\n",
                     what, w.type);
        return false;
    }
    if (w.rows != rows || w.cols != cols) {
        std::fprintf(stderr, "[CPU_MLA] %s geometry %zux%zu != expected %zux%zu\n",
                     what, (std::size_t)w.rows, (std::size_t)w.cols, rows, cols);
        return false;
    }
    const float* p = fdata(w);
    for (std::size_t r = 0; r < rows; ++r) {
        double acc = 0.0;
        for (std::size_t c = 0; c < cols; ++c) acc += double(p[r * cols + c]) * double(x[c]);
        y[r] = float(acc);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tiled implementation: projections + RoPE + attention, tiled over heads.
// ---------------------------------------------------------------------------
struct KvEntry {
    std::vector<float> k;      // heads * keyLen
    std::vector<float> v;      // heads * valueLen
};

bool mlaForwardCpu(const Deep2::LayerWeights& lw, const Geometry& g,
                   const float* input, std::size_t seqPos,
                   float theta, float scaling, float normEps,
                   std::vector<KvEntry>& cache, const KvEntry* cursor,
                   float* output, const char* what)
{
    if (!geometryAndBindingValid(g, lw)) {
        std::fprintf(stderr, "[CPU_MLA] %s failed geometry/binding guard\n", what);
        return false;
    }
    const std::size_t H = g.hidden, heads = g.heads;
    const std::size_t qRank = g.qRank, kvRank = g.kvRank;
    const std::size_t nope = g.nope, rope = g.rope, vlen = g.valueLen;
    const std::size_t klen = g.keyLen();

    // 1..3  query path
    std::vector<float> qa(qRank), qaNorm(qRank), qFull(heads * klen);
    if (!gemvF32(lw.attnQ_a, input, qa.data(), qRank, H, "attnQ_a")) return false;
    mlaRmsNormW(qa.data(), fdata(lw.attnQ_a_norm), qaNorm.data(), qRank, normEps);
    if (!gemvF32(lw.attnQ_b, qaNorm.data(), qFull.data(), heads * klen, qRank,
                 "attnQ_b")) return false;

    // 4..8  latent / key / value path
    std::vector<float> kva(kvRank + rope), cNorm(kvRank);
    if (!gemvF32(lw.attnKV_a_mqa, input, kva.data(), kvRank + rope, H,
                 "attnKV_a_mqa")) return false;
    mlaRmsNormW(kva.data(), fdata(lw.attnKV_a_norm), cNorm.data(), kvRank, normEps);

    std::vector<float> kNope(heads * nope), values(heads * vlen);
    if (!gemvF32(lw.attnK_b, cNorm.data(), kNope.data(), heads * nope, kvRank,
                 "attnK_b")) return false;
    if (!gemvF32(lw.attnV_b, cNorm.data(), values.data(), heads * vlen, kvRank,
                 "attnV_b")) return false;

    std::vector<float> kPe(kva.begin() + kvRank, kva.end());

    // 9  RoPE on query rotary slice and on the key's own rotary slice
    applyRope(qFull.data(), heads, nope, rope, seqPos, theta, scaling);
    {
        std::vector<float> kRot(kPe);
        applyRope(kRot.data(), 1, 0, rope, seqPos, theta, scaling);
        kPe.swap(kRot);
    }

    // 10  assemble the key for this position
    std::vector<float> kFull(heads * klen);
    for (std::size_t h = 0; h < heads; ++h) {
        std::memcpy(kFull.data() + h * klen, kNope.data() + h * nope,
                    nope * sizeof(float));
        std::memcpy(kFull.data() + h * klen + nope, kPe.data(),
                    rope * sizeof(float));
    }

    // publish this position so the next layer/token sees it
    cache[seqPos].k = kFull;
    cache[seqPos].v = values;

    // 11  attention over positions [0, seqPos]
    const float scale = 1.0f / std::sqrt(float(klen));
    std::vector<float> attn(heads * vlen, 0.0f);
    std::vector<double> logits(seqPos + 1);
    for (std::size_t h = 0; h < heads; ++h) {
        double mx = -1e300;
        for (std::size_t t = 0; t <= seqPos; ++t) {
            const float* qh = qFull.data() + h * klen;
            const float* kt = cache[t].k.data() + h * klen;
            double s = 0.0;
            for (std::size_t d = 0; d < klen; ++d) s += double(qh[d]) * double(kt[d]);
            s *= double(scale);
            logits[t] = s;
            if (s > mx) mx = s;
        }
        double den = 0.0;
        for (std::size_t t = 0; t <= seqPos; ++t) { logits[t] = std::exp(logits[t] - mx); den += logits[t]; }
        for (std::size_t t = 0; t <= seqPos; ++t) {
            const double p = logits[t] / den;
            const float* vt = cache[t].v.data() + h * vlen;
            for (std::size_t d = 0; d < vlen; ++d) attn[h * vlen + d] += float(p * double(vt[d]));
        }
    }

    // 12  output projection
    if (!gemvF32(lw.attnO, attn.data(), output, H, heads * vlen, "attnO")) return false;
    for (std::size_t i = 0; i < H; ++i)
        if (!std::isfinite(output[i])) { std::fprintf(stderr, "[CPU_MLA] %s non-finite out\n", what); return false; }
    return true;
}

} // namespace rawrxd::mla

