// deep2_cpu_mla.cpp
// RAWRXD_CPU_MLA_KERNEL_001 -- CPU Multi-head Latent Attention.
//
// WHY THIS EXISTS
// ---------------
// Deep2's ONLY MLA attention implementation was computeMLAAttentionGpu
// (Deep2Engine_GpuMoEMLA.cpp:384), and every call it makes -- tryVulkanHostGEMV,
// RunMLAAttentionHost -- returns false at its first guard when
// vulkanInitialized_ is false. computeAttention had no CPU branch at all:
//
//     if (lw.useMLA || modelWeights.useMLA) {
//         if (computeMLAAttentionGpu(layer, input, output, seqLen)) return;
//         throw std::runtime_error(
//             "attention: GPU MLA path failed or unsupported");
//     }
//
// So an MLA architecture on a CPU-only machine had exactly two outcomes: Vulkan,
// or an exception at prefill token 0. That is not a fallback optimisation. It
// means no MLA architecture -- DeepSeek-V2, DeepSeek-V3, Kimi K2 -- can run on
// the CPU route at all.
//
// THE PRIOR FILE WAS NEVER COMPILED
// --------------------------------
// The previous revision of this file was in no CMake target and did not compile:
// it called Deep2::MakeExecutionView, which is not declared in namespace Deep2 by
// ExecutionView.hpp or by Deep2Engine.h, and it required F32-backed weights
// (w.type != 0 -> refuse), so it would have rejected the Q4_K_M DeepSeek file
// even once it built. Treat any receipt describing it as an executed CPU MLA path
// as describing code that was never linked.
//
// THE MATH IS DEEP2'S, NOT THE PAPER'S
// ------------------------------------
// Every step is transcribed from computeMLAAttentionGpu. Where the reference
// makes a choice, this makes the same choice, so a CPU/GPU divergence cannot be
// blamed on interpretation. One correction is deliberate and is called out at
// applyMlaRope below.
//
//   1  qa      = attnQ_a      @ x                  [qRank]      (split only)
//   2  qaNorm  = RMSNorm(qa, attnQ_a_norm, eps)    [qRank]      (split only)
//   3  qFull   = attnQ_b      @ qaNorm             [heads*keyLen]
//                                                          (fused: @ x directly)
//   4  kva     = attnKV_a_mqa @ x                   [kvRank + rope]
//   5  cNorm   = RMSNorm(kva[0:kvRank], attnKV_a_norm, eps)
//   6  kNope   = attnK_b      @ cNorm               [heads * nope]
//   7  values  = attnV_b      @ cNorm               [heads * valueLen]
//                                                          (fused: one attnK_b
//                                                           GEMV producing
//                                                           heads*(nope+valueLen))
//   8  kPe     = kva[kvRank : kvRank+rope]
//   9  applyMlaRope(qFull, kPe, heads, nope, rope, pos, theta, scaling)
//  10  kFull[h] = concat(kNope[h*nope : (h+1)*nope], kPe)
//  11  attn[h]  = softmax_t( dot(qFull[h], kFull_t[h]) * 1/sqrt(keyLen) ) values_t[h]
//  12  out      = attnO @ attn                      [hidden]
//
// The fused layout needs no weight surgery. attn_q is already [heads*keyLen,
// hidden] and attn_kv_b is already [heads*(nope+valueLen), kvRank]; both land in
// the attnQ_b / attnK_b slots at bind time. The K/V split is performed on the
// GEMV OUTPUT, which is plain f32, so no packed Q4_K byte is ever dequantised and
// requantised and no additional resident copy is created.

#include "Deep2Engine.h"

#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace {

// RAWRXD_MLA_CPU_TRACE: off unless the environment asks. Every value printed is
// an observation of this run; nothing here is a prediction.
bool mlaTraceOn() {
    static const bool on = [] {
        const char* v = std::getenv("RAWRXD_MLA_CPU_TRACE");
        return v && v[0] && v[0] != '0';
    }();
    return on;
}

void mlaTrace(const char* fmt, ...) {
    if (!mlaTraceOn()) return;
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "\n");
    std::fflush(stderr);
}

// Transcribed verbatim from Deep2Engine_GpuMoEMLA.cpp:38 applyMlaRope.
//
// Note this is INTERLEAVED-pair rotation at adjacent indices (d, d+1), not the
// rotate-half form used by Deep2's non-MLA attention path. The earlier draft of
// this file implemented rotate-half, which would have silently disagreed with
// the GPU reference on every rotary dimension. Interleaved is what the reference
// does and what DeepSeek2 GGUF weights were trained for.
void applyMlaRopeCpu(float* qFull, float* kPe,
                     std::size_t heads, std::size_t nope, std::size_t rope,
                     std::size_t pos, float theta, float scaling)
{
    if (!qFull || !kPe || !heads || !rope || (rope & 1u)) return;
    const float position = static_cast<float>(pos) / scaling;
    for (std::size_t pair = 0; pair < rope / 2; ++pair) {
        const std::size_t d = pair * 2;
        const float freq = std::pow(theta,
            -static_cast<float>(d) / static_cast<float>(rope));
        const float angle = position * freq;
        const float cs = std::cos(angle);
        const float sn = std::sin(angle);
        for (std::size_t h = 0; h < heads; ++h) {
            float* qr = qFull + h * (nope + rope) + nope;
            const float a = qr[d], b = qr[d + 1];
            qr[d]     = a * cs - b * sn;
            qr[d + 1] = a * sn + b * cs;
        }
        const float a = kPe[d], b = kPe[d + 1];
        kPe[d]     = a * cs - b * sn;
        kPe[d + 1] = a * sn + b * cs;
    }
}

} // namespace

// RAWRXD_CPU_MLA_KERNEL_001
//
// Returns true only when this layer's attention was actually computed on the CPU
// and written to output. Returns false, with the specific reason on stderr, when
// the route is not available for this model. It never returns true on a partial
// computation: any non-finite result or unbound tensor is a refusal, because a
// silent wrong answer here is indistinguishable from a correct one downstream.

namespace Deep2 {

bool Deep2Engine::computeMLAAttentionCpu(size_t layer, const float* input,
                                        float* output, size_t seqLen)
{
    if (!input || !output || seqLen == 0) {
        std::fprintf(stderr, "[CPU_MLA] reject: null buffers or seqLen=0\n");
        return false;
    }
    if (layer >= modelWeights.layers.size()) {
        std::fprintf(stderr, "[CPU_MLA] reject: layer %zu >= %zu layers bound\n",
                     layer, modelWeights.layers.size());
        return false;
    }

    const LayerWeights& lw = modelWeights.layers[layer];

    const std::size_t H      = modelWeights.hiddenDim;
    const std::size_t heads  = modelWeights.numHeads;
    const std::size_t qRank  = modelWeights.qLoraRank;
    const std::size_t kvRank = modelWeights.kvLoraRank;
    const std::size_t nope   = modelWeights.qkNopeHeadDim;
    const std::size_t rope   = modelWeights.qkRopeHeadDim;
    const std::size_t vlen   = modelWeights.vHeadDim;
    if (!H || !heads || !kvRank || !nope || !rope || !vlen || (rope & 1u)) {
        std::fprintf(stderr,
            "[CPU_MLA] reject: incomplete geometry H=%zu heads=%zu kvRank=%zu "
            "nope=%zu rope=%zu vlen=%zu\n",
            H, heads, kvRank, nope, rope, vlen);
        return false;
    }
    const std::size_t klen = nope + rope;

    // Which layout is bound. qLoraRank==0 with a populated attnQ_b is the fused
    // signature; a populated attnQ_a is the split signature. Decided from the
    // BOUND tensors, not from a remembered flag, so it cannot disagree with what
    // the binder actually did.
    const bool splitLayout = lw.attnQ_a.data != nullptr;
    const bool fusedLayout = !splitLayout && lw.attnQ_b.data != nullptr;

    // ---- binding + geometry guard, mirrored from the GPU path ---------------
    std::ostringstream why;
    if (splitLayout) {
        if (!lw.attnQ_a.data || !lw.attnQ_a_norm.data || !lw.attnQ_b.data ||
            !lw.attnKV_a_mqa.data || !lw.attnKV_a_norm.data ||
            !lw.attnK_b.data || !lw.attnV_b.data || !lw.attnO.data) {
            why << "split layout incompletely bound";
        } else if (qRank == 0) {
            why << "split layout bound but qLoraRank=0";
        } else if (lw.attnQ_a.rows != qRank || lw.attnQ_a.cols != H) {
            why << "attnQ_a " << lw.attnQ_a.rows << "x" << lw.attnQ_a.cols
                << " != " << qRank << "x" << H;
        } else if (lw.attnQ_b.rows != heads * klen || lw.attnQ_b.cols != qRank) {
            why << "attnQ_b " << lw.attnQ_b.rows << "x" << lw.attnQ_b.cols
                << " != " << (heads * klen) << "x" << qRank;
        } else if (lw.attnK_b.rows != heads * nope ||
                   lw.attnK_b.cols != kvRank ||
                   lw.attnV_b.rows != heads * vlen ||
                   lw.attnV_b.cols != kvRank) {
            why << "attnK_b/attnV_b do not match heads*nope x kvRank";
        }
    } else if (fusedLayout) {
        if (!lw.attnKV_a_mqa.data || !lw.attnKV_a_norm.data ||
            !lw.attnK_b.data || !lw.attnO.data) {
            why << "fused layout incompletely bound";
        } else if (lw.attnQ_b.rows != heads * klen || lw.attnQ_b.cols != H) {
            // attn_q: [heads*keyLen, hidden]
            why << "attn_q(->attnQ_b) " << lw.attnQ_b.rows << "x" << lw.attnQ_b.cols
                << " != " << (heads * klen) << "x" << H;
        } else if (lw.attnK_b.rows != heads * (nope + vlen) ||
                   lw.attnK_b.cols != kvRank) {
            // attn_kv_b: [heads*(nope+vHead), kvLoraRank]
            why << "attn_kv_b(->attnK_b) " << lw.attnK_b.rows << "x" << lw.attnK_b.cols
                << " != " << (heads * (nope + vlen)) << "x" << kvRank;
        }
    } else {
        why << "neither split (attnQ_a) nor fused (attnQ_b) query binding present";
    }
    if (why.str().empty() &&
        (lw.attnKV_a_mqa.rows != kvRank + rope || lw.attnKV_a_mqa.cols != H)) {
        why << "attnKV_a_mqa " << lw.attnKV_a_mqa.rows << "x" << lw.attnKV_a_mqa.cols
            << " != " << (kvRank + rope) << "x" << H;
    }
    if (why.str().empty() &&
        (lw.attnO.rows != H || lw.attnO.cols != heads * vlen)) {
        why << "attnO " << lw.attnO.rows << "x" << lw.attnO.cols
            << " != " << H << "x" << (heads * vlen);
    }
    if (!why.str().empty()) {
        std::fprintf(stderr, "[CPU_MLA] reject layer %zu: %s\n",
                     layer, why.str().c_str());
        return false;
    }

    // ---- KV cache geometry --------------------------------------------------
    // The engine allocates one KVCacheConfig for the whole model. MLA stores a
    // per-head key of keyLen and a per-head value of valueLen, both inside rows
    // of headDim. If the shared cache is narrower than this layer needs, the
    // route is refused by name rather than reading past the end of a row.
    if (!kvCache || !kvCache->allocated()) {
        std::fprintf(stderr, "[CPU_MLA] reject layer %zu: KV cache not allocated\n",
                     layer);
        return false;
    }
    {
        const KVCacheConfig& kc = kvCache->config();
        const std::size_t need = klen > vlen ? klen : vlen;
        if (layer >= kc.numLayers || kc.numHeads < heads || kc.headDim < need) {
            std::fprintf(stderr,
                "[CPU_MLA] reject layer %zu: KV cache geometry "
                "layers=%zu heads=%zu headDim=%zu does not satisfy "
                "layers>%zu heads>=%zu headDim>=%zu\n",
                layer, kc.numLayers, kc.numHeads, kc.headDim,
                layer, heads, need);
            return false;
        }
    }

    const std::size_t pos = kvCache->currentLength();
    if (seqLen != pos + 1 || pos >= config.maxSeqLen) {
        std::fprintf(stderr,
            "[CPU_MLA] reject layer %zu: seqLen=%zu but kvPos+1=%zu "
            "(maxSeqLen=%zu)\n",
            layer, seqLen, pos + 1, config.maxSeqLen);
        return false;
    }

    // ---- 1..3  query path ---------------------------------------------------
    // Every projection goes through LinearW, which is the engine's own audited
    // CPU route: it validates geometry, resolves the registered quant kernel for
    // this WeightTensor type, records the consumption census, and refuses a
    // non-finite result. Using it rather than a private GEMV is what makes this
    // path consume Q4_K/Q4_0/Q5_0/... correctly instead of assuming f32.
    std::vector<float> qa, qaNorm, qFull;
    try {
        if (splitLayout) {
            qa.assign(qRank, 0.0f);
            LinearW(lw.attnQ_a, input, nullptr, qa.data(), qRank);
            qaNorm.assign(qRank, 0.0f);
            RMSNormW(lw.attnQ_a_norm, qa.data(), qaNorm.data(), qRank,
                     modelWeights.normEps);
            qFull.assign(heads * klen, 0.0f);
            LinearW(lw.attnQ_b, qaNorm.data(), nullptr, qFull.data(), heads * klen);
        } else {
            // attn_q consumes x directly: there is no low-rank query bottleneck
            // in this architecture (qLoraRank is 0 and the GGUF proves it, since
            // attn_q.cols == hiddenDim).
            qFull.assign(heads * klen, 0.0f);
            LinearW(lw.attnQ_b, input, nullptr, qFull.data(), heads * klen);
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[CPU_MLA] reject layer %zu at query projection: %s\n",
                     layer, e.what());
        return false;
    }

    // ---- 4..8  latent / key / value path ------------------------------------
    std::vector<float> kva(kvRank + rope, 0.0f), cNorm(kvRank, 0.0f);
    std::vector<float> kNope(heads * nope, 0.0f), values(heads * vlen, 0.0f);
    try {
        LinearW(lw.attnKV_a_mqa, input, nullptr, kva.data(), kvRank + rope);
        RMSNormW(lw.attnKV_a_norm, kva.data(), cNorm.data(), kvRank,
                 modelWeights.normEps);
        if (splitLayout) {
            LinearW(lw.attnK_b, cNorm.data(), nullptr, kNope.data(), heads * nope);
            LinearW(lw.attnV_b, cNorm.data(), nullptr, values.data(), heads * vlen);
        } else {
            // One GEMV produces heads*(nope+valueLen). Per head, the nope slice
            // precedes the value slice, which is the same per-head ordering the
            // split layout's two separate tensors produce.
            std::vector<float> kv(heads * (nope + vlen), 0.0f);
            LinearW(lw.attnK_b, cNorm.data(), nullptr, kv.data(),
                    heads * (nope + vlen));
            const std::size_t perHead = nope + vlen;
            for (std::size_t h = 0; h < heads; ++h) {
                std::memcpy(kNope.data() + h * nope,
                            kv.data() + h * perHead,
                            nope * sizeof(float));
                std::memcpy(values.data() + h * vlen,
                            kv.data() + h * perHead + nope,
                            vlen * sizeof(float));
            }
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr,
            "[CPU_MLA] reject layer %zu at latent projection: %s\n",
            layer, e.what());
        return false;
    }

    std::vector<float> kPe(kva.begin() + kvRank, kva.end());

    // ---- 9  RoPE ------------------------------------------------------------
    const float theta = modelWeights.ropeTheta > 1.0f
        ? modelWeights.ropeTheta : config.ropeTheta;
    const float scaling = modelWeights.ropeScaling > 0.0f
        ? modelWeights.ropeScaling : config.ropeScaling;
    if (theta > 1.0f && scaling > 0.0f) {
        applyMlaRopeCpu(qFull.data(), kPe.data(), heads, nope, rope, pos,
                        theta, scaling);
    } else {
        std::fprintf(stderr,
            "[CPU_MLA] reject layer %zu: invalid rope theta=%g scaling=%g\n",
            layer, (double)theta, (double)scaling);
        return false;
    }

    // ---- 10  publish this position into the KV cache ------------------------
    const std::size_t cacheHeadDim = kvCache->config().headDim;
    for (std::size_t h = 0; h < heads; ++h) {
        float* kDst = kvCache->keyPtr(layer, h, pos);
        float* vDst = kvCache->valuePtr(layer, h, pos);
        if (!kDst || !vDst) {
            std::fprintf(stderr,
                "[CPU_MLA] reject layer %zu: no KV slot head=%zu pos=%zu\n",
                layer, h, pos);
            return false;
        }
        std::memcpy(kDst, kNope.data() + h * nope, nope * sizeof(float));
        std::memcpy(kDst + nope, kPe.data(), rope * sizeof(float));
        std::memcpy(vDst, values.data() + h * vlen, vlen * sizeof(float));
    }

    // ---- 11  causal attention over [0, pos] ---------------------------------
    const float scale = 1.0f / std::sqrt(static_cast<float>(klen));
    std::vector<float> attn(heads * vlen, 0.0f);
    std::vector<double> logits(pos + 1);
    for (std::size_t h = 0; h < heads; ++h) {
        const float* qh = qFull.data() + h * klen;
        double mx = -1e300;
        for (std::size_t t = 0; t <= pos; ++t) {
            const float* kt = kvCache->keyPtr(layer, h, t);
            if (!kt) {
                std::fprintf(stderr,
                    "[CPU_MLA] reject layer %zu: no key slot head=%zu pos=%zu\n",
                    layer, h, t);
                return false;
            }
            double s = 0.0;
            for (std::size_t d = 0; d < klen; ++d)
                s += static_cast<double>(qh[d]) * static_cast<double>(kt[d]);
            s *= static_cast<double>(scale);
            logits[t] = s;
            if (s > mx) mx = s;
        }
        double den = 0.0;
        for (std::size_t t = 0; t <= pos; ++t) {
            logits[t] = std::exp(logits[t] - mx);
            den += logits[t];
        }
        if (!(den > 0.0) || !std::isfinite(den)) {
            std::fprintf(stderr,
                "[CPU_MLA] reject layer %zu head %zu: softmax denominator %g\n",
                layer, h, den);
            return false;
        }
        for (std::size_t t = 0; t <= pos; ++t) {
            const float* vt = kvCache->valuePtr(layer, h, t);
            if (!vt) {
                std::fprintf(stderr,
                    "[CPU_MLA] reject layer %zu: no value slot head=%zu pos=%zu\n",
                    layer, h, t);
                return false;
            }
            const double p = logits[t] / den;
            for (std::size_t d = 0; d < vlen; ++d)
                attn[h * vlen + d] += static_cast<float>(p * static_cast<double>(vt[d]));
        }
    }

    // ---- 12  output projection ----------------------------------------------
    try {
        LinearW(lw.attnO, attn.data(), nullptr, output, H);
    } catch (const std::exception& e) {
        std::fprintf(stderr,
            "[CPU_MLA] reject layer %zu at output projection: %s\n",
            layer, e.what());
        return false;
    }
    for (std::size_t i = 0; i < H; ++i) {
        if (!std::isfinite(output[i])) {
            std::fprintf(stderr,
                "[CPU_MLA] reject layer %zu: non-finite output at index %zu\n",
                layer, i);
            return false;
        }
    }

    ++cpuMla_.attentionCalls;
    cpuMla_.lastLayer = layer;
    cpuMla_.lastPos = pos;
    mlaTrace("[CPU_MLA] layer=%zu pos=%zu layout=%s heads=%zu keyLen=%zu "
             "valueLen=%zu ropeTheta=%g ropeScaling=%g OK",
             layer, pos, splitLayout ? "split" : "fused", heads, klen, vlen,
             (double)theta, (double)scaling);
    return true;
}
} // namespace Deep2
