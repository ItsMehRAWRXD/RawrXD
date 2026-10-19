// Deep2 Move 6: Real-token autoregressive oracle for Phi-3 (dense) via the paged ROM path.
// Validates quantized dequant scale factors end-to-end: wrong dequant => garbage tokens instantly.
//
// Usage:
//   rom_audit oracle  <model.gguf> "<prompt>" [max_tokens]
//   rom_audit tokenize <model.gguf> "<prompt>"
//   rom_audit info    <model.gguf>

#include "TensorROM.hpp"
#include "Deep2Engine.hpp"
#include "quant_kernels.hpp"
#include "core/GgufTokenizer.hpp"

#include <algorithm>
#include <cstdio>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace deep2;

// ---------------------------------------------------------------------------
// Minimal BPE tokenizer read straight out of the GGUF
// (tokenizer.ggml.tokens / tokenizer.ggml.merges / tokenizer.ggml.bos_token_id / ...).
// Self-contained; does not depend on the whole-model GGUFLoader path.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// GGUF tokenizer.
//
// The implementation lives in src/core/GgufTokenizer.hpp and is shared with
// the production inference path. It reproduces llama.cpp's SentencePiece
// (Phi-3, TinyLlama) and byte-level BPE (DeepSeek-V2, Qwen) behaviour, and
// is verified against the reference HuggingFace tokenizers.
// ---------------------------------------------------------------------------
using GgufTokenizer = Deep2Rom::Inference::GgufTokenizer;

// ---------------------------------------------------------------------------
// Phi-3 weights resident in host RAM (paged once from ROM at startup).
// ---------------------------------------------------------------------------
struct LayerW {
    std::vector<float> attnNormW;   // [hidden]
    std::vector<float> qkvW;        // [3*hidden, hidden] row-major logical
    std::vector<float> attnOutW;    // [hidden, hidden]
    std::vector<float> ffnNormW;    // [hidden]
    std::vector<float> ffnUpW;      // [intermediate, hidden]
    std::vector<float> ffnDownW;    // [hidden, intermediate]
};

// RMSNorm: out = w * x / sqrt(mean(x^2) + eps), in-place on x.
static void rmsNorm(float* x, const float* w, uint32_t dim, float eps) {
    float mean = 0.0f;
    for (uint32_t i = 0; i < dim; ++i) mean += x[i] * x[i];
    mean /= (float)dim;
    float scale = 1.0f / std::sqrtf(mean + eps);
    for (uint32_t i = 0; i < dim; ++i) x[i] *= scale * w[i];
}

static void rope(float* x, uint32_t pos, uint32_t dim, float theta) {
    for (uint32_t i = 0; i < dim; i += 2) {
        float freq = 1.0f / std::powf(theta, (float)i / (float)dim);
        float ang = (float)pos * freq;
        float s = std::sinf(ang), c = std::cosf(ang);
        float x0 = x[i], x1 = x[i + 1];
        x[i] = x0 * c - x1 * s;
        x[i + 1] = x0 * s + x1 * c;
    }
}

struct Phi3Model {
    uint32_t hidden = 0, layers = 0, heads = 0, intermediate = 0, vocab = 0;
    uint32_t headDim = 0;
    float eps = 1e-5f, theta = 10000.0f;
    std::vector<float> tokenEmbdW;   // [vocab, hidden]
    std::vector<float> outputNormW;  // [hidden]
    std::vector<float> outputW;      // [vocab, hidden]
    std::vector<LayerW> layersW;
    std::vector<float> kCache, vCache; // [layers][heads][seq][headDim]
    uint32_t seqCap = 0;

    bool loadRom(const TensorROM& rom) {
        auto get = [&](const std::string& name) { return rom.findTensor(name); };
        auto readF32 = [&](const TensorEntry* e, std::vector<float>& out) -> bool {
            if (!e) { std::cerr << "[ORACLE] missing tensor: " << (e ? e->name : std::string("null")) << "\n"; return false; }
            uint64_t size = e->byteSize();
            std::vector<uint8_t> raw(size);
            if (!rom.readTensor(*e, raw.data())) { std::cerr << "[ORACLE] readTensor failed: " << e->name << "\n"; return false; }
            TensorView view{ e->type, raw.data(), size, e->dims, true };
            DequantizedTensor dq;
            if (!dequantizeTensor(view, dq)) { std::cerr << "[ORACLE] dequant failed: " << e->name << " type=" << tensorTypeName(e->type) << "\n"; return false; }
            out = std::move(dq.data);
            return true;
        };

        const TensorEntry* te;
        te = get("token_embd.weight");   if (!readF32(te, tokenEmbdW)) return false;
        te = get("output_norm.weight");  if (!readF32(te, outputNormW)) return false;
        te = get("output.weight");       if (!readF32(te, outputW)) return false;

        // Geometry comes from the shard metadata, cross-checked against the
        // tensor shapes. GGUF stores weight dims as [in, out], so the logical
        // matrix is [out, in].
        const auto& g = rom.geometry();
        hidden  = static_cast<uint32_t>(g.hiddenDim);
        layers  = static_cast<uint32_t>(g.numLayers);
        heads   = static_cast<uint32_t>(g.numHeads);
        intermediate = static_cast<uint32_t>(g.intermediateDim);
        vocab   = static_cast<uint32_t>(g.vocabSize);
        if (hidden == 0 || layers == 0 || heads == 0 || vocab == 0) {
            std::cerr << "[ORACLE] incomplete geometry in shard metadata\n";
            return false;
        }
        headDim = hidden / heads;

        // ffn_up holds both halves of the gated MLP (gate then up), so it has
        // 2 * intermediate rows. Derive it from the tensor rather than assume.
        {
            const TensorEntry* fu = get("blk.0.ffn_up.weight");
            if (!fu) { std::cerr << "[ORACLE] missing blk.0.ffn_up.weight\n"; return false; }
            if (fu->dims.size() != 2) { std::cerr << "[ORACLE] unexpected ffn_up rank\n"; return false; }
            const uint64_t ffnUpRows = fu->dims[1];   // GGUF [in, out]
            if (ffnUpRows != static_cast<uint64_t>(intermediate) * 2) {
                std::cerr << "[ORACLE] ffn_up rows=" << ffnUpRows
                          << " expected 2*intermediate=" << (intermediate * 2) << "\n";
                return false;
            }
        }

        seqCap = 1536;
        kCache.assign(layers * heads * seqCap * headDim, 0.0f);
        vCache.assign(layers * heads * seqCap * headDim, 0.0f);
        layersW.resize(layers);

        for (uint32_t l = 0; l < layers; ++l) {
            std::ostringstream os; os << "blk." << l << ".";
            const std::string p = os.str();
            LayerW& lw = layersW[l];
            if (!readF32(get(p + "attn_norm.weight"), lw.attnNormW)) return false;
            if (!readF32(get(p + "attn_qkv.weight"), lw.qkvW)) return false;
            if (!readF32(get(p + "attn_output.weight"), lw.attnOutW)) return false;
            if (!readF32(get(p + "ffn_norm.weight"), lw.ffnNormW)) return false;
            if (!readF32(get(p + "ffn_up.weight"), lw.ffnUpW)) return false;
            if (!readF32(get(p + "ffn_down.weight"), lw.ffnDownW)) return false;
            std::cerr << "[ORACLE] layer " << l << " weights resident\n";
        }
        std::cerr << "[ORACLE] model resident: hidden=" << hidden << " layers=" << layers
                  << " heads=" << heads << " headDim=" << headDim
                  << " ffn=" << intermediate << " vocab=" << vocab << "\n";
        return true;
    }

    // Logits for the last token of `tokens` (full recompute each step; KV cache holds K/V).
    std::vector<float> forward(const std::vector<uint32_t>& tokens) {
        const uint32_t seq = (uint32_t)tokens.size();
        std::vector<float> h(seq * hidden, 0.0f);
        for (uint32_t t = 0; t < seq; ++t) {
            const float* emb = &tokenEmbdW[tokens[t] * hidden];
            std::memcpy(&h[t * hidden], emb, hidden * sizeof(float));
        }

        const float invSqrtD = 1.0f / std::sqrtf((float)headDim);

        for (uint32_t l = 0; l < layers; ++l) {
            LayerW& lw = layersW[l];
            float* kLayer = &kCache[l * heads * seqCap * headDim];
            float* vLayer = &vCache[l * heads * seqCap * headDim];

            for (uint32_t t = 0; t < seq; ++t) {
                float* ht = &h[t * hidden];

                // ---- attention branch ----
                float normIn[3072]; // stack too big? hidden=3072 floats = 12KB OK
                std::memcpy(normIn, ht, hidden * sizeof(float));
                rmsNorm(normIn, lw.attnNormW.data(), hidden, eps);

                float qkv[9216]; // 3*hidden
                gemvFloat(lw.qkvW.data(), normIn, qkv, 3 * hidden, hidden);

                float q[3072], k[3072], v[3072];
                std::memcpy(q, qkv, hidden * sizeof(float));
                std::memcpy(k, qkv + hidden, hidden * sizeof(float));
                std::memcpy(v, qkv + 2 * hidden, hidden * sizeof(float));

                for (uint32_t hh = 0; hh < heads; ++hh) {
                    rope(q + hh * headDim, t, headDim, theta);
                    rope(k + hh * headDim, t, headDim, theta);
                }

                // store K/V for this position
                for (uint32_t hh = 0; hh < heads; ++hh) {
                    std::memcpy(kLayer + ((hh * seq + t) * headDim), k + hh * headDim, headDim * sizeof(float));
                    std::memcpy(vLayer + ((hh * seq + t) * headDim), v + hh * headDim, headDim * sizeof(float));
                }

                // causal attention output per head
                float attnOut[3072] = {0};
                for (uint32_t hh = 0; hh < heads; ++hh) {
                    float* outH = attnOut + hh * headDim;
                    for (uint32_t tt = 0; tt <= t; ++tt) {
                        float score = 0.0f;
                        const float* kT = kLayer + (hh * seq + tt) * headDim;
                        for (uint32_t d = 0; d < headDim; ++d) score += q[hh * headDim + d] * kT[d];
                        score *= invSqrtD;
                        // softmax computed below per (h,t) needs all scores; do two-pass
                        // store score in outH temporarily? We need proper softmax: recompute.
                        (void)score;
                    }
                    // proper softmax: first pass max
                    float scores[1536];
                    float maxSc = -1e30f;
                    for (uint32_t tt = 0; tt <= t; ++tt) {
                        const float* kT = kLayer + (hh * seq + tt) * headDim;
                        float s = 0.0f;
                        for (uint32_t d = 0; d < headDim; ++d) s += q[hh * headDim + d] * kT[d];
                        scores[tt] = s * invSqrtD;
                        if (scores[tt] > maxSc) maxSc = scores[tt];
                    }
                    float sum = 0.0f;
                    for (uint32_t tt = 0; tt <= t; ++tt) { float vv = std::expf(scores[tt] - maxSc); scores[tt] = vv; sum += vv; }
                    for (uint32_t d = 0; d < headDim; ++d) { float acc = 0.0f; for (uint32_t tt = 0; tt <= t; ++tt) acc += scores[tt] * vLayer[(hh * seq + tt) * headDim + d]; outH[d] = acc / sum; }
                }

                // residual: x = x + attn_output @ W_attn_out
                float attnProj[3072];
                gemvFloat(lw.attnOutW.data(), attnOut, attnProj, hidden, hidden);
                for (uint32_t i = 0; i < hidden; ++i) ht[i] += attnProj[i];

                // ---- ffn branch ----
                // Phi-3 uses a gated SwiGLU: ffn_up produces 2*intermediate
                // values, the first half is the gate and the second half is
                // the up projection. The activation is silu(gate) * up.
                std::memcpy(normIn, ht, hidden * sizeof(float));
                rmsNorm(normIn, lw.ffnNormW.data(), hidden, eps);

                std::vector<float> fup(2 * intermediate);
                gemvFloat(lw.ffnUpW.data(), normIn, fup.data(), 2 * intermediate, hidden);
                for (uint32_t i = 0; i < intermediate; ++i) {
                    const float gate = fup[i];
                    const float up   = fup[intermediate + i];
                    fup[i] = (gate / (1.0f + std::expf(-gate))) * up;  // silu(gate) * up
                }

                std::vector<float> fdown(hidden);
                gemvFloat(lw.ffnDownW.data(), fup.data(), fdown.data(), hidden, intermediate);
                for (uint32_t i = 0; i < hidden; ++i) ht[i] += fdown[i];
            }
        }

        // final norm + lm head on last position
        float* last = &h[(seq - 1) * hidden];
        rmsNorm(last, outputNormW.data(), hidden, eps);
        std::vector<float> logits(vocab);
        gemvFloat(outputW.data(), last, logits.data(), vocab, hidden);
        return logits;
    }
};

// ---------------------------------------------------------------------------
// DeepSeek-V2-Lite forward pass (Move 8: MLA + dense FFN, layer 0 diagnostic).
// Layer 0 is the single dense layer (leading_dense_block_count=1); layers 1-26
// are MoE and handled in Move 9.
// ---------------------------------------------------------------------------
struct DeepSeek2Model {
    uint32_t hidden = 0, layers = 0, heads = 0, intermediate = 0, vocab = 0;
    uint32_t qkNope = 0, qkRope = 0, vHead = 0, kvLora = 0;
    float eps = 1e-6f, theta = 10000.0f;
    uint32_t seqCap = 0;
    // MoE geometry
    uint32_t moeNumExperts = 0, moeTopK = 0, moeNumShared = 0;

    std::vector<float> tokenEmbdW;   // [vocab, hidden]
    std::vector<float> outputNormW;  // [hidden]
    std::vector<float> outputW;      // [vocab, hidden]

    struct LayerW {
        std::vector<float> attnNormW;    // [hidden]
        std::vector<float> qW;           // [3072, hidden] logical
        std::vector<float> kvANormW;     // [kvLora]
        std::vector<float> kvAMqaW;      // [kvLora + qkRope, hidden]
        std::vector<float> kvBW;         // [(qkNope + vHead)*heads, kvLora]
        std::vector<float> attnOutW;     // [hidden, hidden]
        std::vector<float> ffnNormW;     // [hidden]
        // Dense layer 0 only:
        std::vector<float> ffnUpW;       // [intermediate, hidden]
        std::vector<float> ffnGateW;     // [intermediate, hidden]
        std::vector<float> ffnDownW;     // [hidden, intermediate]
        // MoE layers 1-26 (loaded on demand from ROM):
        std::vector<float> ffnGateInpW;  // [hidden, numExperts] router
        std::vector<float> ffnGateExpsW; // [numExperts, intermediate, hidden]
        std::vector<float> ffnUpExpsW;   // [numExperts, intermediate, hidden]
        std::vector<float> ffnDownExpsW; // [numExperts, hidden, intermediate]
        std::vector<float> ffnGateShexpW;// [hidden, 2*intermediate]
        std::vector<float> ffnUpShexpW;  // [hidden, 2*intermediate]
        std::vector<float> ffnDownShexpW;// [2*intermediate, hidden]
        bool moeLoaded = false;
    };
    std::vector<LayerW> layersW;

    // KV caches: kNope [layers][heads][seq][qkNope], v [layers][heads][seq][vHead], kRope [layers][seq][qkRope] (shared across heads)
    std::vector<float> kNopeCache, vCache, kRopeCache;

    bool loadRom(const TensorROM& rom) {
        auto get = [&](const std::string& name) { return rom.findTensor(name); };
        auto readF32 = [&](const TensorEntry* e, std::vector<float>& out) -> bool {
            if (!e) { std::cerr << "[DS2] missing tensor: " << (e ? e->name : std::string("null")) << "\n"; return false; }
            uint64_t size = e->byteSize();
            std::vector<uint8_t> raw(size);
            if (!rom.readTensor(*e, raw.data())) { std::cerr << "[DS2] readTensor failed: " << e->name << "\n"; return false; }
            TensorView view{ e->type, raw.data(), size, e->dims, true };
            DequantizedTensor dq;
            if (!dequantizeTensor(view, dq)) { std::cerr << "[DS2] dequant failed: " << e->name << " type=" << tensorTypeName(e->type) << "\n"; return false; }
            out = std::move(dq.data);
            return true;
        };

        const TensorEntry* te;
        te = get("token_embd.weight");   if (!readF32(te, tokenEmbdW)) return false;
        float me = 0.0f, mx = -1e30f, mn = 1e30f;
        int nz = 0;
        const uint32_t peek = std::min<uint32_t>(2048, tokenEmbdW.size());
        for (uint32_t i = 0; i < peek; ++i) {
            float v = tokenEmbdW[i];
            me += v;
            if (v > mx) mx = v;
            if (v < mn) mn = v;
            if (v != 0.0f) ++nz;
        }
        me /= (float)peek;
        std::cerr << "[DS2-DBG] token_embd row0: mean=" << me << " min=" << mn
                  << " max=" << mx << " nz=" << nz << "/" << peek << "\n";
        te = get("output_norm.weight");  if (!readF32(te, outputNormW)) return false;
        te = get("output.weight");       if (!readF32(te, outputW)) return false;
        {
            std::cerr << "[DS2-DBG] output.weight (offset=0) first 8 f32:";
            for (size_t i = 0; i < std::min<size_t>(8, outputW.size()); ++i)
                std::cerr << " " << outputW[i];
            std::cerr << "\n";
        }

        const auto& g = rom.geometry();
        hidden = (uint32_t)g.hiddenDim; layers = (uint32_t)g.numLayers; heads = (uint32_t)g.numHeads;
        intermediate = (uint32_t)g.intermediateDim; vocab = (uint32_t)g.vocabSize;
        theta = (float)g.ropeTheta;
        qkNope = g.qkNopeHeadDim; qkRope = g.qkRopeHeadDim; vHead = g.vHeadDim; kvLora = g.kvLoraRank;
        moeNumExperts = g.nRoutedExperts; moeTopK = g.moeTopK; moeNumShared = g.nSharedExperts;
        seqCap = 256;

        layersW.resize(layers);
        LayerW& lw = layersW[0];
        if (!readF32(get("blk.0.attn_norm.weight"), lw.attnNormW)) return false;
        {
            double nmax = -1e30, nmin = 1e30; bool nnan = false;
            for (size_t i = 0; i < lw.attnNormW.size(); ++i) { if (!(lw.attnNormW[i] == lw.attnNormW[i])) { nnan = true; break; } if (lw.attnNormW[i] > nmax) nmax = lw.attnNormW[i]; if (lw.attnNormW[i] < nmin) nmin = lw.attnNormW[i]; }
            std::cerr << "[DS2-DBG] attn_norm.weight: min=" << nmin << " max=" << nmax << " nan=" << nnan << "/" << lw.attnNormW.size() << "\n";
        }
        if (!readF32(get("blk.0.attn_q.weight"), lw.qW)) return false;
        {
            double qmax = -1e30, qmin = 1e30; int qnan = 0;
            for (size_t i = 0; i < lw.qW.size(); ++i) { if (!(lw.qW[i] == lw.qW[i])) { qnan++; } if (lw.qW[i] > qmax) qmax = lw.qW[i]; if (lw.qW[i] < qmin) qmin = lw.qW[i]; }
            std::cerr << "[DS2-DBG] attn_q.weight: min=" << qmin << " max=" << qmax << " nan=" << qnan << "/" << lw.qW.size() << "\n";
        }
        if (!readF32(get("blk.0.attn_kv_a_norm.weight"), lw.kvANormW)) return false;
        if (!readF32(get("blk.0.attn_kv_a_mqa.weight"), lw.kvAMqaW)) return false;
        if (!readF32(get("blk.0.attn_kv_b.weight"), lw.kvBW)) return false;
        if (!readF32(get("blk.0.attn_output.weight"), lw.attnOutW)) return false;
        if (!readF32(get("blk.0.ffn_norm.weight"), lw.ffnNormW)) return false;
        if (!readF32(get("blk.0.ffn_up.weight"), lw.ffnUpW)) return false;
        if (!readF32(get("blk.0.ffn_gate.weight"), lw.ffnGateW)) return false;
        if (!readF32(get("blk.0.ffn_down.weight"), lw.ffnDownW)) return false;

        kNopeCache.assign(layers * heads * seqCap * qkNope, 0.0f);
        vCache.assign(layers * heads * seqCap * vHead, 0.0f);
        kRopeCache.assign(layers * seqCap * qkRope, 0.0f);

        std::cerr << "[DS2] model resident: hidden=" << hidden << " layers=" << layers
                  << " heads=" << heads << " qkNope=" << qkNope << " qkRope=" << qkRope
                  << " vHead=" << vHead << " kvLora=" << kvLora << " ffn=" << intermediate
                  << " vocab=" << vocab << "\n";
        return true;
    }

    // Load MoE weights for a specific layer from ROM (on demand, to save memory)
    bool loadMoELayer(const TensorROM& rom, int layerIdx) {
        auto get = [&](const std::string& name) { return rom.findTensor(name); };
        auto readF32 = [&](const TensorEntry* e, std::vector<float>& out) -> bool {
            if (!e) { std::cerr << "[DS2] missing tensor: " << (e ? e->name : std::string("null")) << "\n"; return false; }
            uint64_t size = e->byteSize();
            std::vector<uint8_t> raw(size);
            if (!rom.readTensor(*e, raw.data())) { std::cerr << "[DS2] readTensor failed: " << e->name << "\n"; return false; }
            TensorView view{ e->type, raw.data(), size, e->dims, true };
            DequantizedTensor dq;
            if (!dequantizeTensor(view, dq)) { std::cerr << "[DS2] dequant failed: " << e->name << " type=" << tensorTypeName(e->type) << "\n"; return false; }
            out = std::move(dq.data);
            return true;
        };

        LayerW& lw = layersW[layerIdx];
        std::ostringstream os;
        os << "blk." << layerIdx << ".";
        const std::string p = os.str();

        if (!readF32(get(p + "ffn_gate_inp.weight"), lw.ffnGateInpW)) return false;
        if (!readF32(get(p + "ffn_gate_exps.weight"), lw.ffnGateExpsW)) return false;
        if (!readF32(get(p + "ffn_up_exps.weight"), lw.ffnUpExpsW)) return false;
        if (!readF32(get(p + "ffn_down_exps.weight"), lw.ffnDownExpsW)) return false;
        if (!readF32(get(p + "ffn_gate_shexp.weight"), lw.ffnGateShexpW)) return false;
        if (!readF32(get(p + "ffn_up_shexp.weight"), lw.ffnUpShexpW)) return false;
        if (!readF32(get(p + "ffn_down_shexp.weight"), lw.ffnDownShexpW)) return false;

        lw.moeLoaded = true;
        std::cerr << "[DS2] MoE layer " << layerIdx << " weights resident\n";
        return true;
    }

    static float silu(float x) { return x / (1.0f + std::expf(-x)); }

    // MoE forward pass for a single position
    void moeForward(int layerIdx, float* h, int t, int numExperts, int topK, int numShared,
                    int intermediate) {
        LayerW& lw = layersW[layerIdx];
        if (!lw.moeLoaded) return;

        float* ht = &h[t * hidden];

        // Router: x @ ffn_gate_inpW -> [numExperts]
        std::vector<float> routerLogits(numExperts);
        gemvFloat(lw.ffnGateInpW.data(), ht, routerLogits.data(), numExperts, hidden);

        // Softmax
        float maxLogit = -1e30f;
        for (int e = 0; e < numExperts; ++e) if (routerLogits[e] > maxLogit) maxLogit = routerLogits[e];
        float sumExp = 0.0f;
        std::vector<float> routerWeights(numExperts);
        for (int e = 0; e < numExperts; ++e) {
            routerWeights[e] = std::expf(routerLogits[e] - maxLogit);
            sumExp += routerWeights[e];
        }
        for (int e = 0; e < numExperts; ++e) routerWeights[e] /= sumExp;

        // Top-k selection
        std::vector<std::pair<float, int>> expertScores(numExperts);
        for (int e = 0; e < numExperts; ++e) expertScores[e] = {routerWeights[e], e};
        std::sort(expertScores.begin(), expertScores.end(),
                  [](const auto& a, const auto& b) { return a.first > b.first; });

        // Accumulate expert outputs
        std::vector<float> expertOut(hidden, 0.0f);
        for (int k = 0; k < topK && k < numExperts; ++k) {
            int e = expertScores[k].second;
            float w = expertScores[k].first;

            // Gate: x @ gate_exps[e] -> [intermediate]
            // gate_exps[e] is at [e * intermediate * hidden .. (e+1) * intermediate * hidden]
            const float* gateE = lw.ffnGateExpsW.data() + e * intermediate * hidden;
            std::vector<float> gateVal(intermediate);
            gemvFloat(gateE, ht, gateVal.data(), intermediate, hidden);

            // Up: x @ up_exps[e] -> [intermediate]
            // up_exps[e] is at [e * intermediate * hidden .. (e+1) * intermediate * hidden]
            const float* upE = lw.ffnUpExpsW.data() + e * intermediate * hidden;
            std::vector<float> upVal(intermediate);
            gemvFloat(upE, ht, upVal.data(), intermediate, hidden);

            // Intermediate: gate_val * silu(up_val)
            std::vector<float> intermediateVec(intermediate);
            for (int i = 0; i < intermediate; ++i)
                intermediateVec[i] = gateVal[i] * silu(upVal[i]);

            // Down: intermediate @ down_exps[e] -> [hidden]
            // down_exps[e] is at [e * hidden * intermediate .. (e+1) * hidden * intermediate]
            const float* downE = lw.ffnDownExpsW.data() + e * hidden * intermediate;
            std::vector<float> expertOut(hidden);
            gemvFloat(downE, intermediateVec.data(), expertOut.data(), hidden, intermediate);

            // Weighted combination
            for (int i = 0; i < hidden; ++i)
                ht[i] += w * expertOut[i];
        }

        // Shared expert
        // shared_gate = silu(x @ gate_shexpW) -> [2*intermediate]
        std::vector<float> sharedGate(2 * intermediate);
        gemvFloat(lw.ffnGateShexpW.data(), ht, sharedGate.data(), 2 * intermediate, hidden);

        // shared_up = x @ up_shexpW -> [2*intermediate]
        std::vector<float> sharedUp(2 * intermediate);
        gemvFloat(lw.ffnUpShexpW.data(), ht, sharedUp.data(), 2 * intermediate, hidden);

        // shared_intermediate = shared_gate * silu(shared_up)
        std::vector<float> sharedIntermediate(2 * intermediate);
        for (int i = 0; i < 2 * intermediate; ++i)
            sharedIntermediate[i] = sharedGate[i] * silu(sharedUp[i]);

        // shared_out = shared_intermediate @ down_shexpW -> [hidden]
        // down_shexpW: [2*intermediate, hidden]
        std::vector<float> sharedOut(hidden);
        gemvFloat(lw.ffnDownShexpW.data(), sharedIntermediate.data(), sharedOut.data(), hidden, 2 * intermediate);

        // Add shared expert output
        for (int i = 0; i < hidden; ++i)
            ht[i] += sharedOut[i];
    }

    // Logits for all tokens of `tokens` (full recompute with KV cache), layer-major.
    // Processes all tokens through layer 0, then all through layer 1, etc.
    // Loads MoE weights on demand from ROM for MoE layers (1+).
    std::vector<float> forwardAllLayers(const TensorROM& rom, const std::vector<uint32_t>& tokens) {
        const uint32_t seq = (uint32_t)tokens.size();
        std::vector<float> h(seq * hidden, 0.0f);
        for (uint32_t t = 0; t < seq; ++t)
            std::memcpy(&h[t * hidden], &tokenEmbdW[tokens[t] * hidden], hidden * sizeof(float));

        const float invSqrtD = 1.0f / std::sqrtf((float)(qkNope + qkRope));

        const uint32_t layersToRun = layers;
        for (uint32_t layer = 0; layer < layersToRun; ++layer) {
            LayerW& lw = layersW[layer];
            bool isMoE = (layer > 0);

            // Load MoE weights on demand for MoE layers
            if (isMoE && !lw.moeLoaded) {
                std::cerr << "[DS2] Loading MoE weights for layer " << layer << "...\n";
                if (!loadMoELayer(rom, layer)) {
                    std::cerr << "[DS2] Failed to load MoE weights for layer " << layer << "\n";
                    return {};
                }
                std::cerr << "[DS2] MoE layer " << layer << " weights loaded\n";
            }

            std::cerr << "[DS2] Starting layer " << layer << " forward pass\n";

            // Load MoE weights on demand for MoE layers
            if (isMoE && !lw.moeLoaded) {
                if (!loadMoELayer(rom, layer)) {
                    std::cerr << "[DS2] Failed to load MoE weights for layer " << layer << "\n";
                    return {};
                }
            }

            for (uint32_t t = 0; t < seq; ++t) {
                float* ht = &h[t * hidden];

                // ---- attention branch ----
                float normIn[2048];
                std::memcpy(normIn, ht, hidden * sizeof(float));
                rmsNorm(normIn, lw.attnNormW.data(), hidden, 1e-6f);

                // Q projection
                std::vector<float> qAll(heads * (qkNope + qkRope));
                gemvFloat(lw.qW.data(), normIn, qAll.data(), heads * (qkNope + qkRope), hidden);

                // KV-A projection
                std::vector<float> kvA(kvLora + qkRope);
                gemvFloat(lw.kvAMqaW.data(), normIn, kvA.data(), kvLora + qkRope, hidden);

                // KV-B projection
                std::vector<float> kAll(heads * (qkNope + vHead));
                gemvFloat(lw.kvBW.data(), kvA.data(), kAll.data(), heads * (qkNope + vHead), kvLora);

                // Store K/V in cache
                for (uint32_t hh = 0; hh < heads; ++hh) {
                    const float* kRow = &kAll[hh * (qkNope + vHead)];
                    for (uint32_t d = 0; d < qkNope; ++d)
                        kNopeCache[hh * seqCap * qkNope + t * qkNope + d] = kRow[d];
                    for (uint32_t d = 0; d < vHead; ++d)
                        vCache[hh * seqCap * vHead + t * vHead + d] = kRow[qkNope + d];
                }
                // k_rope shared across heads
                for (uint32_t d = 0; d < qkRope; ++d) kRopeCache[t * qkRope + d] = kvA[kvLora + d];

                // RoPE on q_rope and k_rope
                for (uint32_t hh = 0; hh < heads; ++hh) {
                    float* qR = &qAll[hh * (qkNope + qkRope) + qkNope];
                    rope(qR, t, qkRope, theta);
                }
                rope(kRopeCache.data() + t * qkRope, t, qkRope, theta);

                // Causal softmax attention per head
                float attnOut[2048] = {0};
                for (uint32_t hh = 0; hh < heads; ++hh) {
                    float* outH = attnOut + hh * vHead;
                    float scores[256];
                    float maxSc = -1e30f;
                    for (uint32_t tt = 0; tt <= t; ++tt) {
                        float s = 0.0f;
                        for (uint32_t d = 0; d < qkNope; ++d)
                            s += qAll[hh * (qkNope + qkRope) + d] * kNopeCache[hh * seqCap * qkNope + tt * qkNope + d];
                        for (uint32_t d = 0; d < qkRope; ++d)
                            s += qAll[hh * (qkNope + qkRope) + qkNope + d] * kRopeCache[tt * qkRope + d];
                        scores[tt] = s * invSqrtD;
                        if (scores[tt] > maxSc) maxSc = scores[tt];
                    }
                    float sum = 0.0f;
                    for (uint32_t tt = 0; tt <= t; ++tt) { float vv = std::expf(scores[tt] - maxSc); scores[tt] = vv; sum += vv; }
                    for (uint32_t d = 0; d < vHead; ++d) {
                        float acc = 0.0f;
                        for (uint32_t tt = 0; tt <= t; ++tt) acc += scores[tt] * vCache[hh * seqCap * vHead + tt * vHead + d];
                        outH[d] = acc / sum;
                    }
                }

                // residual: h += attn_output @ attn_out
                float attnProj[2048];
                gemvFloat(lw.attnOutW.data(), attnOut, attnProj, hidden, hidden);
                for (uint32_t i = 0; i < hidden; ++i) ht[i] += attnProj[i];

                // ---- FFN branch ----
                std::memcpy(normIn, ht, hidden * sizeof(float));
                rmsNorm(normIn, lw.ffnNormW.data(), hidden, 1e-6f);

                if (!isMoE) {
                    // Dense FFN (layer 0): down(silu(gate(x)) * up(x))
                    std::vector<float> fup(intermediate);
                    gemvFloat(lw.ffnUpW.data(), normIn, fup.data(), intermediate, hidden);
                    std::vector<float> fgate(intermediate);
                    gemvFloat(lw.ffnGateW.data(), normIn, fgate.data(), intermediate, hidden);
                    for (uint32_t i = 0; i < intermediate; ++i) fup[i] *= silu(fgate[i]);

                    std::vector<float> fdown(hidden);
                    gemvFloat(lw.ffnDownW.data(), fup.data(), fdown.data(), hidden, intermediate);
                    for (uint32_t i = 0; i < hidden; ++i) ht[i] += fdown[i];
                } else {
                    // MoE FFN (layers 1+): routed experts + shared experts
                    moeForward(layer, h.data(), t, (int)moeNumExperts, (int)moeTopK,
                               (int)moeNumShared, intermediate);
            }
        }
        std::cerr << "[DS2] Layer " << layer << " complete\n";
    }

        // Debug: norm of position-0 hidden after all layers
        double h0Norm = 0.0;
        for (uint32_t i = 0; i < hidden; ++i) h0Norm += h[i] * h[i];
        std::cerr << "[DS2-DBG] h0Norm after all layers=" << std::sqrt(h0Norm) << "\n";
        float* last = &h[(seq - 1) * hidden];
        double lastNorm = 0.0;
        for (uint32_t i = 0; i < hidden; ++i) lastNorm += last[i] * last[i];
        std::cerr << "[DS2-DBG] lastNorm=" << std::sqrt(lastNorm) << "\n";
        rmsNorm(last, outputNormW.data(), hidden, 1e-6f);
        std::vector<float> logits(vocab);
        gemvFloat(outputW.data(), last, logits.data(), vocab, hidden);
        double lmin=1e18,lmax=-1e18,lnorm=0; int lz=0;
        for (uint32_t i=0;i<vocab;++i){float v=logits[i]; if(v<lmin)lmin=v; if(v>lmax)lmax=v; lnorm+=v*v; if(v==0)lz++;}
        std::cerr << "[DS2-DBG] logits min="<<lmin<<" max="<<lmax<<" norm="<<std::sqrt(lnorm)<<" zeros="<<lz<<"/"<<vocab<<"\n";
        return logits;
    }

    // Dual-GPU forward pass: layers 0-17 on GPU 0 (R9700, 32GB),
    // layers 18-26 on GPU 1 (RX 7800 XT, 16GB).
    std::vector<float> forwardAllLayersDualGPU(const TensorROM& rom, Deep2Engine& engine,
                                                const std::vector<uint32_t>& tokens) {
        const uint32_t seq = (uint32_t)tokens.size();
        std::vector<float> h(seq * hidden, 0.0f);
        for (uint32_t t = 0; t < seq; ++t)
            std::memcpy(&h[t * hidden], &tokenEmbdW[tokens[t] * hidden], hidden * sizeof(float));

        const float invSqrtD = 1.0f / std::sqrtf((float)(qkNope + qkRope));
        const uint32_t layersToRun = layers;

        const uint32_t gpu0LayerCount = 18;

        for (uint32_t layer = 0; layer < layersToRun; ++layer) {
            LayerW& lw = layersW[layer];
            bool isMoE = (layer > 0);

            const deep2::VulkanDevice::Gpu* gpu = (layer < gpu0LayerCount)
                ? engine.vulkan->primary()
                : engine.vulkan->secondary();
            if (!gpu) {
                std::cerr << "[DS2] No GPU available for layer " << layer << "\n";
                return {};
            }
            const char* gpuName = (layer < gpu0LayerCount) ? "R9700 (GPU 0)" : "7800 XT (GPU 1)";
            std::cerr << "[DS2] Layer " << layer << " on " << gpuName << "\n";

            if (isMoE && !lw.moeLoaded) {
                std::cerr << "[DS2] Loading MoE weights for layer " << layer << "...\n";
                if (!loadMoELayer(rom, layer)) {
                    std::cerr << "[DS2] Failed to load MoE weights for layer " << layer << "\n";
                    return {};
                }
                lw.moeLoaded = true;
                std::cerr << "[DS2] MoE layer " << layer << " weights resident on " << gpuName << "\n";
            }

            for (uint32_t t = 0; t < seq; ++t) {
                float* ht = &h[t * hidden];

                float normIn[2048];
                std::memcpy(normIn, ht, hidden * sizeof(float));
                rmsNorm(normIn, lw.attnNormW.data(), hidden, 1e-6f);

                std::vector<float> qAll(heads * (qkNope + qkRope));
                deep2::TensorView wView{ deep2::TensorType::F32,
                    reinterpret_cast<const uint8_t*>(lw.qW.data()),
                    lw.qW.size() * 4, { heads * (qkNope + qkRope), hidden }, true };
                deep2::TensorView xView{ deep2::TensorType::F32,
                    reinterpret_cast<const uint8_t*>(normIn),
                    hidden * 4, { hidden }, true };
                if (!engine.vulkanGemv(*gpu, wView, xView, qAll)) {
                    std::cerr << "[DS2] Vulkan GEMV failed for Q projection on layer " << layer << "\n";
                    return {};
                }

                std::vector<float> kvA(kvLora + qkRope);
                deep2::TensorView kvAMqaView{ deep2::TensorType::F32,
                    reinterpret_cast<const uint8_t*>(lw.kvAMqaW.data()),
                    lw.kvAMqaW.size() * 4, { kvLora + qkRope, hidden }, true };
                if (!engine.vulkanGemv(*gpu, kvAMqaView, xView, kvA)) {
                    std::cerr << "[DS2] Vulkan GEMV failed for KV-A on layer " << layer << "\n";
                    return {};
                }

                std::vector<float> kAll(heads * (qkNope + vHead));
                deep2::TensorView kvBWView{ deep2::TensorType::F32,
                    reinterpret_cast<const uint8_t*>(lw.kvBW.data()),
                    lw.kvBW.size() * 4, { heads * (qkNope + vHead), kvLora }, true };
                deep2::TensorView kvAView{ deep2::TensorType::F32,
                    reinterpret_cast<const uint8_t*>(kvA.data()),
                    kvA.size() * 4, { kvLora + qkRope }, true };
                if (!engine.vulkanGemv(*gpu, kvBWView, kvAView, kAll)) {
                    std::cerr << "[DS2] Vulkan GEMV failed for KV-B on layer " << layer << "\n";
                    return {};
                }

                for (uint32_t hh = 0; hh < heads; ++hh) {
                    const float* kRow = &kAll[hh * (qkNope + vHead)];
                    for (uint32_t d = 0; d < qkNope; ++d)
                        kNopeCache[hh * seqCap * qkNope + t * qkNope + d] = kRow[d];
                    for (uint32_t d = 0; d < vHead; ++d)
                        vCache[hh * seqCap * vHead + t * vHead + d] = kRow[qkNope + d];
                }
                for (uint32_t d = 0; d < qkRope; ++d) kRopeCache[t * qkRope + d] = kvA[kvLora + d];

                for (uint32_t hh = 0; hh < heads; ++hh) {
                    float* qR = &qAll[hh * (qkNope + qkRope) + qkNope];
                    rope(qR, t, qkRope, theta);
                }
                rope(kRopeCache.data() + t * qkRope, t, qkRope, theta);

                float attnOut[2048] = {0};
                for (uint32_t hh = 0; hh < heads; ++hh) {
                    float* outH = attnOut + hh * vHead;
                    float scores[256];
                    float maxSc = -1e30f;
                    for (uint32_t tt = 0; tt <= t; ++tt) {
                        float s = 0.0f;
                        for (uint32_t d = 0; d < qkNope; ++d)
                            s += qAll[hh * (qkNope + qkRope) + d] * kNopeCache[hh * seqCap * qkNope + tt * qkNope + d];
                        for (uint32_t d = 0; d < qkRope; ++d)
                            s += qAll[hh * (qkNope + qkRope) + qkNope + d] * kRopeCache[tt * qkRope + d];
                        scores[tt] = s * invSqrtD;
                        if (scores[tt] > maxSc) maxSc = scores[tt];
                    }
                    float sum = 0.0f;
                    for (uint32_t tt = 0; tt <= t; ++tt) { float vv = std::expf(scores[tt] - maxSc); scores[tt] = vv; sum += vv; }
                    for (uint32_t d = 0; d < vHead; ++d) {
                        float acc = 0.0f;
                        for (uint32_t tt = 0; tt <= t; ++tt) acc += scores[tt] * vCache[hh * seqCap * vHead + tt * vHead + d];
                        outH[d] = acc / sum;
                    }
                }

                for (uint32_t i = 0; i < hidden; ++i) {
                    float acc = 0.0f;
                    for (uint32_t j = 0; j < hidden; ++j)
                        acc += attnOut[j] * lw.attnOutW[i * hidden + j];
                    ht[i] += acc;
                }

                std::memcpy(normIn, ht, hidden * sizeof(float));
                rmsNorm(normIn, lw.ffnNormW.data(), hidden, 1e-6f);

                if (!isMoE) {
                    std::vector<float> fup(intermediate);
                    deep2::TensorView ffnUpView{ deep2::TensorType::F32,
                        reinterpret_cast<const uint8_t*>(lw.ffnUpW.data()),
                        lw.ffnUpW.size() * 4, { intermediate, hidden }, true };
                    if (!engine.vulkanGemv(*gpu, ffnUpView, xView, fup)) {
                        std::cerr << "[DS2] Vulkan GEMV failed for FFN up on layer " << layer << "\n";
                        return {};
                    }
                    for (uint32_t i = 0; i < intermediate; ++i) fup[i] = fup[i] > 0.0f ? fup[i] : 0.0f;

                    std::vector<float> fdown(hidden);
                    deep2::TensorView ffnDownView{ deep2::TensorType::F32,
                        reinterpret_cast<const uint8_t*>(lw.ffnDownW.data()),
                        lw.ffnDownW.size() * 4, { hidden, intermediate }, true };
                    deep2::TensorView fupView{ deep2::TensorType::F32,
                        reinterpret_cast<const uint8_t*>(fup.data()),
                        fup.size() * 4, { intermediate }, true };
                    if (!engine.vulkanGemv(*gpu, ffnDownView, fupView, fdown)) {
                        std::cerr << "[DS2] Vulkan GEMV failed for FFN down on layer " << layer << "\n";
                        return {};
                    }
                    for (uint32_t i = 0; i < hidden; ++i) ht[i] += fdown[i];
                } else {
                    std::vector<float> routerLogits(moeNumExperts);
                    deep2::TensorView routerView{ deep2::TensorType::F32,
                        reinterpret_cast<const uint8_t*>(lw.ffnGateInpW.data()),
                        lw.ffnGateInpW.size() * 4, { moeNumExperts, hidden }, true };
                    if (!engine.vulkanGemv(*gpu, routerView, xView, routerLogits)) {
                        std::cerr << "[DS2] Vulkan GEMV failed for MoE router on layer " << layer << "\n";
                        return {};
                    }

                    float maxLogit = -1e30f;
                    for (int e = 0; e < (int)moeNumExperts; ++e)
                        if (routerLogits[e] > maxLogit) maxLogit = routerLogits[e];
                    float sumExp = 0.0f;
                    std::vector<float> routerWeights(moeNumExperts);
                    for (int e = 0; e < (int)moeNumExperts; ++e) {
                        routerWeights[e] = std::expf(routerLogits[e] - maxLogit);
                        sumExp += routerWeights[e];
                    }
                    for (int e = 0; e < (int)moeNumExperts; ++e)
                        routerWeights[e] /= sumExp;

                    std::vector<std::pair<float, int>> expertScores(moeNumExperts);
                    for (int e = 0; e < (int)moeNumExperts; ++e)
                        expertScores[e] = { routerWeights[e], e };
                    std::sort(expertScores.begin(), expertScores.end(),
                              [](const auto& a, const auto& b) { return a.first > b.first; });

                    std::vector<float> expertAccum(hidden, 0.0f);
                    for (int k = 0; k < (int)moeTopK && k < (int)moeNumExperts; ++k) {
                        int e = expertScores[k].second;
                        float w = expertScores[k].first;

                        const float* gateE = lw.ffnGateExpsW.data() + e * intermediate * hidden;
                        std::vector<float> gateVal(intermediate);
                        deep2::TensorView gateEView{ deep2::TensorType::F32,
                            reinterpret_cast<const uint8_t*>(gateE),
                            intermediate * hidden * 4, { intermediate, hidden }, true };
                        if (!engine.vulkanGemv(*gpu, gateEView, xView, gateVal)) {
                            std::cerr << "[DS2] Vulkan GEMV failed for MoE gate on layer " << layer << " expert " << e << "\n";
                            return {};
                        }

                        const float* upE = lw.ffnUpExpsW.data() + e * intermediate * hidden;
                        std::vector<float> upVal(intermediate);
                        deep2::TensorView upEView{ deep2::TensorType::F32,
                            reinterpret_cast<const uint8_t*>(upE),
                            intermediate * hidden * 4, { intermediate, hidden }, true };
                        if (!engine.vulkanGemv(*gpu, upEView, xView, upVal)) {
                            std::cerr << "[DS2] Vulkan GEMV failed for MoE up on layer " << layer << " expert " << e << "\n";
                            return {};
                        }

                        std::vector<float> intermediateVec(intermediate);
                        for (int i = 0; i < intermediate; ++i)
                            intermediateVec[i] = gateVal[i] / (1.0f + std::expf(-upVal[i]));

                        const float* downE = lw.ffnDownExpsW.data() + e * hidden * intermediate;
                        std::vector<float> expertOut(hidden);
                        deep2::TensorView downEView{ deep2::TensorType::F32,
                            reinterpret_cast<const uint8_t*>(downE),
                            hidden * intermediate * 4, { hidden, intermediate }, true };
                        deep2::TensorView intView{ deep2::TensorType::F32,
                            reinterpret_cast<const uint8_t*>(intermediateVec.data()),
                            intermediate * 4, { intermediate }, true };
                        if (!engine.vulkanGemv(*gpu, downEView, intView, expertOut)) {
                            std::cerr << "[DS2] Vulkan GEMV failed for MoE down on layer " << layer << " expert " << e << "\n";
                            return {};
                        }

                        for (int i = 0; i < hidden; ++i)
                            expertAccum[i] += w * expertOut[i];
                    }

                    std::vector<float> sharedGate(2 * intermediate);
                    deep2::TensorView sharedGateView{ deep2::TensorType::F32,
                        reinterpret_cast<const uint8_t*>(lw.ffnGateShexpW.data()),
                        lw.ffnGateShexpW.size() * 4, { 2 * intermediate, hidden }, true };
                    if (!engine.vulkanGemv(*gpu, sharedGateView, xView, sharedGate)) {
                        std::cerr << "[DS2] Vulkan GEMV failed for MoE shared gate on layer " << layer << "\n";
                        return {};
                    }

                    std::vector<float> sharedUp(2 * intermediate);
                    deep2::TensorView sharedUpView{ deep2::TensorType::F32,
                        reinterpret_cast<const uint8_t*>(lw.ffnUpShexpW.data()),
                        lw.ffnUpShexpW.size() * 4, { 2 * intermediate, hidden }, true };
                    if (!engine.vulkanGemv(*gpu, sharedUpView, xView, sharedUp)) {
                        std::cerr << "[DS2] Vulkan GEMV failed for MoE shared up on layer " << layer << "\n";
                        return {};
                    }

                    std::vector<float> sharedIntermediate(2 * intermediate);
                    for (int i = 0; i < 2 * intermediate; ++i)
                        sharedIntermediate[i] = sharedGate[i] / (1.0f + std::expf(-sharedUp[i]));

                    std::vector<float> sharedOut(hidden);
                    deep2::TensorView sharedDownView{ deep2::TensorType::F32,
                        reinterpret_cast<const uint8_t*>(lw.ffnDownShexpW.data()),
                        lw.ffnDownShexpW.size() * 4, { hidden, 2 * intermediate }, true };
                    deep2::TensorView sharedIntView{ deep2::TensorType::F32,
                        reinterpret_cast<const uint8_t*>(sharedIntermediate.data()),
                        2 * intermediate * 4, { 2 * intermediate }, true };
                    if (!engine.vulkanGemv(*gpu, sharedDownView, sharedIntView, sharedOut)) {
                        std::cerr << "[DS2] Vulkan GEMV failed for MoE shared down on layer " << layer << "\n";
                        return {};
                    }

                    for (int i = 0; i < hidden; ++i)
                        ht[i] += sharedOut[i];
                }
            }
        }

        double h0Norm = 0.0;
        for (uint32_t i = 0; i < hidden; ++i) h0Norm += h[i] * h[i];
        std::cerr << "[DS2-DBG] h0Norm after all layers=" << std::sqrt(h0Norm) << "\n";
        float* last = &h[(seq - 1) * hidden];
        double lastNorm = 0.0;
        for (uint32_t i = 0; i < hidden; ++i) lastNorm += last[i] * last[i];
        std::cerr << "[DS2-DBG] lastNorm=" << std::sqrt(lastNorm) << "\n";
        rmsNorm(last, outputNormW.data(), hidden, 1e-6f);
        std::vector<float> logits(vocab);
        gemvFloat(outputW.data(), last, logits.data(), vocab, hidden);
        double lmin=1e18,lmax=-1e18,lnorm=0; int lz=0;
        for (uint32_t i=0;i<vocab;++i){float v=logits[i]; if(v<lmin)lmin=v; if(v>lmax)lmax=v; lnorm+=v*v; if(v==0)lz++;}
        std::cerr << "[DS2-DBG] logits min="<<lmin<<" max="<<lmax<<" norm="<<std::sqrt(lnorm)<<" zeros="<<lz<<"/"<<vocab<<"\n";
        return logits;
    }
};

// ---------------------------------------------------------------------------
// Oracle driver
// ---------------------------------------------------------------------------
int cmdOracle(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: rom_audit oracle <model.gguf> \"<prompt>\" [max_tokens]\n";
        return 1;
    }
    const std::string modelPath = argv[2];
    const std::string prompt = argv[3];
    uint32_t maxTokens = (argc > 4) ? (uint32_t)std::stoul(argv[4]) : 64;

    TensorROM rom;
    if (!rom.addShard(modelPath)) return 1;
    if (!rom.finalizeIndex()) return 1;

    GgufTokenizer tok;
    if (!tok.loadFromGGUF(modelPath)) return 1;

    std::cerr << "[ORACLE] tokenizer: family="
              << (tok.type() == Deep2Rom::Inference::GgufTokenizerType::Spm ? "spm" : "bpe")
              << " vocab=" << tok.vocabSize() << " bos=" << tok.bosTokenId()
              << " eos=" << tok.eosTokenId() << " unk=" << tok.unkTokenId() << "\n";

    if (maxTokens == 0) {
        std::cout << "[ORACLE] load-only mode: tokenizer+weights OK, skipping generation\n";
        return 0;
    }

    if (rom.geometry().arch == ModelArch::DeepSeek2) {
        // ---- Move 8: DeepSeek-V2-Lite layer-0 (dense MLA) diagnostic ----
        DeepSeek2Model model;
        if (!model.loadRom(rom)) return 1;

        std::vector<uint32_t> tokens = tok.encode(prompt);
        std::vector<uint32_t> run;
        run.push_back(tok.bosTokenId());
        run.insert(run.end(), tokens.begin(), tokens.end());

        std::cout << "[ORACLE] prompt tokens: " << run.size() << " -> ";
        for (uint32_t id : tokens) std::cout << tok.decode(id);
        std::cout << "\n[ORACLE] DeepSeek-V2-Lite layer-0 autoregressive generation...\n";

        for (uint32_t step = 0; step < maxTokens; ++step) {
            std::vector<float> logits = model.forwardAllLayers(rom, run);
            // Greedy sampling: argmax
            uint32_t next = 0; float best = -1e30f;
            for (uint32_t i = 0; i < model.vocab; ++i)
                if (logits[i] > best) { best = logits[i]; next = i; }
            run.push_back(next);
            std::cout << tok.decode(next);
            std::cout.flush();
            if (next == tok.eosTokenId()) break;
            if ((uint32_t)run.size() >= model.seqCap) break;
        }
        std::cout << "\n[ORACLE] generation complete (" << run.size() << " total tokens)\n";
        return 0;
    }

    // ---- Phi-3 full autoregressive oracle (Move 6) ----
    Phi3Model model;
    if (!model.loadRom(rom)) return 1;

    std::vector<uint32_t> tokens = tok.encode(prompt);
    std::vector<uint32_t> run;
    run.push_back(tok.bosTokenId());
    run.insert(run.end(), tokens.begin(), tokens.end());

    std::cout << "[ORACLE] prompt tokens: " << run.size() << " -> ";
    for (uint32_t id : tokens) std::cout << tok.decode(id);
    std::cout << "\n[ORACLE] generating...\n";

    for (uint32_t step = 0; step < maxTokens; ++step) {
        std::vector<float> logits = model.forward(run);
        uint32_t next = 0; float best = -1e30f;
        for (uint32_t i = 0; i < model.vocab; ++i) if (logits[i] > best) { best = logits[i]; next = i; }

        // Report the top candidates. A working model puts a real word at the
        // top; a broken dequant scatters probability over unrelated tokens.
        {
            const size_t kTop = 5;
            std::vector<std::pair<float, uint32_t>> ranked;
            ranked.reserve(model.vocab);
            for (uint32_t i = 0; i < model.vocab; ++i) ranked.emplace_back(logits[i], i);
            std::partial_sort(ranked.begin(),
                              ranked.begin() + (std::min)(kTop, ranked.size()),
                              ranked.end(),
                              [](const auto& a, const auto& b) { return a.first > b.first; });

            float maxLogit = ranked.front().first;
            double sumExp = 0.0;
            for (size_t i = 0; i < kTop && i < ranked.size(); ++i)
                sumExp += std::exp((double)(ranked[i].first - maxLogit));

            std::cout << "\n[ORACLE] step " << step << " top-" << kTop << ":";
            for (size_t i = 0; i < kTop && i < ranked.size(); ++i) {
                const double p = std::exp((double)(ranked[i].first - maxLogit)) / sumExp;
                std::cout << " [" << tok.piece(ranked[i].second) << ":" << ranked[i].second
                          << " p=" << p << "]";
            }
            std::cout << "\n";
        }

        run.push_back(next);
        std::string piece = tok.decode(next);
        std::cout << piece << std::flush;
        if (next == tok.eosTokenId()) break;
        if ((uint32_t)run.size() >= model.seqCap) break;
    }
    std::cout << "\n[ORACLE] done (" << run.size() << " tokens total)\n";
    return 0;
}

// ---------------------------------------------------------------------------
// Tensor dump: dequantize a named tensor and print the first N values.
// Used to cross-check the dequant kernels against a reference implementation.
// ---------------------------------------------------------------------------
int cmdDumpTensor(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: rom_audit dump-tensor <model.gguf> <tensor.name> [count]\n";
        return 1;
    }
    const size_t count = (argc >= 5) ? static_cast<size_t>(std::atoll(argv[4])) : 32;

    TensorROM rom;
    if (!rom.addShard(argv[2])) return 1;
    if (!rom.finalizeIndex()) return 1;

    const TensorEntry* te = rom.findTensor(argv[3]);
    if (!te) {
        std::cerr << "[ORACLE] tensor not found: " << argv[3] << "\n";
        return 1;
    }

    std::vector<uint8_t> raw;
    raw.resize(TensorROM::tensorStorageBytes(*te));
    if (!rom.readTensor(*te, raw.data())) {
        std::cerr << "[ORACLE] failed to read tensor bytes\n";
        return 1;
    }

    TensorView view;
    view.type = te->type;
    view.data = raw.data();
    view.byteSize = raw.size();
    view.dims = te->dims;

    DequantizedTensor dq;
    if (!dequantizeTensor(view, dq)) {
        std::cerr << "[ORACLE] dequant failed for " << argv[3]
                  << " type=" << tensorTypeName(te->type) << "\n";
        return 1;
    }

    std::cout << "# tensor=" << argv[3] << " type=" << tensorTypeName(te->type)
              << " elements=" << dq.data.size() << "\n";
    const size_t n = (std::min)(count, dq.data.size());
    for (size_t i = 0; i < n; ++i) {
        std::cout << i << "\t" << dq.data[i] << "\n";
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Row-split GEMV parity.
//
// A GEMV is row-parallel, so splitting the output rows across two devices
// and concatenating the results has to reproduce the unsplit GEMV exactly.
// This checks the CPU form of the split that the multi-device Vulkan path
// performs, so it can be verified on a machine with a single GPU.
// ---------------------------------------------------------------------------
int cmdGemvSplit(int argc, char** argv) {
    const uint32_t colsList[] = {1, 7, 32, 100, 256, 333};
    const uint32_t rowsList[] = {1, 3, 16, 64, 129};
    const float weights[] = {0.0f, 0.1f, 0.35f, 0.5f, 0.9f, 1.0f};

    Deep2Engine engine;
    size_t checked = 0;
    size_t splitCases = 0;
    size_t mismatches = 0;

    for (uint32_t cols : colsList) {
        for (uint32_t rows : rowsList) {
            // A deterministic pseudo-random matrix, so the comparison is not
            // accidentally satisfied by a degenerate input.
            std::vector<float> W(static_cast<size_t>(rows) * cols);
            uint32_t state = 0x9E3779B9u ^ (cols * 2654435761u) ^ (rows * 40503u);
            for (size_t i = 0; i < W.size(); ++i) {
                state = state * 1664525u + 1013904223u;
                W[i] = static_cast<float>(static_cast<int32_t>(state >> 8) % 2001 - 1000) / 512.0f;
            }
            std::vector<float> x(cols);
            for (uint32_t i = 0; i < cols; ++i) {
                state = state * 1664525u + 1013904223u;
                x[i] = static_cast<float>(static_cast<int32_t>(state >> 8) % 2001 - 1000) / 1024.0f;
            }

            std::vector<float> reference(static_cast<size_t>(rows), 0.0f);
            if (!engine.gemvFloat(W.data(), x.data(), reference.data(), rows, cols)) {
                std::cerr << "[ORACLE] reference GEMV failed\n";
                return 1;
            }

            for (float w : weights) {
                const auto plan = deep2::Quant::CalculateRowSplitIndex(
                    rows, cols, GGML_TYPE_F32, w);
                if (plan.device0Rows > 0 && plan.device0Rows < rows) ++splitCases;

                std::vector<float> split(static_cast<size_t>(rows), 0.0f);
                if (!engine.gemvFloatSplit(W.data(), x.data(), split.data(), rows, cols, w)) {
                    std::cerr << "[ORACLE] split GEMV failed\n";
                    return 1;
                }
                ++checked;

                for (uint32_t r = 0; r < rows; ++r) {
                    if (split[r] != reference[r]) {
                        std::cerr << "[ORACLE] mismatch at row " << r
                                  << " weight=" << w << " rows=" << rows
                                  << " cols=" << cols
                                  << " split=" << split[r] << " ref=" << reference[r]
                                  << " W=" << W[(size_t)r * cols]
                                  << " x0=" << x[0] << "\n";
                        ++mismatches;
                        break;
                    }
                }
            }
        }
    }

    std::cout << "[ORACLE] row-split GEMV parity: " << checked << " cases, "
              << splitCases << " with a non-trivial split\n";
    if (mismatches) {
        std::cerr << "[ORACLE] " << mismatches
                  << " case(s) did not reproduce the single-device GEMV\n";
        return 1;
    }
    std::cout << "[ORACLE] the row-split GEMV reproduces the single-device GEMV exactly\n";
    return 0;
}

// ---------------------------------------------------------------------------
// Tokenizer diagnostics: print the ids and pieces a prompt encodes to.
// ---------------------------------------------------------------------------
int cmdTokenize(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: rom_audit tokenize <model.gguf> \"<prompt>\"\n";
        return 1;
    }
    GgufTokenizer tok;
    if (!tok.loadFromGGUF(argv[2])) return 1;

    std::vector<uint32_t> ids = tok.encode(argv[3]);
    std::cout << ids.size() << " tokens\n";
    for (uint32_t id : ids) {
        std::cout << id << "\t" << tok.piece(id) << "\t" << tok.decode(id) << "\n";
    }
    std::cout << "[decoded] " << tok.decode(ids) << "\n";
    return 0;
}

// ---------------------------------------------------------------------------
// Model metadata
// ---------------------------------------------------------------------------
int cmdInfo(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: rom_audit info <model.gguf>\n";
        return 1;
    }
    TensorROM rom;
    if (!rom.addShard(argv[2])) return 1;
    if (!rom.finalizeIndex()) return 1;

    const auto& g = rom.geometry();
    const char* archName = "unknown";
    switch (g.arch) {
        case ModelArch::Phi3:     archName = "phi3"; break;
        case ModelArch::DeepSeek2: archName = "deepseek2"; break;
        default: break;
    }
    std::cout << "arch         = " << archName << "\n";
    std::cout << "layers       = " << g.numLayers << "\n";
    std::cout << "hidden       = " << g.hiddenDim << "\n";
    std::cout << "heads        = " << g.numHeads << " (kv " << g.numKVHeads << ")\n";
    std::cout << "intermediate = " << g.intermediateDim << "\n";
    std::cout << "vocab        = " << g.vocabSize << "\n";
    std::cout << "max_seq_len  = " << g.maxSeqLen << "\n";
    std::cout << "rope_theta   = " << g.ropeTheta << "\n";
    return 0;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: rom_audit <oracle|tokenize|info> <model.gguf> [args]\n";
        return 2;
    }

    const std::string cmd = argv[1];
    if (cmd == "oracle")       return cmdOracle(argc, argv);
    if (cmd == "tokenize")     return cmdTokenize(argc, argv);
    if (cmd == "info")         return cmdInfo(argc, argv);
    if (cmd == "dump-tensor")  return cmdDumpTensor(argc, argv);
    if (cmd == "gemv-split")   return cmdGemvSplit(argc, argv);

    std::cerr << "unknown command: " << cmd << "\n";
    std::cerr << "usage: rom_audit <oracle|tokenize|info|dump-tensor|gemv-split> "
                 "<model.gguf> [args]\n";
    return 2;
}
