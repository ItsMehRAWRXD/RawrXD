// Deep2 Move 6: Real-token autoregressive oracle for Phi-3 (dense) via the paged ROM path.
// Validates quantized dequant scale factors end-to-end: wrong dequant => garbage tokens instantly.
//
// Usage:
//   rom_audit oracle <model.gguf> "<prompt>" [max_tokens]

#include "TensorROM.hpp"
#include "quant_kernels.hpp"

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
struct GgufTokenizer {
    std::vector<std::string> vocab;   // id -> token string
    std::vector<std::pair<std::string, std::string>> merges; // in GGUF order
    uint32_t bosId = 1, eosId = 2, unkId = 0;

    bool loadFromGguf(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return false;
        uint32_t magic = 0, version = 0;
        f.read(reinterpret_cast<char*>(&magic), 4);
        f.read(reinterpret_cast<char*>(&version), 4);
        if (magic != 0x46554747u) return false;
        uint64_t tensorCount = 0, kvCount = 0;
        f.read(reinterpret_cast<char*>(&tensorCount), 8);
        f.read(reinterpret_cast<char*>(&kvCount), 8);

        auto readStr = [&](std::string& out) -> bool {
            uint64_t len = 0;
            f.read(reinterpret_cast<char*>(&len), 8);
            if (!f || len > (1u << 20)) return false;
            out.resize(static_cast<size_t>(len));
            f.read(out.data(), len);
            return static_cast<bool>(f);
        };
        auto skipValue = [&](uint32_t type) -> bool {
            if (type <= 7) {
                static const uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 1};
                f.seekg(sz[type & 7], std::ios::cur);
                return static_cast<bool>(f);
            }
            if (type == 8) { std::string s; return readStr(s); }
            if (type == 9) {
                uint32_t at = 0;
                uint64_t al = 0;
                f.read(reinterpret_cast<char*>(&at), 4);
                f.read(reinterpret_cast<char*>(&al), 8);
                if (at == 8) {
                    for (uint64_t i = 0; i < al; ++i) { std::string s; if (!readStr(s)) return false; }
                } else {
                    static const uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 8};
                    f.seekg(static_cast<std::streamoff>(al * sz[at & 7]), std::ios::cur);
                }
                return static_cast<bool>(f);
            }
            if (type == 10 || type == 11 || type == 12) { f.seekg(8, std::ios::cur); return static_cast<bool>(f); }
            return false;
        };

        for (uint64_t i = 0; i < kvCount; ++i) {
            std::string key;
            if (!readStr(key)) return false;
            uint32_t type = 0;
            f.read(reinterpret_cast<char*>(&type), 4);
            if (!f) return false;

            if (key == "tokenizer.ggml.tokens") {
                uint32_t at = 0; uint64_t al = 0;
                f.read(reinterpret_cast<char*>(&at), 4);
                f.read(reinterpret_cast<char*>(&al), 8);
                if (at != 8) return false;
                vocab.reserve(al);
                for (uint64_t j = 0; j < al; ++j) { std::string t; if (!readStr(t)) return false; vocab.push_back(std::move(t)); }
            } else if (key == "tokenizer.ggml.token_type") {
                if (type != 9) return false;
                uint32_t at = 0; uint64_t al = 0;
                f.read(reinterpret_cast<char*>(&at), 4);
                f.read(reinterpret_cast<char*>(&al), 8);
                for (uint64_t j = 0; j < al; ++j) { uint32_t v = 0; f.read(reinterpret_cast<char*>(&v), 4); }
            } else if (key == "tokenizer.ggml.merges") {
                uint32_t at = 0; uint64_t al = 0;
                f.read(reinterpret_cast<char*>(&at), 4);
                f.read(reinterpret_cast<char*>(&al), 8);
                std::cerr << "[ORACLE-DBG] merges arrayLen=" << al << " elementType=" << at << "\n";
                if (at != 8) return false;
                merges.reserve(al);
                for (uint64_t j = 0; j < al; ++j) { std::string m; if (!readStr(m)) return false; auto sp = m.find(' '); if (sp != std::string::npos) merges.emplace_back(m.substr(0, sp), m.substr(sp + 1)); }
            } else if (key == "tokenizer.ggml.bos_token_id") { uint32_t v = 0; f.read(reinterpret_cast<char*>(&v), 4); bosId = v; }
            else if (key == "tokenizer.ggml.eos_token_id") { uint32_t v = 0; f.read(reinterpret_cast<char*>(&v), 4); eosId = v; }
            else if (key == "tokenizer.ggml.unknown_token_id") { uint32_t v = 0; f.read(reinterpret_cast<char*>(&v), 4); unkId = v; }
            else { if (!skipValue(type)) return false; }
        }
        if (vocab.empty()) return false;
        std::cerr << "[ORACLE] tokenizer: vocab=" << vocab.size() << " merges=" << merges.size()
                  << " bos=" << bosId << " eos=" << eosId << "\n";
        return true;
    }

    std::vector<uint32_t> encode(const std::string& text) const {
        // Greedy maximum-match segmentation against the GGUF vocab.
        // This GGUF variant ships vocab entries but no merges array, so we match
        // the longest vocab entry at each position; unmatched bytes fall back to
        // the "<0xNN>" byte tokens (ids ~3..258) or unkId.
        std::vector<uint32_t> ids;
        ids.reserve(text.size() * 2);
        size_t pos = 0;
        while (pos < text.size()) {
            size_t bestLen = 0;
            uint32_t bestId = unkId;
            for (size_t i = 0; i < vocab.size(); ++i) {
                const auto& t = vocab[i];
                if (t.empty() || t.size() <= bestLen) continue;
                if (pos + t.size() <= text.size() && text.compare(pos, t.size(), t) == 0) {
                    bestLen = t.size();
                    bestId = (uint32_t)i;
                }
            }
            if (bestLen == 0) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "<0x%02x>", (unsigned char)text[pos]);
                bool found = false;
                for (size_t i = 0; i < vocab.size(); ++i) {
                    if (vocab[i] == buf) { ids.push_back((uint32_t)i); found = true; break; }
                }
                if (!found) ids.push_back(unkId);
                pos += 1;
            } else {
                ids.push_back(bestId);
                pos += bestLen;
            }
        }
        return ids;
    }

    std::string decodeRaw(uint32_t id) const {
        if (id >= vocab.size()) return "";
        const auto& t = vocab[id];
        // Render "<0xNN>" byte tokens as the actual byte for readable output.
        if (t.size() == 5 && t[0] == '<' && t[1] == '0' && t[2] == 'x' && t[4] == '>') {
            unsigned int v = 0;
            std::sscanf(t.c_str() + 3, "%2x", &v);
            return std::string(1, static_cast<char>(v));
        }
        return t;
    }

    std::string decode(uint32_t id) const { return decodeRaw(id); }
};

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

        // Geometry from GGUF metadata-like fixed Phi-3 values (validated against shard index).
        hidden = 3072; layers = 32; heads = 32; intermediate = 8192; vocab = 32064;
        headDim = hidden / heads;
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
                std::memcpy(normIn, ht, hidden * sizeof(float));
                rmsNorm(normIn, lw.ffnNormW.data(), hidden, eps);

                float fup[8192];
                gemvFloat(lw.ffnUpW.data(), normIn, fup, intermediate, hidden);
                for (uint32_t i = 0; i < intermediate; ++i) fup[i] = fup[i] > 0.0f ? fup[i] : 0.0f; // ReLU

                float fdown[3072];
                gemvFloat(lw.ffnDownW.data(), fup, fdown, hidden, intermediate);
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

    std::vector<float> tokenEmbdW;   // [vocab, hidden]
    std::vector<float> outputNormW;  // [hidden]
    std::vector<float> outputW;      // [vocab, hidden]

    struct LayerW {
        std::vector<float> attnNormW;    // [hidden]
        std::vector<float> qW;           // [3*? , hidden] -> logical [3072, hidden]: q_nope[heads][qkNope] + q_rope[heads][qkRope]
        std::vector<float> kvANormW;     // [kvLora]
        std::vector<float> kvAMqaW;      // [kvLora + qkRope, hidden]
        std::vector<float> kvBW;         // [(qkNope + vHead)*heads, kvLora]
        std::vector<float> attnOutW;     // [hidden, hidden]
        std::vector<float> ffnNormW;     // [hidden]
        std::vector<float> ffnUpW;       // [intermediate, hidden]
        std::vector<float> ffnGateW;     // [intermediate, hidden]
        std::vector<float> ffnDownW;     // [hidden, intermediate]
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

        const auto& g = rom.geometry();
        hidden = (uint32_t)g.hiddenDim; layers = (uint32_t)g.numLayers; heads = (uint32_t)g.numHeads;
        intermediate = (uint32_t)g.intermediateDim; vocab = (uint32_t)g.vocabSize;
        theta = (float)g.ropeTheta;
        qkNope = g.qkNopeHeadDim; qkRope = g.qkRopeHeadDim; vHead = g.vHeadDim; kvLora = g.kvLoraRank;
        seqCap = 256;

        layersW.resize(1);
        LayerW& lw = layersW[0];
        if (!readF32(get("blk.0.attn_norm.weight"), lw.attnNormW)) return false;
        if (!readF32(get("blk.0.attn_q.weight"), lw.qW)) return false;
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

    static float silu(float x) { return x / (1.0f + std::expf(-x)); }

    // Logits for the last token of `tokens` (layer 0 only, full recompute with KV cache).
    std::vector<float> forwardLayer0(const std::vector<uint32_t>& tokens) {
        const uint32_t seq = (uint32_t)tokens.size();
        std::vector<float> h(seq * hidden, 0.0f);
        for (uint32_t t = 0; t < seq; ++t)
            std::memcpy(&h[t * hidden], &tokenEmbdW[tokens[t] * hidden], hidden * sizeof(float));

        LayerW& lw = layersW[0];
        const float invSqrtD = 1.0f / std::sqrtf((float)(qkNope + qkRope));

        for (uint32_t t = 0; t < seq; ++t) {
            float* ht = &h[t * hidden];

            float normIn[2048];
            std::memcpy(normIn, ht, hidden * sizeof(float));
            rmsNorm(normIn, lw.attnNormW.data(), hidden, 1e-6f);

            // Q projection: [3072] = q_nope[heads][qkNope] + q_rope[heads][qkRope]
            std::vector<float> qAll(heads * (qkNope + qkRope));
            gemvFloat(lw.qW.data(), normIn, qAll.data(), heads * (qkNope + qkRope), hidden);

            // KV-A projection: [kvLora + qkRope]
            std::vector<float> kvA(kvLora + qkRope);
            gemvFloat(lw.kvAMqaW.data(), normIn, kvA.data(), kvLora + qkRope, hidden);

            // KV-B projection: [(qkNope+vHead)*heads]
            std::vector<float> kAll(heads * (qkNope + vHead));
            gemvFloat(lw.kvBW.data(), kvA.data(), kAll.data(), heads * (qkNope + vHead), kvLora);

            float* kNopeT = &kNopeCache[t * heads * qkNope];
            float* vT = &vCache[t * heads * vHead];
            float* kRopeT = &kRopeCache[t * qkRope];

            for (uint32_t hh = 0; hh < heads; ++hh) {
                const float* qRow = &qAll[hh * (qkNope + qkRope)];
                for (uint32_t d = 0; d < qkNope; ++d) kNopeT[hh * qkNope + d] = qRow[d];
                for (uint32_t d = 0; d < qkRope; ++d) kRopeT[d] = qRow[qkNope + d];
                const float* kRow = &kAll[hh * (qkNope + vHead)];
                for (uint32_t d = 0; d < qkNope; ++d) { /* k_nope stored below with cache index (hh, t) */ }
                // store k_nope at (hh, t): index = hh*seqCap*qkNope + t*qkNope + d
                for (uint32_t d = 0; d < qkNope; ++d) kNopeCache[hh * seqCap * qkNope + t * qkNope + d] = qRow[d];
                for (uint32_t d = 0; d < vHead; ++d) vCache[hh * seqCap * vHead + t * vHead + d] = kRow[qkNope + d];
            }
            // k_rope shared across heads: from kvA tail
            for (uint32_t d = 0; d < qkRope; ++d) kRopeT[d] = kvA[kvLora + d];

            // RoPE on q_rope and k_rope (position t)
            for (uint32_t hh = 0; hh < heads; ++hh) {
                float* qR = &qAll[hh * (qkNope + qkRope) + qkNope];
                rope(qR, t, qkRope, theta);
            }
            rope(kRopeT, t, qkRope, theta);

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

            // FFN (dense, layer 0): down(silu(gate(x)) * up(x))
            std::memcpy(normIn, ht, hidden * sizeof(float));
            rmsNorm(normIn, lw.ffnNormW.data(), hidden, 1e-6f);

            std::vector<float> fup(intermediate);
            gemvFloat(lw.ffnUpW.data(), normIn, fup.data(), intermediate, hidden);
            std::vector<float> fgate(intermediate);
            gemvFloat(lw.ffnGateW.data(), normIn, fgate.data(), intermediate, hidden);
            for (uint32_t i = 0; i < intermediate; ++i) fup[i] *= silu(fgate[i]);

            std::vector<float> fdown(hidden);
            gemvFloat(lw.ffnDownW.data(), fup.data(), fdown.data(), hidden, intermediate);
            for (uint32_t i = 0; i < hidden; ++i) ht[i] += fdown[i];
        }

        float* last = &h[(seq - 1) * hidden];
        rmsNorm(last, outputNormW.data(), hidden, 1e-6f);
        std::vector<float> logits(vocab);
        gemvFloat(outputW.data(), last, logits.data(), vocab, hidden);
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
    if (!tok.loadFromGguf(modelPath)) return 1;

    // Tokenizer diagnostics
    std::cerr << "[ORACLE-DBG] vocab[0..5]:";
    for (size_t i = 0; i < std::min<size_t>(6, tok.vocab.size()); ++i)
        std::cerr << " [" << i << "]=" << tok.vocab[i];
    std::cerr << "\n[ORACLE-DBG] merges=" << tok.merges.size();
    for (size_t i = 0; i < std::min<size_t>(5, tok.merges.size()); ++i)
        std::cerr << " [" << tok.merges[i].first << "][" << tok.merges[i].second << "]";
    std::cerr << "\n[ORACLE-DBG] raw-printable single-char tokens:";
    int nPrint = 0;
    for (size_t i = 0; i < tok.vocab.size() && nPrint < 12; ++i) {
        const auto& t = tok.vocab[i];
        if (t.size() == 1 && ((unsigned char)t[0] >= 32) && ((unsigned char)t[0] < 127)) {
            std::cerr << " [" << i << "]=" << t;
            ++nPrint;
        }
    }
    std::cerr << "\n[ORACLE-DBG] vocab has \"The\"=";
    bool hasThe = false;
    for (const auto& t : tok.vocab) { if (t == "The") { hasThe = true; break; } }
    std::cerr << hasThe << " vocab has \" \"=";
    bool hasSpace = false;
    for (const auto& t : tok.vocab) { if (t == " ") { hasSpace = true; break; } }
    std::cerr << hasSpace << "\n";

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
        run.push_back(tok.bosId);
        run.insert(run.end(), tokens.begin(), tokens.end());

        std::cout << "[ORACLE] prompt tokens: " << run.size() << " -> ";
        for (uint32_t id : tokens) std::cout << tok.decode(id);
        std::cout << "\n[ORACLE] DeepSeek-V2-Lite layer-0 forward pass...\n";

        std::vector<float> logits = model.forwardLayer0(run);
        // top-8 candidates
        std::vector<std::pair<float, uint32_t>> cand;
        cand.reserve(model.vocab);
        for (uint32_t i = 0; i < model.vocab; ++i) cand.emplace_back(logits[i], i);
        std::sort(cand.begin(), cand.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
        float sum = 0.0f;
        for (auto& c : cand) sum += std::expf(c.first - cand[0].first);
        std::cout << "[ORACLE] top-8 next-token candidates:\n";
        for (int i = 0; i < 8 && i < (int)cand.size(); ++i) {
            float p = std::expf(cand[i].first - cand[0].first) / sum;
            std::cout << "  " << i + 1 << ") id=" << cand[i].second << " \"" << tok.decode(cand[i].second)
                      << "\" logit=" << cand[i].first << " p=" << p << "\n";
        }
        std::cout << "[ORACLE] layer-0 forward complete\n";
        return 0;
    }

    // ---- Phi-3 full autoregressive oracle (Move 6) ----
    Phi3Model model;
    if (!model.loadRom(rom)) return 1;

    std::vector<uint32_t> tokens = tok.encode(prompt);
    std::vector<uint32_t> run;
    run.push_back(tok.bosId);
    run.insert(run.end(), tokens.begin(), tokens.end());

    std::cout << "[ORACLE] prompt tokens: " << run.size() << " -> ";
    for (uint32_t id : tokens) std::cout << tok.decode(id);
    std::cout << "\n[ORACLE] generating...\n";

    for (uint32_t step = 0; step < maxTokens; ++step) {
        std::vector<float> logits = model.forward(run);
        uint32_t next = 0; float best = -1e30f;
        for (uint32_t i = 0; i < model.vocab; ++i) if (logits[i] > best) { best = logits[i]; next = i; }
        run.push_back(next);
        std::string piece = tok.decode(next);
        std::cout << piece << std::flush;
        if (next == tok.eosId) break;
        if ((uint32_t)run.size() >= model.seqCap) break;
    }
    std::cout << "\n[ORACLE] done (" << run.size() << " tokens total)\n";
    return 0;
}
