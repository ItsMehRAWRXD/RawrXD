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
#include "core/MlaLayout.hpp"

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

// The root mean square of a vector's components, for the component
// decomposition. The engine prints the same shape, so the two traces can be
// read side by side.
static double ComponentRms(const float* v, size_t n) {
    double s = 0.0;
    for (size_t i = 0; i < n; ++i) s += static_cast<double>(v[i]) * v[i];
    return (n ? std::sqrt(s / n) : 0.0);
}

// Print the reference's per-layer trace, so the first layer where it and
// the engine diverge can be read off directly.
static bool g_traceLayers = false;

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
    // The model reads its layer weights from here, one layer at a time.
    const TensorROM* m_rom = nullptr;

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
        m_rom = &rom;
        return true;
    }

    // Read one layer's weights out of the ROM.
    //
    // The weights are read where they are used and released afterwards, so
    // the peak memory is one layer rather than the whole model.
    bool loadLayer(uint32_t l, LayerW& lw) {
        if (!m_rom) return false;
        std::ostringstream os; os << "blk." << l << ".";
        const std::string p = os.str();
        auto readF32 = [&](const std::string& name, std::vector<float>& out) -> bool {
            const TensorEntry* e = m_rom->findTensor(name);
            if (!e) { std::cerr << "[ORACLE] missing tensor: " << name << "\n"; return false; }
            const uint64_t size = e->byteSize();
            std::vector<uint8_t> raw(size);
            if (!m_rom->readTensor(*e, raw.data())) {
                std::cerr << "[ORACLE] readTensor failed: " << name << "\n"; return false;
            }
            TensorView view{ e->type, raw.data(), size, e->dims, true };
            DequantizedTensor dq;
            if (!dequantizeTensor(view, dq)) {
                std::cerr << "[ORACLE] dequant failed: " << name
                          << " type=" << tensorTypeName(e->type) << "\n"; return false;
            }
            out = std::move(dq.data);
            return true;
        };
        return readF32(p + "attn_norm.weight", lw.attnNormW) &&
               readF32(p + "attn_qkv.weight", lw.qkvW) &&
               readF32(p + "attn_output.weight", lw.attnOutW) &&
               readF32(p + "ffn_norm.weight", lw.ffnNormW) &&
               readF32(p + "ffn_up.weight", lw.ffnUpW) &&
               readF32(p + "ffn_down.weight", lw.ffnDownW);
    }

    // Logits for the last token of `tokens` (full recompute each step; KV cache holds K/V).
    //
    // The layer weights are read from the ROM one layer at a time and
    // released before the next one is read. Holding all of them at once
    // costs about 16 GB of host memory for a 32 layer model, which is more
    // than a build machine has to spare, and it made the parity gate fail
    // with an out-of-memory abort rather than with a result. Reading them
    // on demand brings the peak down to about a gigabyte, which is what
    // makes the gate usable as a check that runs everywhere.
    std::vector<float> forward(const std::vector<uint32_t>& tokens) {
        const uint32_t seq = (uint32_t)tokens.size();
        if (!m_rom || seq == 0) return {};

        // The cache only has to hold the positions this call produces.
        std::vector<float> kCache(static_cast<size_t>(layers) * heads * seq * headDim, 0.0f);
        std::vector<float> vCache(static_cast<size_t>(layers) * heads * seq * headDim, 0.0f);

        std::vector<float> h(seq * hidden, 0.0f);
        for (uint32_t t = 0; t < seq; ++t) {
            const float* emb = &tokenEmbdW[tokens[t] * hidden];
            std::memcpy(&h[t * hidden], emb, hidden * sizeof(float));
        }

        const float invSqrtD = 1.0f / std::sqrtf((float)headDim);

        for (uint32_t l = 0; l < layers; ++l) {
            // This layer's weights, read now and released at the end of the
            // iteration.
            LayerW lw;
            if (!loadLayer(l, lw)) return {};

            float* kLayer = &kCache[l * heads * seq * headDim];
            float* vLayer = &vCache[l * heads * seq * headDim];

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
                    // The cache holds the keys and values in half precision,
                    // and so does the reference. A reference that kept them
                    // in f32 would differ from the engine for a reason that
                    // has nothing to do with whether the engine is right,
                    // and the difference would be invisible in the token
                    // it produces.
                    for (uint32_t d = 0; d < headDim; ++d) {
                        k[hh * headDim + d] = deep2::KvHalfToFloat(
                            deep2::KvFloatToHalf(k[hh * headDim + d]));
                        v[hh * headDim + d] = deep2::KvHalfToFloat(
                            deep2::KvFloatToHalf(v[hh * headDim + d]));
                    }
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

                // The component trace, matching the engine's, so the first
                // branch where the two differ is visible.
                if (g_traceLayers && t == seq - 1) {
                    std::cout << "[ORACLE-COMP] layer=" << l
                              << " attnOutRms=" << ComponentRms(attnOut, hidden)
                              << " attnProjRms=" << ComponentRms(attnProj, hidden)
                              << " streamRms=" << ComponentRms(ht, hidden)
                              << "\n" << std::flush;
                }

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

            // The layer trace, for locating the first layer where the engine
            // and the reference diverge. The engine prints the same shape,
            // so the two traces can be read side by side.
            if (g_traceLayers) {
                const float* lastRow = &h[(seq - 1) * hidden];
                double sum = 0.0;
                float absMax = 0.0f;
                for (uint32_t i = 0; i < hidden; ++i) {
                    sum += lastRow[i];
                    const float a = std::fabs(lastRow[i]);
                    if (a > absMax) absMax = a;
                }
                std::cout << "[ORACLE-TRACE] layer=" << l
                          << " sum=" << sum
                          << " absmax=" << absMax << "\n" << std::flush;
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
// Llama family reference.
//
// This is the independent reference for the Llama executor. It is written
// from the model's own layout rather than from the executor, so the two can
// be compared and a mistake in either one shows up.
//
// The differences from the Phi-3 path are the ones that matter:
//
//   - the query, the key and the value are three separate matrices, not one
//     fused matrix
//   - the key and the value are narrower than the hidden size when the model
//     groups query heads, and the key head a query head reads is its own
//     divided by the group size
//   - the feed-forward is gated with a separate gate projection
//   - the rotary pairs the elements half a head apart rather than the ones
//     next to each other
//   - the rotary frequency base is a model value and is not always 10000
//
// The key and the value are held in the same half precision the engine's
// ring holds them in. A reference that kept them in f32 would differ from
// the engine for a reason that has nothing to do with whether the engine is
// right.
// ---------------------------------------------------------------------------
struct LlamaModel {
    struct LayerW {
        std::vector<float> attnNormW, ffnNormW;
        std::vector<float> qW, kW, vW, attnOutW;
        std::vector<float> gateW, upW, downW;
    };

    const TensorROM* rom = nullptr;
    uint32_t hidden = 0, layers = 0, heads = 0, kvHeads = 0, headDim = 0;
    uint32_t intermediate = 0, vocab = 0, kvWidth = 0;
    uint32_t ropeDim = 0;
    double theta = 10000.0;
    float eps = 1e-5f;
    bool outputTied = false;
    std::vector<float> tokenEmbdW, outputNormW, outputW;

    // Read one tensor and expand it to f32.
    bool readF32(const std::string& name, std::vector<float>& out) const {
        const TensorEntry* e = rom->findTensor(name);
        if (!e) {
            std::cerr << "[LLAMA-ORACLE] missing tensor: " << name << "\n";
            return false;
        }
        const uint64_t size = e->byteSize();
        std::vector<uint8_t> raw(size);
        if (!rom->readTensor(*e, raw.data())) {
            std::cerr << "[LLAMA-ORACLE] readTensor failed: " << name << "\n";
            return false;
        }
        TensorView view{ e->type, raw.data(), size, e->dims, true };
        DequantizedTensor dq;
        if (!dequantizeTensor(view, dq)) {
            std::cerr << "[LLAMA-ORACLE] dequant failed: " << name << "\n";
            return false;
        }
        out = std::move(dq.data);
        return true;
    }

    bool loadRom(const TensorROM& r) {
        rom = &r;
        const auto& g = rom->geometry();
        if (g.arch != ModelArch::Llama) {
            std::cerr << "[LLAMA-ORACLE] the model is not a llama-family model\n";
            return false;
        }
        hidden = static_cast<uint32_t>(g.hiddenDim);
        layers = static_cast<uint32_t>(g.numLayers);
        heads = static_cast<uint32_t>(g.numHeads);
        kvHeads = static_cast<uint32_t>(g.numKVHeads ? g.numKVHeads : g.numHeads);
        intermediate = static_cast<uint32_t>(g.intermediateDim);
        vocab = static_cast<uint32_t>(g.vocabSize);
        theta = g.ropeTheta;

        if (hidden == 0 || layers == 0 || heads == 0 || kvHeads == 0 || heads % kvHeads != 0) {
            std::cerr << "[LLAMA-ORACLE] the head geometry is not usable: " << heads << " heads, "
                      << kvHeads << " kv heads\n";
            return false;
        }
        headDim = hidden / heads;
        kvWidth = kvHeads * headDim;
        ropeDim = headDim;

        // The rotary dimension count and the norm epsilon are model values.
        // The rotary dimension is the number of elements of a head the rotary
        // touches, and it is less than the head for some models.
        if (const std::string* s = rom->findKv("llama.rope.dimension_count")) {
            const long v = std::strtol(s->c_str(), nullptr, 10);
            if (v > 0 && (v % 2) == 0 && v <= static_cast<long>(headDim)) {
                ropeDim = static_cast<uint32_t>(v);
            }
        }
        if (const std::string* s = rom->findKv("llama.attention.layer_norm_rms_epsilon")) {
            eps = static_cast<float>(std::strtod(s->c_str(), nullptr));
        }
        if (!readF32("token_embd.weight", tokenEmbdW)) return false;
        if (!readF32("output_norm.weight", outputNormW)) return false;

        // The output projection is sometimes tied to the token embedding.
        // A model that has no output.weight computes its logits from the
        // embedding matrix, and reading the projection that is not there is
        // the difference between a model that runs and one that does not.
        if (rom->hasTensor("output.weight")) {
            if (!readF32("output.weight", outputW)) return false;
            outputTied = false;
        } else {
            outputW = tokenEmbdW;
            outputTied = true;
        }

        std::cerr << "[LLAMA-ORACLE] hidden=" << hidden << " layers=" << layers
                  << " heads=" << heads << " kvHeads=" << kvHeads << " headDim=" << headDim
                  << " kvWidth=" << kvWidth << " ropeDim=" << ropeDim
                  << " theta=" << theta << " eps=" << eps
                  << " intermediate=" << intermediate << " vocab=" << vocab
                  << (outputTied ? " output=tied-to-embedding" : "") << "\n";
        return true;
    }

    // The rotary, with the elements of a pair half a head apart.
    //
    // This is the pairing the llama family uses. The Phi-3 path pairs the
    // elements next to each other, and using the wrong pairing produces a
    // model that generates fluent nonsense.
    void rope(float* v, size_t headDim_, uint32_t position) const {
        const size_t nRot = ropeDim;
        if (nRot < 2) return;
        const size_t half = nRot / 2;
        for (size_t i = 0; i < half; ++i) {
            const double frequency = 1.0 / std::pow(theta, (2.0 * i) / static_cast<double>(nRot));
            const double angle = static_cast<double>(position) * frequency;
            const float s = static_cast<float>(std::sin(angle));
            const float c = static_cast<float>(std::cos(angle));
            const float v0 = v[i];
            const float v1 = v[i + half];
            v[i] = v0 * c - v1 * s;
            v[i + half] = v0 * s + v1 * c;
        }
    }

    // The attention over the cache, with the query heads grouped onto the
    // key and value heads.
    void groupedAttention(float* out, const float* q, const deep2::HostKvRing& ring,
                          uint32_t layer, uint32_t startLogical, uint32_t count) const {
        std::memset(out, 0, static_cast<size_t>(heads) * headDim * sizeof(float));
        if (count == 0) return;

        const uint32_t groupSize = heads / kvHeads;
        const float scale = 1.0f / std::sqrt(static_cast<float>(headDim));
        std::vector<float> scores(count);

        for (uint32_t h = 0; h < heads; ++h) {
            // The key head this query head reads.
            const uint32_t kvHead = h / groupSize;
            const float* qh = q + static_cast<size_t>(h) * headDim;

            float maxScore = -std::numeric_limits<float>::infinity();
            for (uint32_t t = 0; t < count; ++t) {
                const uint16_t* kh = ring.keyRow(layer, startLogical + t);
                if (!kh) return;
                kh += static_cast<size_t>(kvHead) * headDim;
                float dot = 0.0f;
                for (uint32_t d = 0; d < headDim; ++d) {
                    dot += qh[d] * deep2::KvHalfToFloat(kh[d]);
                }
                scores[t] = dot * scale;
                maxScore = (std::max)(maxScore, scores[t]);
            }

            float expSum = 0.0f;
            for (uint32_t t = 0; t < count; ++t) {
                scores[t] = std::exp(scores[t] - maxScore);
                expSum += scores[t];
            }
            if (expSum <= 0.0f) continue;
            const float invExpSum = 1.0f / expSum;

            float* headOut = out + static_cast<size_t>(h) * headDim;
            for (uint32_t t = 0; t < count; ++t) {
                const uint16_t* vh = ring.valueRow(layer, startLogical + t);
                if (!vh) return;
                vh += static_cast<size_t>(kvHead) * headDim;
                const float weight = scores[t] * invExpSum;
                for (uint32_t d = 0; d < headDim; ++d) {
                    headOut[d] += weight * deep2::KvHalfToFloat(vh[d]);
                }
            }
        }
    }

    // The logits for the last token of `tokens`.
    //
    // The layer weights are read from the ROM one layer at a time and
    // released before the next one is read, so the peak memory is one layer
    // rather than the whole model.
    std::vector<float> forward(const std::vector<uint32_t>& tokens) {
        const uint32_t seq = static_cast<uint32_t>(tokens.size());
        if (seq == 0) return {};

        deep2::HostKvRing ring;
        // The ring's width is the key and value width, which is narrower
        // than the hidden size when the model groups query heads.
        ring.reset(layers, seq, kvWidth);

        std::vector<float> h(seq * hidden, 0.0f);
        for (uint32_t t = 0; t < seq; ++t) {
            std::memcpy(&h[t * hidden], &tokenEmbdW[tokens[t] * hidden], hidden * sizeof(float));
        }

        std::vector<float> normIn(hidden), q(heads * headDim), k(kvHeads * headDim),
            v(kvHeads * headDim), attnOut(hidden), proj(hidden), gate(intermediate),
            up(intermediate), down(hidden);

        for (uint32_t l = 0; l < layers; ++l) {
            LayerW lw;
            {
                std::ostringstream os;
                os << "blk." << l << ".";
                const std::string p = os.str();
                if (!readF32(p + "attn_norm.weight", lw.attnNormW)) return {};
                if (!readF32(p + "attn_q.weight", lw.qW)) return {};
                if (!readF32(p + "attn_k.weight", lw.kW)) return {};
                if (!readF32(p + "attn_v.weight", lw.vW)) return {};
                if (!readF32(p + "attn_output.weight", lw.attnOutW)) return {};
                if (!readF32(p + "ffn_norm.weight", lw.ffnNormW)) return {};
                if (!readF32(p + "ffn_gate.weight", lw.gateW)) return {};
                if (!readF32(p + "ffn_up.weight", lw.upW)) return {};
                if (!readF32(p + "ffn_down.weight", lw.downW)) return {};
            }

            for (uint32_t t = 0; t < seq; ++t) {
                float* ht = &h[t * hidden];

                // Attention branch.
                std::memcpy(normIn.data(), ht, hidden * sizeof(float));
                rmsNorm(normIn.data(), lw.attnNormW.data(), hidden, eps);

                gemvFloat(lw.qW.data(), normIn.data(), q.data(), heads * headDim, hidden);
                gemvFloat(lw.kW.data(), normIn.data(), k.data(), kvHeads * headDim, hidden);
                gemvFloat(lw.vW.data(), normIn.data(), v.data(), kvHeads * headDim, hidden);

                for (uint32_t hIdx = 0; hIdx < heads; ++hIdx) {
                    rope(q.data() + hIdx * headDim, headDim, t);
                }
                for (uint32_t hIdx = 0; hIdx < kvHeads; ++hIdx) {
                    rope(k.data() + hIdx * headDim, headDim, t);
                }

                // The cache holds the key and the value for this position, in
                // the key and value width.
                ring.append(l, t, k.data(), v.data());

                const uint32_t count = t + 1;
                groupedAttention(attnOut.data(), q.data(), ring, l, 0, count);

                gemvFloat(lw.attnOutW.data(), attnOut.data(), proj.data(), hidden, hidden);
                for (uint32_t i = 0; i < hidden; ++i) ht[i] += proj[i];

                // Feed-forward branch: the gate and the up projection are
                // separate, and the activation is silu(gate) * up.
                std::memcpy(normIn.data(), ht, hidden * sizeof(float));
                rmsNorm(normIn.data(), lw.ffnNormW.data(), hidden, eps);

                gemvFloat(lw.gateW.data(), normIn.data(), gate.data(), intermediate, hidden);
                gemvFloat(lw.upW.data(), normIn.data(), up.data(), intermediate, hidden);
                for (uint32_t i = 0; i < intermediate; ++i) {
                    const float g = gate[i];
                    up[i] = (g / (1.0f + std::expf(-g))) * up[i];
                }
                gemvFloat(lw.downW.data(), up.data(), down.data(), hidden, intermediate);
                for (uint32_t i = 0; i < hidden; ++i) ht[i] += down[i];
            }
        }

        // Final norm and the output projection on the last position.
        float* last = &h[(seq - 1) * hidden];
        rmsNorm(last, outputNormW.data(), hidden, eps);
        std::vector<float> logits(vocab);
        gemvFloat(outputW.data(), last, logits.data(), vocab, hidden);
        return logits;
    }
};

// ---------------------------------------------------------------------------
// The Llama family reference, run on its own.
//
// This is the independent answer for a llama-family model. The executor is
// checked against it, and the executor and the reference are written
// separately, so a mistake in the shared understanding of the layout shows
// up as a difference rather than as agreement.
//
//   rom_audit llama-oracle <model.gguf> "<prompt>" [tokens]
//
// The prompt is tokenized with the model's own tokenizer, the beginning of
// sequence token is prepended, and the reference runs the whole sequence.
// The logits for the last position are printed, together with the tokens
// the highest few logits name.
// ---------------------------------------------------------------------------
int cmdLlamaOracle(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: rom_audit llama-oracle <model.gguf> \"<prompt>\" [tokens]\n";
        return 1;
    }
    const std::string modelPath = argv[2];
    const std::string prompt = (argc > 3) ? argv[3] : "The capital of France is";
    const int topN = (argc > 4) ? std::atoi(argv[4]) : 5;

    TensorROM rom;
    if (!rom.addShard(modelPath) || !rom.finalizeIndex()) {
        std::cerr << "[LLAMA-ORACLE] the model could not be indexed\n";
        return 1;
    }

    GgufTokenizer tok;
    if (!tok.loadFromGGUF(modelPath)) {
        std::cerr << "[LLAMA-ORACLE] the tokenizer could not be loaded\n";
        return 1;
    }

    std::vector<uint32_t> tokens = tok.encode(prompt);
    if (tokens.empty()) {
        std::cerr << "[LLAMA-ORACLE] the prompt produced no tokens\n";
        return 1;
    }
    if (tok.bosTokenId() != 0xFFFFFFFFu) {
        tokens.insert(tokens.begin(), tok.bosTokenId());
    }
    std::cerr << "[LLAMA-ORACLE] " << tokens.size() << " prompt token(s)\n";

    LlamaModel model;
    if (!model.loadRom(rom)) return 1;

    const std::vector<float> logits = model.forward(tokens);
    if (logits.empty()) {
        std::cerr << "[LLAMA-ORACLE] the reference produced no logits\n";
        return 1;
    }

    std::vector<std::pair<float, uint32_t>> ranked;
    ranked.reserve(logits.size());
    for (size_t i = 0; i < logits.size(); ++i) ranked.emplace_back(logits[i], (uint32_t)i);
    std::partial_sort(ranked.begin(),
                      ranked.begin() + (std::min)((size_t)topN, ranked.size()),
                      ranked.end(),
                      [](const auto& a, const auto& b) { return a.first > b.first; });

    std::cout << "[LLAMA-ORACLE] logits=" << logits.size() << " top:";
    for (size_t i = 0; i < ranked.size() && i < (size_t)topN; ++i) {
        std::cout << " [" << tok.piece(ranked[i].second) << ":" << ranked[i].second
                  << "=" << ranked[i].first << "]";
    }
    std::cout << "\n";
    std::cout << "[LLAMA-ORACLE] argmax=" << ranked[0].second
              << " piece=" << tok.piece(ranked[0].second) << "\n";
    std::cout.flush();
    return 0;
}

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
    // Feed-forward width of one routed expert. This is not the dense
    // intermediateDim: DeepSeek-V2-Lite has a dense width of 10944 and an
    // expert width of 1408, and the shared expert is twice the expert width.
    uint32_t moeExpertFF = 0;
    uint32_t moeSharedFF = 0;

    // One routed expert's weights, dequantized on demand.
    struct ExpertWeights {
        std::vector<float> gate;  // [expertFF, hidden]
        std::vector<float> up;    // [expertFF, hidden]
        std::vector<float> down;  // [hidden, expertFF]
    };

    // Experts currently resident, and their total footprint. The peak of this
    // number is the quantity the demand paging exists to bound.
    std::unordered_map<int, ExpertWeights> m_expertCache;
    size_t m_expertResidentBytes = 0;
    size_t m_expertPeakBytes = 0;
    size_t m_expertLoads = 0;

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
        // The shared expert is small enough to keep resident for the layer.
        std::vector<float> ffnGateShexpW;// [sharedFF, hidden]
        std::vector<float> ffnUpShexpW;  // [sharedFF, hidden]
        std::vector<float> ffnDownShexpW;// [hidden, sharedFF]
        // The routed experts are demand-paged per position; only the ones the
        // router selects are materialized, and they are released again when
        // the layer finishes.
        std::unordered_map<int, ExpertWeights> experts;
        bool moeLoaded = false;
    };
    std::vector<LayerW> layersW;

    // KV caches: kNope [layers][heads][seq][qkNope], v [layers][heads][seq][vHead], kRope [layers][seq][qkRope] (shared across heads)
    // Multi-head Latent Attention caches.
    //
    // MLA never materialises the per-head key and value vectors: it keeps the
    // compressed latent c_kv (kvLora wide) and the single shared rope key.
    // The per-head keys and values are recovered on the fly from the latent,
    // which is what makes the cache kvLora wide instead of
    // numHeads * (qkNope + vHead).
    std::vector<float> cKVCache;    // [seqCap][kvLora]
    std::vector<float> kRopeCache;  // [seqCap][qkRope]
    // The fused attn_kv_b is expanded per position into the per-head keys
    // and values, which are cached for the causal attention.
    std::vector<float> kNopeCache;  // [heads][seqCap][qkNope]
    std::vector<float> vCache;     // [heads][seqCap][vHead]

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
        moeExpertFF = g.nFfExp;
        moeSharedFF = 2 * moeExpertFF;
        if (moeNumExperts == 0 || moeTopK == 0 || moeExpertFF == 0) {
            std::cerr << "[DS2] incomplete MoE geometry: experts=" << moeNumExperts
                      << " topK=" << moeTopK << " expertFF=" << moeExpertFF << "\n";
            return false;
        }
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

        cKVCache.assign(seqCap * kvLora, 0.0f);
        kRopeCache.assign(seqCap * qkRope, 0.0f);
        kNopeCache.assign((size_t)heads * seqCap * qkNope, 0.0f);
        vCache.assign((size_t)heads * seqCap * vHead, 0.0f);

        std::cerr << "[DS2] model resident: hidden=" << hidden << " layers=" << layers
                  << " heads=" << heads << " qkNope=" << qkNope << " qkRope=" << qkRope
                  << " vHead=" << vHead << " kvLora=" << kvLora << " ffn=" << intermediate
                  << " vocab=" << vocab << "\n";
        return true;
    }

    // Load a layer's weights that are needed for every position: the
    // attention projections, the norms, and the dense or MoE feed-forward.
    //
    // The routed experts are NOT loaded here. They are the bulk of a MoE
    // layer (2.28 GB dequantized for DeepSeek-V2-Lite) and only the topK=6
    // the router picks are ever used, so they are demand-paged per position
    // by loadMoEExpert(). Keeping all 64 of them resident for all 26 MoE
    // layers was a 59 GB allocation on a 63 GB host.
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

        // The attention projections and the norms are needed by every layer.
        if (!readF32(get(p + "attn_norm.weight"), lw.attnNormW)) return false;
        if (!readF32(get(p + "attn_q.weight"), lw.qW)) return false;
        if (!readF32(get(p + "attn_kv_a_norm.weight"), lw.kvANormW)) return false;
        if (!readF32(get(p + "attn_kv_a_mqa.weight"), lw.kvAMqaW)) return false;
        if (!readF32(get(p + "attn_kv_b.weight"), lw.kvBW)) return false;
        if (!readF32(get(p + "attn_output.weight"), lw.attnOutW)) return false;
        if (!readF32(get(p + "ffn_norm.weight"), lw.ffnNormW)) return false;

        if (layerIdx == 0) {
            // The leading dense block has a plain feed-forward.
            if (!readF32(get(p + "ffn_up.weight"), lw.ffnUpW)) return false;
            if (!readF32(get(p + "ffn_gate.weight"), lw.ffnGateW)) return false;
            if (!readF32(get(p + "ffn_down.weight"), lw.ffnDownW)) return false;
        } else {
            // The router and the shared expert stay resident for the layer.
            if (!readF32(get(p + "ffn_gate_inp.weight"), lw.ffnGateInpW)) return false;
            if (!readF32(get(p + "ffn_gate_shexp.weight"), lw.ffnGateShexpW)) return false;
            if (!readF32(get(p + "ffn_up_shexp.weight"), lw.ffnUpShexpW)) return false;
            if (!readF32(get(p + "ffn_down_shexp.weight"), lw.ffnDownShexpW)) return false;
        }

        lw.moeLoaded = true;
        std::cerr << "[DS2] layer " << layerIdx << " weights resident"
                  << (layerIdx == 0 ? " (dense)" : " (router + shared expert)") << "\n";
        return true;
    }

    // Load one routed expert.
    //
    // The expert weights live in a single 3-D tensor per projection
    // (ffn_gate_exps, ffn_up_exps, ffn_down_exps) whose outermost dimension
    // is the expert index, so an expert is a contiguous slice of that tensor
    // rather than a tensor of its own. The slice starts at a quant block
    // boundary, because the per-expert element count is a multiple of the
    // block size, so only the expert's own bytes are read and dequantized.
    bool loadMoEExpert(const TensorROM& rom, int layerIdx, int expertId, ExpertWeights& out) {
        const int expertFF = (int)moeExpertFF;
        const uint32_t expertBytes = (uint32_t)expertFF * hidden;

        auto loadSlice = [&](const char* suffix, uint32_t rows, uint32_t cols,
                             std::vector<float>& dst) -> bool {
            const TensorEntry* e = rom.findTensor("blk." + std::to_string(layerIdx) + "." + suffix);
            if (!e) {
                std::cerr << "[DS2] missing expert tensor: blk." << layerIdx << "." << suffix << "\n";
                return false;
            }
            const ggml_type gtype = static_cast<ggml_type>(e->type);
            const uint32_t blockElems = deep2::Quant::ElementsPerBlock(gtype);
            const uint32_t blockBytes = deep2::Quant::BlockBytes(gtype);
            const uint64_t elementsPerExpert = (uint64_t)rows * cols;
            if (blockElems == 0 || blockBytes == 0 || (elementsPerExpert % blockElems) != 0) {
                std::cerr << "[DS2] expert slice is not block aligned: " << e->name
                          << " elements=" << elementsPerExpert << " blockElems=" << blockElems << "\n";
                return false;
            }
            const uint64_t bytesPerExpert = (elementsPerExpert / blockElems) * blockBytes;
            const uint64_t offset = (uint64_t)expertId * bytesPerExpert;
            if (offset + bytesPerExpert > e->byteSize()) {
                std::cerr << "[DS2] expert " << expertId << " out of range in " << e->name << "\n";
                return false;
            }

            std::vector<uint8_t> raw(bytesPerExpert);
            if (!rom.readTensorRange(*e, offset, bytesPerExpert, raw.data())) {
                std::cerr << "[DS2] readTensorRange failed for expert " << expertId
                          << " of " << e->name << "\n";
                return false;
            }

            // The slice is a 2-D [rows, cols] block of the original tensor.
            TensorView view{ e->type, raw.data(), raw.size(), { rows, cols }, true };
            DequantizedTensor dq;
            if (!dequantizeTensor(view, dq)) {
                std::cerr << "[DS2] dequant failed for expert " << expertId
                          << " of " << e->name << "\n";
                return false;
            }
            dst = std::move(dq.data);
            return true;
        };

        // gate and up are [expertFF, hidden]; down is [hidden, expertFF].
        if (!loadSlice("ffn_gate_exps.weight", expertFF, hidden, out.gate)) return false;
        if (!loadSlice("ffn_up_exps.weight", expertFF, hidden, out.up)) return false;
        if (!loadSlice("ffn_down_exps.weight", hidden, expertFF, out.down)) return false;

        m_expertResidentBytes += out.gate.size() * sizeof(float)
                               + out.up.size() * sizeof(float)
                               + out.down.size() * sizeof(float);
        return true;
    }

    // Drop every cached expert. The router and the shared expert stay.
    void releaseMoEExperts() {
        for (auto& kv : m_expertCache) {
            m_expertResidentBytes -= (kv.second.gate.size() + kv.second.up.size()
                                      + kv.second.down.size()) * sizeof(float);
        }
        m_expertCache.clear();
    }

    static float silu(float x) { return x / (1.0f + std::expf(-x)); }

    // MoE forward pass for a single position
    // Multi-head Latent Attention for one position.
    //
    // MLA never materialises the per-head key and value vectors: it caches the
    // compressed latent c_kv (kvLora wide) and the single shared rope key,
    // and recovers the per-head keys and values from the latent on the fly.
    // That is what makes the cache kvLora wide instead of
    // numHeads * (qkNope + vHead), and it is also what lets the key up
    // projection be applied to the query instead of to every cached key.
    //
    // The caller supplies the query projection and the KV-A projection; this
    // applies the rope, updates the cache, and produces the attention output
    // projected back into the residual stream.
    void mlaAttention(int layerIdx, float* ht, std::vector<float>& qAll,
                      const std::vector<float>& kvA, uint32_t t) {
        LayerW& lw = layersW[layerIdx];
        const float invSqrtD = 1.0f / std::sqrtf((float)(qkNope + qkRope));

        // The latent is RMS normalized before it is cached; the rope key is
        // the tail of the same projection.
        float* cKV = cKVCache.data() + (size_t)t * kvLora;
        std::memcpy(cKV, kvA.data(), kvLora * sizeof(float));
        rmsNorm(cKV, lw.kvANormW.data(), kvLora, 1e-6f);

        float* kRope = kRopeCache.data() + (size_t)t * qkRope;
        std::memcpy(kRope, kvA.data() + kvLora, qkRope * sizeof(float));

        // RoPE on q_rope and k_rope
        for (uint32_t hh = 0; hh < heads; ++hh) {
            rope(&qAll[hh * (qkNope + qkRope) + qkNope], t, qkRope, theta);
        }
        rope(kRope, t, qkRope, theta);

        // Expand the latent into this position's per-head keys and values.
        //
        // The expansion is the one llama.cpp's deepseek2.cpp performs for a
        // fused attn_kv_b: one row block per head, the key rows first and the
        // value rows second. The MLA absorption optimization, which projects
        // the query through the key up-projection instead and keeps the cache
        // kvLora wide, needs the split attn_k_b and attn_v_b tensors; this
        // file has neither.
        {
            Deep2Rom::MlaKvBLayout kvLayout;
            kvLayout.numHeads = heads;
            kvLayout.qkNope   = qkNope;
            kvLayout.vHead    = vHead;
            kvLayout.kvLora   = kvLora;

            std::vector<float> kv;
            gemvFloat(lw.kvBW.data(), cKV, kv.data(), kvLayout.totalRows(), kvLora);

            std::vector<float> keys, values;
            Deep2Rom::expandFusedAttnKvB(kv.data(), kvLayout, keys, values);

            for (uint32_t hh = 0; hh < heads; ++hh) {
                std::memcpy(&kNopeCache[((size_t)hh * seqCap + t) * qkNope],
                            &keys[(size_t)hh * qkNope], qkNope * sizeof(float));
                std::memcpy(&vCache[((size_t)hh * seqCap + t) * vHead],
                            &values[(size_t)hh * vHead], vHead * sizeof(float));
            }
        }

        // Causal softmax attention per head.
        std::vector<float> attnOut((size_t)heads * vHead, 0.0f);
        std::vector<float> scores(t + 1);
        for (uint32_t hh = 0; hh < heads; ++hh) {
            const float* qNope = &qAll[hh * (qkNope + qkRope)];
            const float* qRope = qNope + qkNope;
            float* outH = attnOut.data() + (size_t)hh * vHead;

            float maxSc = -1e30f;
            for (uint32_t tt = 0; tt <= t; ++tt) {
                const float* kN = &kNopeCache[((size_t)hh * seqCap + tt) * qkNope];
                const float* kR = &kRopeCache[(size_t)tt * qkRope];
                float s = 0.0f;
                for (uint32_t d = 0; d < qkNope; ++d) s += qNope[d] * kN[d];
                for (uint32_t d = 0; d < qkRope; ++d) s += qRope[d] * kR[d];
                scores[tt] = s * invSqrtD;
                if (scores[tt] > maxSc) maxSc = scores[tt];
            }
            float sum = 0.0f;
            for (uint32_t tt = 0; tt <= t; ++tt) {
                const float e = std::expf(scores[tt] - maxSc);
                scores[tt] = e;
                sum += e;
            }
            const float invSum = (sum > 0.0f) ? (1.0f / sum) : 0.0f;

            for (uint32_t d = 0; d < vHead; ++d) {
                float acc = 0.0f;
                for (uint32_t tt = 0; tt <= t; ++tt) {
                    acc += scores[tt] * vCache[((size_t)hh * seqCap + tt) * vHead + d];
                }
                outH[d] = acc * invSum;
            }
        }

        // residual: h += attn_output @ attn_out
        std::vector<float> attnProj(hidden);
        gemvFloat(lw.attnOutW.data(), attnOut.data(), attnProj.data(), hidden, hidden);
        for (uint32_t i = 0; i < hidden; ++i) ht[i] += attnProj[i];

        {
            auto bad = [](const std::vector<float>& v) {
                int c = 0;
                for (float x : v) if (!std::isfinite(x)) ++c;
                return c;
            };
            const int nQ = bad(qAll), nKvA = bad(kvA);
            const int nC = bad(std::vector<float>(cKV, cKV + kvLora));
            const int nO = bad(attnOut), nP = bad(attnProj);
            int nH = 0;
            for (uint32_t i = 0; i < hidden; ++i) if (!std::isfinite(ht[i])) ++nH;
            if (nQ || nKvA || nC || nO || nP || nH) {
                std::cerr << "[MLA-DBG] layer " << layerIdx << " t=" << t
                          << " nonfinite: q=" << nQ << " kvA=" << nKvA << " cKV=" << nC
                          << " attnOut=" << nO << " attnProj=" << nP << " ht=" << nH
                          << " kvANormW=" << lw.kvANormW.size()
                          << " kvBW=" << lw.kvBW.size() << "\n";
            }
        }
    }

    // MoE forward pass for a single position.
    //
    // `ht` is the residual stream, which the MoE output is added to. `ffnIn`
    // is the *normalized* hidden state the feed-forward projections consume.
    // They are not the same: the block normalizes before the projection, and
    // feeding the raw residual to the experts makes the stream grow without
    // bound across layers.
    void moeForward(const TensorROM& rom, int layerIdx, float* ht, const float* ffnIn,
                    int t, int numExperts, int topK, int numShared,
                    int intermediate) {
        LayerW& lw = layersW[layerIdx];
        if (!lw.moeLoaded) return;

        // The routed experts use the expert feed-forward width, not the dense
        // intermediate width. DeepSeek-V2-Lite: dense 10944, expert 1408.
        const int expertFF = (int)moeExpertFF;
        const int sharedFF = (int)moeSharedFF;


        // Router: x @ ffn_gate_inpW -> [numExperts]
        std::vector<float> routerLogits(numExperts);
        gemvFloat(lw.ffnGateInpW.data(), ffnIn, routerLogits.data(), numExperts, hidden);

        // DeepSeek-V2 gates with a sigmoid, not a softmax: an expert's score
        // is independent of the other experts.
        std::vector<float> routerScores(numExperts);
        for (int e = 0; e < numExperts; ++e) {
            routerScores[e] = 1.0f / (1.0f + std::expf(-routerLogits[e]));
        }

        // Top-k selection
        std::vector<std::pair<float, int>> expertScores(numExperts);
        for (int e = 0; e < numExperts; ++e) expertScores[e] = {routerScores[e], e};
        std::sort(expertScores.begin(), expertScores.end(),
                  [](const auto& a, const auto& b) { return a.first > b.first; });

        // Renormalise the selected gates over the top-k, as DeepSeek-V2 does.
        float topSum = 0.0f;
        for (int k = 0; k < topK && k < numExperts; ++k) topSum += expertScores[k].first;
        if (topSum > 0.0f) {
            for (int k = 0; k < topK && k < numExperts; ++k) {
                expertScores[k].first /= topSum;
            }
        }

        // Accumulate expert outputs
        std::vector<float> expertOut(hidden, 0.0f);
        for (int k = 0; k < topK && k < numExperts; ++k) {
            int e = expertScores[k].second;
            float w = expertScores[k].first;

            // Demand-page this expert: only the selected experts are ever
            // materialized, and they are released when the layer finishes.
            auto cit = lw.experts.find(e);
            if (cit == lw.experts.end()) {
                ExpertWeights ew;
                if (!loadMoEExpert(rom, layerIdx, e, ew)) {
                    std::cerr << "[DS2] failed to page expert " << e
                              << " of layer " << layerIdx << "\n";
                    return;
                }
                cit = lw.experts.emplace(e, std::move(ew)).first;
                ++m_expertLoads;
                if (m_expertResidentBytes > m_expertPeakBytes) {
                    m_expertPeakBytes = m_expertResidentBytes;
                }
            }
            const ExpertWeights& ew = cit->second;

            // Gate: x @ gate_exps[e] -> [expertFF]
            std::vector<float> gateVal(expertFF);
            gemvFloat(ew.gate.data(), ffnIn, gateVal.data(), expertFF, hidden);

            // Up: x @ up_exps[e] -> [expertFF]
            std::vector<float> upVal(expertFF);
            gemvFloat(ew.up.data(), ffnIn, upVal.data(), expertFF, hidden);

            // SwiGLU: silu(gate) * up
            std::vector<float> intermediateVec(expertFF);
            for (int i = 0; i < expertFF; ++i) {
                intermediateVec[i] = silu(gateVal[i]) * upVal[i];
            }

            // Down: intermediate @ down_exps[e] -> [hidden]
            std::vector<float> expertOutE(hidden);
            gemvFloat(ew.down.data(), intermediateVec.data(), expertOutE.data(), hidden, expertFF);

            // Weighted combination
            for (int i = 0; i < hidden; ++i)
                ht[i] += w * expertOutE[i];
        }

        // Shared expert. Its feed-forward width is twice the routed expert
        // width (DeepSeek-V2-Lite: 2816 against 1408).
        // shared_gate = x @ gate_shexpW -> [sharedFF]
        std::vector<float> sharedGate(sharedFF);
        gemvFloat(lw.ffnGateShexpW.data(), ffnIn, sharedGate.data(), sharedFF, hidden);

        // shared_up = x @ up_shexpW -> [sharedFF]
        std::vector<float> sharedUp(sharedFF);
        gemvFloat(lw.ffnUpShexpW.data(), ffnIn, sharedUp.data(), sharedFF, hidden);

        // shared_intermediate = silu(shared_gate) * shared_up
        std::vector<float> sharedIntermediate(sharedFF);
        for (int i = 0; i < sharedFF; ++i) {
            sharedIntermediate[i] = silu(sharedGate[i]) * sharedUp[i];
        }

        // shared_out = shared_intermediate @ down_shexpW -> [hidden]
        // down_shexpW: [sharedFF, hidden]
        std::vector<float> sharedOut(hidden);
        gemvFloat(lw.ffnDownShexpW.data(), sharedIntermediate.data(), sharedOut.data(), hidden, sharedFF);

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

            // Every layer's attention projections and norms are needed, not
            // just layer 0's. Loading only layer 0 left the rest empty and
            // the first MoE layer dereferenced a null norm vector.
            if (!lw.moeLoaded) {
                std::cerr << "[DS2] Loading weights for layer " << layer << "...\n";
                if (!loadMoELayer(rom, layer)) {
                    std::cerr << "[DS2] Failed to load weights for layer " << layer << "\n";
                    return {};
                }
            }

            // The previous layer's experts are released before the next
            // layer's are paged, so the resident footprint stays at one
            // layer's worth of selected experts.
            if (layer > 0) {
                layersW[layer - 1].experts.clear();
                m_expertResidentBytes = 0;
            }

            std::cerr << "[DS2] Starting layer " << layer << " forward pass\n";

            for (uint32_t t = 0; t < seq; ++t) {
                float* ht = &h[t * hidden];

                // ---- attention branch ----
                float normIn[2048];
                std::memcpy(normIn, ht, hidden * sizeof(float));
                rmsNorm(normIn, lw.attnNormW.data(), hidden, 1e-6f);

                // Q projection
                std::vector<float> qAll(heads * (qkNope + qkRope));
                gemvFloat(lw.qW.data(), normIn, qAll.data(), heads * (qkNope + qkRope), hidden);

                // KV-A projection: the compressed latent c_kv (kvLora wide)
                // and the shared rope key (qkRope wide) come out of one
                // matrix.
                std::vector<float> kvA(kvLora + qkRope);
                gemvFloat(lw.kvAMqaW.data(), normIn, kvA.data(), kvLora + qkRope, hidden);

                mlaAttention(layer, ht, qAll, kvA, t);

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
                    moeForward(rom, layer, h.data() + (size_t)t * hidden, normIn, t,
                               (int)moeNumExperts, (int)moeTopK,
                               (int)moeNumShared, intermediate);
            }
        }
        std::cerr << "[DS2] Layer " << layer << " complete\n";
    }

        // The demand-paged experts are released as each layer finishes, so the
        // peak resident footprint is one layer's worth of selected experts
        // rather than every expert of every layer.
        releaseMoEExperts();
        std::cerr << "[DS2] expert paging: " << m_expertLoads << " expert loads, peak resident "
                  << (m_expertPeakBytes / (1024 * 1024)) << " MB, now "
                  << (m_expertResidentBytes / (1024 * 1024)) << " MB\n";


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

                mlaAttention(layer, ht, qAll, kvA, t);

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
                    // DeepSeek-V2 gates with a sigmoid, and renormalises the
                    // selected top-k.
                    std::vector<float> routerScores(moeNumExperts);
                    for (int e = 0; e < (int)moeNumExperts; ++e) {
                        routerScores[e] = 1.0f / (1.0f + std::expf(-routerLogits[e]));
                    }

                    std::vector<std::pair<float, int>> expertScores(moeNumExperts);
                    for (int e = 0; e < (int)moeNumExperts; ++e)
                        expertScores[e] = { routerScores[e], e };
                    std::sort(expertScores.begin(), expertScores.end(),
                              [](const auto& a, const auto& b) { return a.first > b.first; });

                    float topSum = 0.0f;
                    for (int k = 0; k < (int)moeTopK && k < (int)moeNumExperts; ++k)
                        topSum += expertScores[k].first;
                    if (topSum > 0.0f) {
                        for (int k = 0; k < (int)moeTopK && k < (int)moeNumExperts; ++k)
                            expertScores[k].first /= topSum;
                    }

                    const int expertFF = (int)moeExpertFF;
                    std::vector<float> expertAccum(hidden, 0.0f);
                    for (int k = 0; k < (int)moeTopK && k < (int)moeNumExperts; ++k) {
                        int e = expertScores[k].second;
                        float w = expertScores[k].first;

                        // Demand-page this expert, same as the CPU path.
                        auto cit = lw.experts.find(e);
                        if (cit == lw.experts.end()) {
                            ExpertWeights ew;
                            if (!loadMoEExpert(rom, layer, e, ew)) {
                                std::cerr << "[DS2] failed to page expert " << e
                                          << " of layer " << layer << "\n";
                                return {};
                            }
                            cit = lw.experts.emplace(e, std::move(ew)).first;
                            ++m_expertLoads;
                            if (m_expertResidentBytes > m_expertPeakBytes) {
                                m_expertPeakBytes = m_expertResidentBytes;
                            }
                        }
                        const ExpertWeights& ew = cit->second;

                        std::vector<float> gateVal(expertFF);
                        deep2::TensorView gateEView{ deep2::TensorType::F32,
                            reinterpret_cast<const uint8_t*>(ew.gate.data()),
                            ew.gate.size() * sizeof(float), { (uint64_t)expertFF, (uint64_t)hidden }, true };
                        if (!engine.vulkanGemv(*gpu, gateEView, xView, gateVal)) {
                            std::cerr << "[DS2] Vulkan GEMV failed for MoE gate on layer " << layer << " expert " << e << "\n";
                            return {};
                        }

                        std::vector<float> upVal(expertFF);
                        deep2::TensorView upEView{ deep2::TensorType::F32,
                            reinterpret_cast<const uint8_t*>(ew.up.data()),
                            ew.up.size() * sizeof(float), { (uint64_t)expertFF, (uint64_t)hidden }, true };
                        if (!engine.vulkanGemv(*gpu, upEView, xView, upVal)) {
                            std::cerr << "[DS2] Vulkan GEMV failed for MoE up on layer " << layer << " expert " << e << "\n";
                            return {};
                        }

                        // SwiGLU: silu(gate) * up
                        std::vector<float> intermediateVec(expertFF);
                        for (int i = 0; i < expertFF; ++i) {
                            intermediateVec[i] = (gateVal[i] / (1.0f + std::expf(-gateVal[i]))) * upVal[i];
                        }

                        std::vector<float> expertOut(hidden);
                        deep2::TensorView downEView{ deep2::TensorType::F32,
                            reinterpret_cast<const uint8_t*>(ew.down.data()),
                            ew.down.size() * sizeof(float), { (uint64_t)hidden, (uint64_t)expertFF }, true };
                        deep2::TensorView intView{ deep2::TensorType::F32,
                            reinterpret_cast<const uint8_t*>(intermediateVec.data()),
                            intermediateVec.size() * sizeof(float), { (uint64_t)expertFF }, true };
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

// The index of the largest value, or -1 when the vector is empty.
static int argmaxOf(const std::vector<float>& v) {
    if (v.empty()) return -1;
    int best = 0;
    for (size_t i = 1; i < v.size(); ++i) {
        if (v[i] > v[best]) best = static_cast<int>(i);
    }
    return best;
}

// ---------------------------------------------------------------------------
// Incremental decode parity.
// The oracle driver re-runs the whole prefix at every step, so it always
// sees the true context. A decode loop that keeps its cache and only
// computes the new position has to produce the same answer, and it does
// not follow that it does: the two can agree on every projection and
// still disagree on the text, because the attention is the part that
// depends on the state carried between steps.
//
// This compares three things for the same prompt:
//
//   1. the oracle, which recomputes the whole prefix,
//   2. the engine's full-prefix pass, which computes every position in one
//      pass over a fresh cache,
//   3. the engine's incremental pass, which computes one position at a time
//      against a cache that is kept between the calls.
//
// If 1 and 2 agree and 3 does not, the cache is what is wrong. If 2 and 3
// agree and 1 does not, the engine's attention is what is wrong.
// ---------------------------------------------------------------------------
int cmdKvIncremental(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: rom_audit kv-incremental <model.gguf> \"<prompt>\" [cpu|gpu]\n";
        return 1;
    }
    const std::string modelPath = argv[2];
    const std::string prompt = (argc > 3) ? argv[3] : "The capital of France is";

    // 77 is the automake convention for "skipped". The test that runs this
    // declares SKIP_RETURN_CODE 77, so CTest reports the gate as Skipped
    // rather than as Passed. A gate that cannot run must be visible in the
    // test report, not green because it did nothing.
    {
        std::ifstream probe(modelPath, std::ios::binary);
        if (!probe) {
            std::cout << "[KVPARITY] SKIPPED: no model at " << modelPath << "\n" << std::flush;
            return 77;
        }
    }

    TensorROM rom;
    if (!rom.addShard(modelPath) || !rom.finalizeIndex()) return 1;

    GgufTokenizer tok;
    if (!tok.loadFromGGUF(modelPath)) return 1;

    std::vector<uint32_t> tokens = tok.encode(prompt);
    tokens.insert(tokens.begin(), tok.bosTokenId());
    std::cerr << "[KVPARITY] " << tokens.size() << " prompt token(s)\n";

    // 1. The reference: the oracle, which recomputes the whole prefix.
    std::vector<float> reference;
    {
        Phi3Model model;
        if (!model.loadRom(rom)) return 1;
        g_traceLayers = true;
        reference = model.forward(tokens);
        g_traceLayers = false;
    }

    // 2 and 3: the engine.
    Deep2Engine engine;
    if (!engine.Initialize(modelPath, "", false)) {
        std::cerr << "[KVPARITY] the engine could not be initialized\n";
        return 1;
    }

    const auto& g = engine.rom.geometry();

    // 2. The full-prefix pass.
    //
    // The CPU mode runs the engine's own CPU path, which is the path the
    // GPU path is checked against. The three bugs that made the engine
    // produce noise were all in the code the two paths share, so the CPU
    // mode catches every one of them, and it needs no GPU. That is what
    // makes the gate runnable on a build machine.
    const bool cpuMode = (argc > 4) && (std::string(argv[4]) == "--cpu");
    std::vector<float> fullLogits;
    std::vector<float> baseline;
    engine.m_layerTrace = true;
    if (!engine.executePhi3ROMForwardPass(tokens, fullLogits, baseline, cpuMode)) {
        std::cerr << "[KVPARITY] the full-prefix pass failed\n";
        return 1;
    }
    engine.m_layerTrace = false;

    // 3. The incremental passes, against a cache that is kept between them.
    std::vector<float> incrementalLogits;
    {
        deep2::HostKvRing ring;
        ring.reset(static_cast<uint32_t>(g.numLayers), 64, static_cast<uint32_t>(g.hiddenDim));
        for (size_t i = 0; i < tokens.size(); ++i) {
            const std::vector<uint32_t> one{ tokens[i] };
            if (!engine.executePhi3ROMForwardStep(one, incrementalLogits, baseline,
                                                   ring, static_cast<uint32_t>(i), cpuMode)) {
                std::cerr << "[KVPARITY] the incremental pass failed at position " << i << "\n";
                return 1;
            }
        }
    }

    auto report = [&](const char* name, const std::vector<float>& a, const std::vector<float>& b) {
        if (a.size() != b.size()) {
            std::cout << "[KVPARITY] " << name << ": sizes differ, " << a.size() << " vs " << b.size() << "\n";
            return 0.0;
        }
        double worst = 0.0;
        for (size_t i = 0; i < a.size(); ++i) {
            worst = (std::max)(worst, std::fabs(static_cast<double>(a[i]) - static_cast<double>(b[i])));
        }
        const int argA = argmaxOf(a);
        const int argB = argmaxOf(b);
        std::cout << "[KVPARITY] " << name
                  << " max_abs_diff=" << worst
                  << " argmax=" << argA << " vs " << argB
                  << (argA == argB ? " (same)" : " (DIFFERENT)") << "\n";
        return worst;
    };

    std::cout << "[KVPARITY] reference top-5:";
    {
        std::vector<std::pair<float, uint32_t>> ranked;
        for (size_t i = 0; i < reference.size(); ++i) ranked.emplace_back(reference[i], (uint32_t)i);
        std::partial_sort(ranked.begin(),
                          ranked.begin() + (std::min)((size_t)5, ranked.size()),
                          ranked.end(),
                          [](const auto& a, const auto& b) { return a.first > b.first; });
        for (size_t i = 0; i < 5 && i < ranked.size(); ++i) {
            std::cout << " [" << tok.piece(ranked[i].second) << ":" << ranked[i].second << "]";
        }
        std::cout << "\n";
    }

    const double dFull = report("engine full-prefix vs oracle ", fullLogits, reference);
    const double dIncr = report("engine incremental  vs oracle ", incrementalLogits, reference);
    report("engine incremental  vs full    ", incrementalLogits, fullLogits);

    if (dIncr > 1e-2 && dFull <= 1e-2) {
        std::cerr << "[KVPARITY] the full-prefix pass reproduces the oracle and the incremental "
                     "pass does not: the cache carried between the calls is what is wrong\n";
        return 1;
    }
    if (dFull > 1e-2) {
        std::cerr << "[KVPARITY] the engine's full-prefix pass does not reproduce the oracle: "
                     "the discrepancy is in the forward pass, not in the cache\n";
        return 1;
    }
    std::cout << "[KVPARITY] all three agree\n";
    return 0;
}

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
// Packed Q2_K GEMV parity.
//
// The packed shader dequantizes as it reads, so the f32 expansion never
// happens. That is only worth anything if the shader reconstructs exactly
// the same values the CPU dequantizer does, so this compares the two on the
// model's own quantized tensors.
//
// The reference is the dot product of the dequantized weights in double
// precision, so it is not a product of the thing being tested. The CPU f32
// GEMV is measured against the same reference as a control: if the CPU path
// and the GPU path are both close to it, the two agree with each other.
//
// The previous version of the shader read the scales and the quants from
// the wrong offsets and left the minimum term out, and it produced values
// that were wrong by the size of the values themselves. This gate is what
// would have caught that.
// ---------------------------------------------------------------------------
int cmdQ2KParity(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: rom_audit q2k-parity <model.gguf> [tensor...]\n";
        return 1;
    }

    Deep2Engine engine;
    engine.vulkan = std::make_unique<deep2::VulkanDevice>();
    engine.vulkanReady = engine.vulkan->init();
    if (!engine.vulkanReady) {
        std::cerr << "[ORACLE] no Vulkan device available\n";
        return 1;
    }
    if (!engine.rom.addShard(argv[2]) || !engine.rom.finalizeIndex()) {
        std::cerr << "[ORACLE] could not index the model\n";
        return 1;
    }

    // The tensors to test. When none are named, the quantized projections
    // are the ones that matter, because they are the ones the forward pass
    // would place.
    std::vector<std::string> names;
    for (int a = 3; a < argc; ++a) names.push_back(argv[a]);
    if (names.empty()) {
        const auto& g = engine.rom.geometry();
        for (size_t layer = 0; layer < g.numLayers; ++layer) {
            const std::string prefix = "blk." + std::to_string(layer) + ".";
            names.push_back(prefix + "attn_qkv.weight");
            names.push_back(prefix + "ffn_up.weight");
            names.push_back(prefix + "ffn_down.weight");
        }
        names.push_back("output.weight");
    }

    int failures = 0;
    size_t tensorsTested = 0;
    double worstGpuError = 0.0;
    double worstCpuError = 0.0;

    for (const std::string& name : names) {
        const deep2::TensorEntry* entry = engine.rom.findTensor(name);
        if (!entry) {
            std::cerr << "[ORACLE] tensor not found: " << name << "\n";
            ++failures;
            continue;
        }
        if (entry->type != deep2::TensorType::Q2_K) {
            // Only Q2_K has a packed shader. The others are reported and
            // skipped rather than failed, so the command can be pointed at a
            // whole model.
            continue;
        }
        if (entry->dims.size() < 2) continue;

        // The matrix shape the GEMV sees is the dequantizer's shape, not
        // the raw ggml dimension order. The packed bytes are laid out in
        // the dequantized order, so testing anything else would compare
        // two consistent transpositions and pass.
        const uint64_t rows = entry->dims[entry->dims.size() - 1];
        const uint64_t cols = entry->dims[entry->dims.size() - 2];

        deep2::DequantizedTensor dq;
        if (!engine.dequantTensor(*entry, dq)) {
            std::cerr << "[ORACLE] dequant failed: " << name << "\n";
            ++failures;
            continue;
        }
        // The dequantized matrix has to have the shape the GEMV assumes.
        if (dq.rows != rows || dq.cols != cols) {
            std::cerr << "[ORACLE] shape mismatch on " << name << ": the tensor is "
                      << rows << "x" << cols << " but it dequantizes to "
                      << dq.rows << "x" << dq.cols << "\n";
            ++failures;
            continue;
        }

        // A deterministic input vector, so the comparison is reproducible.
        std::vector<float> x(static_cast<size_t>(cols));
        uint32_t state = 0x9E3779B9u ^ static_cast<uint32_t>(cols) ^ static_cast<uint32_t>(rows);
        for (size_t i = 0; i < x.size(); ++i) {
            state = state * 1664525u + 1013904223u;
            x[i] = static_cast<float>(static_cast<int32_t>(state >> 8) % 2001 - 1000) / 1024.0f;
        }

        // The reference: the same dot product in double precision.
        std::vector<double> reference(static_cast<size_t>(rows), 0.0);
        for (uint64_t r = 0; r < rows; ++r) {
            const float* w = dq.data.data() + static_cast<size_t>(r) * static_cast<size_t>(cols);
            double acc = 0.0;
            for (uint64_t c = 0; c < cols; ++c) {
                acc += static_cast<double>(w[c]) * static_cast<double>(x[c]);
            }
            reference[static_cast<size_t>(r)] = acc;
        }

        // The CPU f32 GEMV, as a control.
        std::vector<float> cpu(static_cast<size_t>(rows), 0.0f);
        if (!engine.gemvFloat(dq.data.data(), x.data(), cpu.data(),
                              static_cast<uint32_t>(rows), static_cast<uint32_t>(cols))) {
            std::cerr << "[ORACLE] the CPU GEMV failed: " << name << "\n";
            ++failures;
            continue;
        }

        // The packed GPU GEMV.
        Deep2Engine::ResidentQuantWeight packed;
        if (!engine.uploadResidentQuantWeight(*entry, packed)) {
            std::cerr << "[ORACLE] the packed upload failed: " << name << "\n";
            ++failures;
            continue;
        }
        const deep2::TensorView xView{ deep2::TensorType::F32,
                                       reinterpret_cast<const uint8_t*>(x.data()),
                                       x.size() * sizeof(float),
                                       { cols }, true };
        std::vector<float> gpu;
        if (!engine.vulkanGemvQ2KResident(packed, xView, gpu)) {
            std::cerr << "[ORACLE] the packed GEMV failed: " << name << "\n";
            engine.releaseResidentQuantWeight(packed);
            ++failures;
            continue;
        }
        engine.releaseResidentQuantWeight(packed);

        // The tolerance is scaled by the size of the answer, so it says
        // "this row is wrong by more than a thousandth of the row's own
        // magnitude" rather than "this row is wrong by a thousandth of
        // one".
        double maxRef = 0.0;
        for (double v : reference) maxRef = (std::max)(maxRef, std::fabs(v));
        const double atol = (std::max)(1e-6, 1e-4 * maxRef);
        const double rtol = 1e-4;

        double worstGpu = 0.0;
        double worstCpu = 0.0;
        uint64_t badRows = 0;
        uint64_t worstRow = 0;
        for (uint64_t r = 0; r < rows; ++r) {
            const double ref = reference[static_cast<size_t>(r)];
            const double gpuErr = std::fabs(static_cast<double>(gpu[static_cast<size_t>(r)]) - ref);
            const double cpuErr = std::fabs(static_cast<double>(cpu[static_cast<size_t>(r)]) - ref);
            if (gpuErr > worstGpu) { worstGpu = gpuErr; worstRow = r; }
            worstCpu = (std::max)(worstCpu, cpuErr);
            if (gpuErr > atol + rtol * std::fabs(ref)) ++badRows;
        }

        worstGpuError = (std::max)(worstGpuError, worstGpu);
        worstCpuError = (std::max)(worstCpuError, worstCpu);
        ++tensorsTested;

        const bool ok = badRows == 0;
        if (!ok) ++failures;
        std::cout << "[Q2K] " << (ok ? "PASS " : "FAIL ") << name
                  << " (" << rows << "x" << cols << ")"
                  << " gpu_err=" << worstGpu
                  << " cpu_err=" << worstCpu
                  << " bad_rows=" << badRows;
        if (!ok) {
            std::cout << " worst_row=" << worstRow
                      << " gpu=" << gpu[static_cast<size_t>(worstRow)]
                      << " ref=" << reference[static_cast<size_t>(worstRow)];
        }
        std::cout << "\n";
    }

    if (!tensorsTested) {
        std::cerr << "[ORACLE] no Q2_K tensors were tested\n";
        return 1;
    }

    std::cout << "[Q2K] " << tensorsTested << " tensor(s) tested, "
              << "worst gpu error " << worstGpuError
              << " against a worst CPU f32 error of " << worstCpuError << "\n";
    if (worstCpuError > 0.0) {
        std::cout << "[Q2K] the packed path is "
                  << (worstGpuError <= worstCpuError * 4.0 ? "as accurate as" : "less accurate than")
                  << " the CPU f32 path\n";
    }
    if (failures) {
        std::cerr << "[ORACLE] " << failures << " tensor(s) did not reproduce the reference\n";
        return 1;
    }
    std::cout << "[ORACLE] the packed Q2_K GEMV reproduces the reference on every row\n";
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
// Resident-weight GEMV benchmark.
//
// A GEMV over a matrix this size is memory bound, so what matters is how
// many bytes cross the bus per call. This compares three ways of running the
// same GEMV:
//
//   cpu       - the AVX2 CPU path,
//   gpu-eager - the GPU path that re-uploads the matrix on every call,
//   gpu-resident - the GPU path with the matrix already in device memory,
//                  split across the devices by output rows.
//
// The three produce the same numbers; only the cost differs. That is the
// measurement that decides whether the forward pass should move to the GPU.
// ---------------------------------------------------------------------------
int cmdGemvResident(int argc, char** argv) {
    // The default shape is the real one: phi3-mini's fused QKV projection.
    uint32_t rows = 9216, cols = 3072;
    if (argc >= 4) rows = static_cast<uint32_t>(std::atoi(argv[2]));
    if (argc >= 5) cols = static_cast<uint32_t>(std::atoi(argv[3]));

    Deep2Engine engine;
    engine.vulkan = std::make_unique<deep2::VulkanDevice>();
    engine.vulkanReady = engine.vulkan->init();
    if (!engine.vulkanReady) {
        std::cerr << "[ORACLE] no Vulkan device available\n";
        return 1;
    }

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

    const deep2::TensorView wView{ deep2::TensorType::F32,
                                   reinterpret_cast<const uint8_t*>(W.data()),
                                   W.size() * sizeof(float),
                                   { rows, cols }, true };
    const deep2::TensorView xView{ deep2::TensorType::F32,
                                   reinterpret_cast<const uint8_t*>(x.data()),
                                   x.size() * sizeof(float),
                                   { cols }, true };

    const int kIters = 8;
    std::vector<float> reference(rows, 0.0f), result(rows, 0.0f);

    // CPU reference.
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kIters; ++i) {
        if (!engine.gemvFloat(W.data(), x.data(), reference.data(), rows, cols)) {
            std::cerr << "[ORACLE] CPU GEMV failed\n";
            return 1;
        }
    }
    const double cpuMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count() / kIters;

    // GPU, re-uploading the matrix on every call.
    t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kIters; ++i) {
        if (!engine.vulkanGemvSplit(wView, xView, result)) {
            std::cerr << "[ORACLE] GPU eager GEMV failed\n";
            return 1;
        }
    }
    const double eagerMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count() / kIters;

    // The same split with the two devices run one after the other. This is
    // the reference the overlapped form is measured against.
    std::vector<float> sequential(rows, 0.0f);
    const auto* g0 = engine.vulkan->primary();
    const auto* g1 = engine.vulkan->secondary();
    double sequentialMs = 0.0;
    size_t splitMismatches = 0;
    if (g0 && g1) {
        t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < kIters; ++i) {
            if (!engine.vulkanGemvSplitSequential(*g0, *g1, wView, xView, sequential)) {
                std::cerr << "[ORACLE] sequential split GEMV failed\n";
                return 1;
            }
        }
        sequentialMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count() / kIters;

        // The two forms have to agree exactly: running the devices together
        // must not change the arithmetic.
        for (uint32_t r = 0; r < rows; ++r) {
            if (sequential[r] != result[r]) ++splitMismatches;
        }
    }

    // GPU, with the matrix resident in device memory.
    Deep2Engine::ResidentSplitWeight resident;
    t0 = std::chrono::steady_clock::now();
    const bool residentOk = engine.uploadResidentSplitWeight(wView, resident);
    const double uploadMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    if (!residentOk) {
        std::cerr << "[ORACLE] resident upload failed\n";
        return 1;
    }
    t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kIters; ++i) {
        if (!engine.vulkanGemvResident(resident, xView, result)) {
            std::cerr << "[ORACLE] resident GEMV failed\n";
            return 1;
        }
    }
    const double residentMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count() / kIters;

    // The resident path must still reproduce the CPU result exactly.
    size_t mismatches = 0;
    for (uint32_t r = 0; r < rows; ++r) {
        if (std::fabs(result[r] - reference[r]) > 1e-3f) ++mismatches;
    }

    const double matrixMb = (static_cast<double>(rows) * cols * sizeof(float)) / (1024.0 * 1024.0);
    std::cout << "[ORACLE] GEMV " << rows << "x" << cols
              << " f32 (" << matrixMb << " MB), " << kIters << " iterations\n";
    std::cout << "[ORACLE]   cpu          : " << cpuMs << " ms/call\n";
    std::cout << "[ORACLE]   gpu-eager    : " << eagerMs << " ms/call (matrix re-uploaded every call)\n";
    if (g0 && g1) {
        std::cout << "[ORACLE]   gpu-split-seq: " << sequentialMs
                  << " ms/call (both devices in series)\n";
        std::cout << "[ORACLE]   gpu-split-par: " << eagerMs
                  << " ms/call (both devices in flight together)\n";
        if (sequentialMs > 0.0) {
            std::cout << "[ORACLE]   overlap speedup: " << (sequentialMs / eagerMs) << "x\n";
        }
        std::cout << "[ORACLE]   sequential vs overlapped split: " << splitMismatches
                  << " mismatched rows of " << rows << "\n";
    }
    std::cout << "[ORACLE]   gpu-resident : " << residentMs << " ms/call (matrix already on the devices)\n";
    std::cout << "[ORACLE]   one-time resident upload: " << uploadMs << " ms\n";
    std::cout << "[ORACLE]   split row: " << resident.splitRow << " of " << resident.totalRows
              << " across " << resident.parts.size() << " device(s)\n";
    std::cout << "[ORACLE]   resident vs cpu: " << mismatches << " mismatched rows of " << rows << "\n";
    engine.releaseResidentSplitWeight(resident);
    if (splitMismatches) {
        std::cerr << "[ORACLE] the overlapped split did not reproduce the sequential one\n";
        return 1;
    }
    return mismatches == 0 ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Resident-weight parity against a real ROM tensor.
//
// The synthetic benchmark proves the resident path against a matrix built in
// memory. This repeats the comparison with a tensor dequantized from the
// model, which is what the forward pass actually uses, so a layout or
// dequantization mismatch shows up here rather than as a wrong logits value
// thirty layers downstream.
// ---------------------------------------------------------------------------
int cmdResidentParity(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: rom_audit resident-parity <model.gguf> <tensor> [tensor...]\n";
        return 1;
    }

    Deep2Engine engine;
    engine.vulkan = std::make_unique<deep2::VulkanDevice>();
    engine.vulkanReady = engine.vulkan->init();
    if (!engine.vulkanReady) {
        std::cerr << "[ORACLE] no Vulkan device available\n";
        return 1;
    }
    if (!engine.rom.addShard(argv[2]) || !engine.rom.finalizeIndex()) {
        std::cerr << "[ORACLE] could not index the model\n";
        return 1;
    }

    int failures = 0;
    for (int a = 3; a < argc; ++a) {
        const std::string name = argv[a];
        const deep2::TensorEntry* entry = engine.rom.findTensor(name);
        if (!entry) {
            std::cerr << "[ORACLE] tensor not found: " << name << "\n";
            ++failures;
            continue;
        }
        deep2::DequantizedTensor dq;
        if (!engine.dequantTensor(*entry, dq)) {
            std::cerr << "[ORACLE] dequant failed: " << name << "\n";
            ++failures;
            continue;
        }
        const uint32_t rows = static_cast<uint32_t>(dq.rows);
        const uint32_t cols = static_cast<uint32_t>(dq.cols);
        std::vector<float> x(cols, 1.0f);

        std::vector<float> reference(rows, 0.0f);
        if (!engine.gemvFloat(dq.data.data(), x.data(), reference.data(), rows, cols)) {
            std::cerr << "[ORACLE] CPU GEMV failed: " << name << "\n";
            ++failures;
            continue;
        }

        const deep2::TensorView wView{ deep2::TensorType::F32,
                                       reinterpret_cast<const uint8_t*>(dq.data.data()),
                                       dq.data.size() * sizeof(float),
                                       { dq.rows, dq.cols }, true };
        const deep2::TensorView xView{ deep2::TensorType::F32,
                                       reinterpret_cast<const uint8_t*>(x.data()),
                                       x.size() * sizeof(float),
                                       { cols }, true };

        Deep2Engine::ResidentSplitWeight resident;
        if (!engine.uploadResidentSplitWeight(wView, resident)) {
            std::cerr << "[ORACLE] resident upload failed: " << name << "\n";
            ++failures;
            continue;
        }
        std::vector<float> result;
        if (!engine.vulkanGemvResident(resident, xView, result)) {
            std::cerr << "[ORACLE] resident GEMV failed: " << name << "\n";
            ++failures;
            continue;
        }

        float maxDiff = 0.0f;
        size_t maxIdx = 0;
        size_t mismatches = 0;
        for (uint32_t r = 0; r < rows; ++r) {
            const float d = std::fabs(result[r] - reference[r]);
            if (d > maxDiff) { maxDiff = d; maxIdx = r; }
            if (d > 1e-3f) ++mismatches;
        }
        std::cout << "[ORACLE] " << name << " " << rows << "x" << cols
                  << " split=" << resident.splitRow
                  << " max_diff=" << maxDiff << " at row " << maxIdx
                  << " mismatched=" << mismatches << "/" << rows
                  << (mismatches == 0 ? "  PASS" : "  FAIL") << "\n";
        if (mismatches != 0) ++failures;
        engine.releaseResidentSplitWeight(resident);
    }
    return failures == 0 ? 0 : 1;
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
    if (cmd == "gemv-resident") return cmdGemvResident(argc, argv);
    if (cmd == "resident-parity") return cmdResidentParity(argc, argv);
    if (cmd == "q2k-parity")    return cmdQ2KParity(argc, argv);
    if (cmd == "llama-oracle")  return cmdLlamaOracle(argc, argv);
    if (cmd == "kv-incremental") return cmdKvIncremental(argc, argv);

    std::cerr << "unknown command: " << cmd << "\n";
    std::cerr << "usage: rom_audit <oracle|tokenize|info|dump-tensor|gemv-split|gemv-resident> "
                 "<model.gguf> [args]\n";
    return 2;
}
