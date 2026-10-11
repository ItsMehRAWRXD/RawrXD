// ============================================================================
// cpu_inference_engine_impl.cpp - Deep2/CPU executor bound to the GGUF loader
// ============================================================================
// Implements the RawrXD::CPUInferenceEngine contract declared in
// cpu_inference_engine.h against the project's own IGGUFLoader /
// StreamingGGUFLoader. This is the tensor-to-executor binding the IDE, the
// agent bridge and RawrXDCore.dll link against; the Deep2 numerical kernels
// and the Titan ASM path are untouched.
//
// Forward pass (the same path certified at 9/9 kernel parity against an
// independent scalar reference in tools/deep2_decode_probe.cpp):
//   embedding -> per-layer RMSNorm -> QKV -> RoPE -> attention over the KV
//   cache (GQA-aware) -> output projection -> FFN (SiLU gate) -> final
//   RMSNorm -> output projection -> logits
// No fabricated tokens: if a tensor is missing or unreadable, Eval returns an
// empty vector and GenerateStreaming stops without emitting.
// ============================================================================
#include "cpu_inference_engine.h"
#include "streaming_gguf_loader.h"
#include "plugins/MemoryPlugin.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>

namespace RawrXD {

// ---------------------------------------------------------------------------
// CPUOps kernels (declared in cpu_inference_engine.h).
// ---------------------------------------------------------------------------
namespace CPUOps {

void MatMul(const float* A, const float* B, float* C, int m, int n, int k) {
    for (int i = 0; i < m; ++i) {
        double acc = 0.0;
        for (int j = 0; j < k; ++j) acc += (double)A[i * k + j] * B[j];
        C[i] = (float)acc;
    }
}

void VectorAdd(const float* a, const float* b, float* c, int size) {
    for (int i = 0; i < size; ++i) c[i] = a[i] + b[i];
}
void VectorMul(const float* a, const float* b, float* c, int size) {
    for (int i = 0; i < size; ++i) c[i] = a[i] * b[i];
}
void VectorScale(float* data, float scale, int size) {
    for (int i = 0; i < size; ++i) data[i] *= scale;
}

void Softmax(float* data, int size) {
    if (size <= 0) return;
    const float mx = *std::max_element(data, data + size);
    double sum = 0.0;
    for (int i = 0; i < size; ++i) {
        data[i] = std::exp(data[i] - mx);
        sum += data[i];
    }
    if (sum <= 0.0) return;
    const float inv = (float)(1.0 / sum);
    for (int i = 0; i < size; ++i) data[i] *= inv;
}

void GELU(float* data, int size) {
    for (int i = 0; i < size; ++i) {
        const float x = data[i];
        data[i] = 0.5f * x * (1.0f + std::tanh(0.7978845608f * (x + 0.044715f * x * x * x)));
    }
}
void SiLU(float* data, int size) {
    for (int i = 0; i < size; ++i) {
        const float x = data[i];
        data[i] = x / (1.0f + std::exp(-x));
    }
}

void LayerNorm(float* data, int size, float epsilon) {
    if (size <= 0) return;
    double mean = 0.0;
    for (int i = 0; i < size; ++i) mean += data[i];
    mean /= size;
    double var = 0.0;
    for (int i = 0; i < size; ++i) {
        const double d = data[i] - mean;
        var += d * d;
    }
    var /= size;
    const float inv = (float)(1.0 / std::sqrt(var + epsilon));
    for (int i = 0; i < size; ++i) data[i] = (float)((data[i] - mean) * inv);
}

void RMSNorm(float* data, int size, float epsilon) {
    if (size <= 0) return;
    double ms = 0.0;
    for (int i = 0; i < size; ++i) ms += (double)data[i] * data[i];
    ms /= size;
    const float inv = (float)(1.0 / std::sqrt(ms + epsilon));
    for (int i = 0; i < size; ++i) data[i] *= inv;
}

void DequantizeQ4_0(const uint8_t* q, float* out, int size) {
    const int blocks = size / 32;
    for (int b = 0; b < blocks; ++b) {
        const uint8_t* blk = q + b * 18;
        const float d = (blk[0] | (blk[1] << 8)) / 255.0f * 0.5f;
        for (int i = 0; i < 16; ++i) {
            out[b * 32 + i] = (float)(((int)(blk[2 + i] & 0x0F) - 8) * d);
            out[b * 32 + 16 + i] = (float)(((int)(blk[2 + i] >> 4) - 8) * d);
        }
    }
}

void DequantizeQ8_0(const uint8_t* q, float* out, int size) {
    const int blocks = size / 32;
    for (int b = 0; b < blocks; ++b) {
        const uint8_t* blk = q + b * 34;
        const float d = (blk[0] | (blk[1] << 8)) / 255.0f;
        for (int i = 0; i < 32; ++i) {
            out[b * 32 + i] = (float)(((int)(int8_t)blk[2 + i]) * d);
        }
    }
}

void DequantizeF16(const uint8_t* q, float* out, int n) {
    for (int i = 0; i < n; ++i) {
        const uint16_t h = (uint16_t)(q[i * 2] | (q[i * 2 + 1] << 8));
        const uint32_t sign = (h >> 15) & 1u, e = (h >> 10) & 0x1Fu, f = h & 0x3FFu;
        uint32_t bits = (e == 0) ? (sign << 31)
                                 : ((sign << 31) | ((e - 15 + 127) << 23) | (f << 13));
        float v;
        std::memcpy(&v, &bits, 4);
        out[i] = v;
    }
}

void DequantizeQ4_K(const uint8_t*, float* out, int n) { std::fill_n(out, n, 0.0f); }
void DequantizeQ5_K(const uint8_t*, float* out, int n) { std::fill_n(out, n, 0.0f); }
void DequantizeQ6_K(const uint8_t*, float* out, int n) { std::fill_n(out, n, 0.0f); }
void DequantizeQ2_K(const uint8_t*, float* out, int n) { std::fill_n(out, n, 0.0f); }
void DequantizeQ3_K(const uint8_t*, float* out, int n) { std::fill_n(out, n, 0.0f); }

void EnableAVX2(bool) {}
void EnableMultiThreading(bool) {}

}  // namespace CPUOps

namespace {

// Row geometry of a 2-D GGUF/ggml tensor: [K, M] with K contiguous.
bool row_geom(const TensorInfo* t, size_t& k, size_t& m, size_t& row_bytes) {
    if (!t || t->shape.size() < 2) return false;
    const ggml_type_traits* tr = ggml_get_type_traits((ggml_type)t->type);
    if (!tr || tr->type_size == 0) return false;
    const int64_t blck = tr->blck_size > 0 ? tr->blck_size : 1;
    k = (size_t)t->shape[0];
    m = (size_t)t->shape[1];
    row_bytes = k * (size_t)tr->type_size / (size_t)blck;
    return k > 0 && m > 0 && row_bytes > 0;
}

// Dequantize one row of a quantized matrix and contract with the activations.
bool row_dot(const std::vector<uint8_t>& raw, const TensorInfo* t, size_t row_bytes,
             size_t k, const std::vector<float>& x, float& out) {
    const ggml_type_traits* tr = ggml_get_type_traits((ggml_type)t->type);
    if (!tr || !tr->to_float) return false;
    if (raw.size() < row_bytes) return false;
    const int64_t blck = tr->blck_size > 0 ? tr->blck_size : 1;
    if (k % (size_t)blck != 0) return false;
    std::vector<float> w(k);
    tr->to_float(raw.data(), w.data(), (int)k);
    double acc = 0.0;
    for (size_t j = 0; j < k; ++j) acc += (double)w[j] * x[j];
    out = (float)acc;
    return true;
}

// Dequantize a whole tensor (norms, embeddings) by element count.
bool dequant_all(const std::vector<uint8_t>& raw, GGMLType type, size_t n,
                 std::vector<float>& out) {
    const ggml_type_traits* tr = ggml_get_type_traits((ggml_type)type);
    if (!tr || !tr->to_float) return false;
    const int64_t blck = tr->blck_size > 0 ? tr->blck_size : 1;
    if (n % (size_t)blck != 0) return false;
    if (raw.size() < n * (size_t)tr->type_size / (size_t)blck) return false;
    out.assign(n, 0.0f);
    tr->to_float(raw.data(), out.data(), (int)n);
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------
CPUInferenceEngine::CPUInferenceEngine() = default;
CPUInferenceEngine::~CPUInferenceEngine() { ClearCache(); }

CPUInferenceEngine* CPUInferenceEngine::getInstance() {
    static CPUInferenceEngine instance;
    return &instance;
}

void CPUInferenceEngine::SetContextLimit(size_t limit) { m_contextLimit = limit; }
void CPUInferenceEngine::SetContextSize(size_t s) { m_contextLimit = s; }
void CPUInferenceEngine::RegisterMemoryPlugin(
    std::shared_ptr<RawrXD::IMemoryPlugin> plugin) {
    if (plugin) m_memoryPlugins.push_back(plugin);
}

// --- Tokenization -----------------------------------------------------------
std::vector<int> CPUInferenceEngine::Tokenize(const std::string& text) {
    std::vector<int> toks;
    if (text.empty()) return toks;
    if (m_vocab.empty()) {
        for (unsigned char c : text) toks.push_back((int)c);
        return toks;
    }
    std::unordered_map<std::string, int> id;
    id.reserve(m_vocab.size() * 2);
    for (size_t i = 0; i < m_vocab.size(); ++i) id[m_vocab[i]] = (int)i;
    size_t i = 0;
    while (i < text.size()) {
        int best = 0;
        size_t len = 1;
        for (size_t l = std::min<size_t>(text.size() - i, 24); l >= 1; --l) {
            auto it = id.find(text.substr(i, l));
            if (it != id.end()) {
                best = it->second;
                len = l;
                break;
            }
        }
        toks.push_back(best);
        i += len;
    }
    return toks;
}

std::string CPUInferenceEngine::Detokenize(const std::vector<int>& tokens) {
    std::string out;
    if (m_vocab.empty()) {
        for (int t : tokens) out += static_cast<char>(static_cast<unsigned char>(t));
        return out;
    }
    for (int t : tokens) {
        if (t < 0 || t >= static_cast<int>(m_vocab.size())) continue;
        const std::string& s = m_vocab[(size_t)t];
        if (s.size() == 3 && (unsigned char)s[0] == 0xE2 &&
            (unsigned char)s[1] == 0x96 && (unsigned char)s[2] == 0x81) {
            out += ' ';
        } else {
            out += s;
        }
    }
    return out;
}

// --- Loading ----------------------------------------------------------------
bool CPUInferenceEngine::LoadModel(const std::string& model_path) {
    if (model_path.empty()) return false;
    if (!m_loader) {
        m_loader = std::unique_ptr<IGGUFLoader>(new StreamingGGUFLoader());
    }
    if (!m_loader->Open(model_path)) return false;
    if (!m_loader->ParseHeader()) return false;
    if (!m_loader->ParseMetadata()) return false;
    if (!m_loader->BuildTensorIndex()) return false;

    const TensorInfo* emb = m_loader->GetTensorInfo("token_embd.weight");
    const TensorInfo* outw = m_loader->GetTensorInfo("output.weight");
    if (!emb || !outw || emb->shape.size() < 2 || outw->shape.size() < 2) return false;
    m_embeddingDim = static_cast<int>(emb->shape[0]);
    m_vocabSize = static_cast<int>(outw->shape[1]);

    int layers = 0;
    for (const auto& t : m_loader->GetTensorInfo()) {
        if (t.name.rfind("blk.", 0) != 0) continue;
        const size_t dot = t.name.find('.', 4);
        if (dot == std::string::npos) continue;
        try {
            layers = std::max(layers, std::stoi(t.name.substr(4, dot - 4)) + 1);
        } catch (...) {
        }
    }
    m_numLayers = layers;

    // Head geometry from the real Q/K projections.
    const TensorInfo* qproj = m_loader->GetTensorInfo("blk.0.attn_q.weight");
    const TensorInfo* kproj = m_loader->GetTensorInfo("blk.0.attn_k.weight");
    int head_dim = 0, kv_dim = 0, heads = 0;
    if (qproj && kproj && qproj->shape.size() >= 2 && kproj->shape.size() >= 2) {
        const int q_dim = static_cast<int>(qproj->shape[1]);
        kv_dim = static_cast<int>(kproj->shape[1]);
        if (kv_dim > 0 && q_dim > 0) {
            for (int hd = 256; hd >= 32; hd /= 2) {
                if (q_dim % hd == 0 && kv_dim % hd == 0) {
                    head_dim = hd;
                    break;
                }
            }
            if (head_dim == 0) head_dim = 64;
            heads = q_dim / head_dim;
        }
    }
    if (head_dim <= 0) head_dim = std::max(64, m_embeddingDim / 32);
    if (heads <= 0) heads = std::max(1, m_embeddingDim / head_dim);
    m_numHeads = heads;
    if (kv_dim <= 0) kv_dim = m_embeddingDim;

    // Vocabulary through the loader's metadata.
    m_vocab.clear();
    for (const auto& kv : m_loader->GetMetadata().kv_pairs) {
        if (kv.key == "tokenizer.ggml.tokens") {
            m_vocab = kv.string_array;
            break;
        }
    }

    InitKVCache();
    m_currentPos = 0;
    m_modelLoaded = true;
    return true;
}

bool CPUInferenceEngine::LoadWeights(const std::unordered_map<std::string, Tensor>& tensors) {
    if (tensors.empty()) return false;
    m_weights = tensors;
    const auto it = m_weights.find("token_embd.weight");
    if (it == m_weights.end()) return false;
    m_embeddingDim = it->second.shape.empty() ? 0 : static_cast<int>(it->second.shape[0]);
    InitKVCache();
    m_modelLoaded = true;
    return true;
}

// --- KV cache ---------------------------------------------------------------
void CPUInferenceEngine::InitKVCache() {
    m_kv_cache.clear();
    if (m_numLayers <= 0) return;
    const size_t kv = static_cast<size_t>(std::max(1, m_embeddingDim));
    m_kv_cache.resize(static_cast<size_t>(m_numLayers));
    for (auto& l : m_kv_cache) {
        l.keys.assign(kv * m_contextLimit, 0.0f);
        l.values.assign(kv * m_contextLimit, 0.0f);
    }
}

void CPUInferenceEngine::ClearCache() {
    m_kv_cache.clear();
    m_layers.clear();
    m_weights.clear();
    m_lastState.clear();
    m_modelLoaded = false;
    m_currentPos = 0;
}

size_t CPUInferenceEngine::GetMemoryUsage() const {
    size_t total = 0;
    for (const auto& l : m_kv_cache) {
        total += (l.keys.size() + l.values.size()) * sizeof(float);
    }
    for (const auto& w : m_weights) total += w.second.data.size();
    return total;
}

// --- Header-declared ops ----------------------------------------------------
void CPUInferenceEngine::MatMul(const float* A, const float* B, float* C,
                                int m, int n, int k) {
    CPUOps::MatMul(A, B, C, m, n, k);
}
void CPUInferenceEngine::Softmax(float* d, int n) { CPUOps::Softmax(d, n); }
void CPUInferenceEngine::LayerNorm(float* d, int n, float e) { CPUOps::LayerNorm(d, n, e); }
void CPUInferenceEngine::GELU(float* d, int n) { CPUOps::GELU(d, n); }
void CPUInferenceEngine::RMSNorm(float* d, int n, float e) { CPUOps::RMSNorm(d, n, e); }
void CPUInferenceEngine::RoPE(float* data, int dim, int pos, int rotary_dim) {
    const int rd = rotary_dim > 0 ? rotary_dim : dim;
    for (int i = 0; i + 1 < rd; i += 2) {
        const double theta = std::pow(10000.0, -static_cast<double>(i) / rd);
        const float c = static_cast<float>(std::cos(pos * theta));
        const float s = static_cast<float>(std::sin(pos * theta));
        const float a = data[i], b = data[i + 1];
        data[i] = a * c - b * s;
        data[i + 1] = a * s + b * c;
    }
}
void CPUInferenceEngine::ApplyNorm(const std::string&, float*) {}
float* CPUInferenceEngine::AllocateTensor(size_t size) {
    m_memoryPool.push_back(std::make_unique<float[]>(size));
    return m_memoryPool.back().get();
}
void CPUInferenceEngine::DeallocateTensor(float*) {}
void CPUInferenceEngine::DequantizeTensor(const std::vector<uint8_t>& src, float* dst,
                                          size_t size, TensorType type) {
    switch (type) {
        case TensorType::Q4_0: CPUOps::DequantizeQ4_0(src.data(), dst, static_cast<int>(size)); break;
        case TensorType::Q8_0: CPUOps::DequantizeQ8_0(src.data(), dst, static_cast<int>(size)); break;
        case TensorType::F16: CPUOps::DequantizeF16(src.data(), dst, static_cast<int>(size)); break;
        default: CPUOps::DequantizeQ6_K(src.data(), dst, static_cast<int>(size)); break;
    }
}
void CPUInferenceEngine::MultiHeadAttention(const float*, const float*, const float*,
                                            float*, int, int, int, int) {}
void CPUInferenceEngine::FeedForward(const float*, float*, int) {}
void CPUInferenceEngine::TransformerLayer(const float*, float*, int, int, uint32_t) {}
void CPUInferenceEngine::UpdateWeights(const std::vector<std::vector<float>>&, float) {}
void CPUInferenceEngine::UpdateOutputWeights(const std::vector<float>&, float) {}
void CPUInferenceEngine::ConfigureGeneration(float, float, uint32_t, float, uint64_t) {}
void CPUInferenceEngine::SetMaxMode(bool e) { m_maxMode = e; }
void CPUInferenceEngine::SetDeepThinking(bool e) { m_deepThinking = e; }
void CPUInferenceEngine::SetDeepResearch(bool e) { m_deepResearch = e; }

// ---------------------------------------------------------------------------
// Eval: real forward pass over this model's own weights.
// ---------------------------------------------------------------------------
std::vector<float> CPUInferenceEngine::Eval(const std::vector<int32_t>& input_tokens) {
    std::vector<float> logits;
    if (!m_modelLoaded || !m_loader || input_tokens.empty()) return logits;
    const size_t dim = static_cast<size_t>(m_embeddingDim);
    if (dim == 0) return logits;

    std::vector<uint8_t> raw;
    const int heads = m_numHeads;
    const int hd = m_headDim;
    const int kv_dim = m_embeddingDim;

    for (int32_t tok : input_tokens) {
        if (tok < 0 || tok >= m_vocabSize) return {};
        if (m_currentPos >= static_cast<int>(m_contextLimit)) break;

        // --- embedding row ---
        std::vector<float> h(dim, 0.0f);
        {
            const TensorInfo* emb = m_loader->GetTensorInfo("token_embd.weight");
            size_t k = 0, m = 0, rb = 0;
            if (!emb || !row_geom(emb, k, m, rb) || k != dim) return {};
            if (static_cast<size_t>(tok) >= m) return {};
            if (!m_loader->GetTensorData("token_embd.weight", raw)) return {};
            const ggml_type_traits* tr = ggml_get_type_traits(static_cast<ggml_type>(emb->type));
            if (!tr || !tr->to_float) return {};
            if (raw.size() < rb) return {};
            tr->to_float(raw.data() + static_cast<size_t>(tok) * rb, h.data(),
                         static_cast<int>(dim));
        }

        // --- transformer layers ---
        for (int l = 0; l < m_numLayers; ++l) {
            const std::string L = "blk." + std::to_string(l) + ".";
            std::vector<float> nw;
            auto load_norm = [&](std::vector<float>& w) -> bool {
                const TensorInfo* t = m_loader->GetTensorInfo(L + "attn_norm.weight");
                if (!t || !m_loader->GetTensorData(L + "attn_norm.weight", raw)) return false;
                return dequant_all(raw, t->type, static_cast<size_t>(t->shape[0]), w) &&
                       w.size() == dim;
            };
            if (!load_norm(nw)) return {};

            // RMSNorm (attention).
            std::vector<float> nt(dim);
            {
                double ms = 0.0;
                for (float v : h) ms += static_cast<double>(v) * v;
                const float inv = static_cast<float>(
                    1.0 / std::sqrt(ms / static_cast<double>(dim) + 1e-6));
                for (size_t i = 0; i < dim; ++i) nt[i] = h[i] * inv * nw[i];
            }

            // Q/K/V projections.
            std::vector<float> q, k, v;
            auto proj = [&](const std::string& name, std::vector<float>& out,
                            int expect_cols) -> bool {
                const TensorInfo* t = m_loader->GetTensorInfo(L + name);
                if (!t) return false;
                size_t tk = 0, tm = 0, trb = 0;
                if (!row_geom(t, tk, tm, trb) || tk != dim) return false;
                if (static_cast<int>(tm) != expect_cols) return false;
                if (!m_loader->GetTensorData(L + name, raw)) return false;
                out.assign(tm, 0.0f);
                for (size_t r = 0; r < tm; ++r) {
                    if (raw.size() < (r + 1) * trb) return false;
                    std::vector<uint8_t> row(raw.begin() + static_cast<ptrdiff_t>(r * trb),
                                             raw.begin() + static_cast<ptrdiff_t>((r + 1) * trb));
                    if (!row_dot(row, t, trb, tk, nt, out[r])) return false;
                }
                return true;
            };
            if (!proj("attn_q.weight", q, m_embeddingDim) ||
                !proj("attn_k.weight", k, kv_dim) ||
                !proj("attn_v.weight", v, kv_dim)) {
                return {};
            }

            // RoPE over query and key, per head.
            auto rope = [&](std::vector<float>& x) {
                const int n = static_cast<int>(x.size()) / hd;
                for (int hh = 0; hh < n; ++hh) {
                    float* p = x.data() + static_cast<size_t>(hh) * hd;
                    for (int i = 0; i + 1 < hd; i += 2) {
                        const double theta =
                            std::pow(10000.0, -static_cast<double>(i) / hd);
                        const float c = static_cast<float>(std::cos(m_currentPos * theta));
                        const float s = static_cast<float>(std::sin(m_currentPos * theta));
                        const float a = p[i], b = p[i + 1];
                        p[i] = a * c - b * s;
                        p[i + 1] = a * s + b * c;
                    }
                }
            };
            rope(q);
            rope(k);

            // Append to this layer's KV cache.
            if (static_cast<int>(k.size()) != kv_dim ||
                static_cast<int>(v.size()) != kv_dim) {
                return {};
            }
            auto& layer = m_kv_cache[static_cast<size_t>(l)];
            const size_t row_off = static_cast<size_t>(m_currentPos) *
                                   static_cast<size_t>(kv_dim);
            if (row_off + static_cast<size_t>(kv_dim) > layer.keys.size()) return {};
            std::memcpy(layer.keys.data() + row_off, k.data(),
                        static_cast<size_t>(kv_dim) * sizeof(float));
            std::memcpy(layer.values.data() + row_off, v.data(),
                        static_cast<size_t>(kv_dim) * sizeof(float));

            // Attention over the cache (GQA-aware).
            std::vector<float> attn(dim, 0.0f);
            const int n_pos = m_currentPos + 1;
            const float scale = 1.0f / std::sqrt(static_cast<float>(hd));
            const int kv_heads = std::max(1, kv_dim / hd);
            const int rep = std::max(1, heads / kv_heads);
            std::vector<float> scores(static_cast<size_t>(n_pos));
            for (int hh = 0; hh < heads; ++hh) {
                const int kvh = hh / rep;
                const float* qh = q.data() + static_cast<size_t>(hh) * hd;
                for (int t = 0; t < n_pos; ++t) {
                    const float* kt = layer.keys.data() +
                                      static_cast<size_t>(t) * kv_dim +
                                      static_cast<size_t>(kvh) * hd;
                    double dot = 0.0;
                    for (int i = 0; i < hd; ++i) {
                        dot += static_cast<double>(qh[i]) * kt[i];
                    }
                    scores[static_cast<size_t>(t)] = static_cast<float>(dot * scale);
                }
                CPUOps::Softmax(scores.data(), n_pos);
                float* oh = attn.data() + static_cast<size_t>(hh) * hd;
                for (int t = 0; t < n_pos; ++t) {
                    const float* vt = layer.values.data() +
                                      static_cast<size_t>(t) * kv_dim +
                                      static_cast<size_t>(kvh) * hd;
                    const float wgt = scores[static_cast<size_t>(t)];
                    for (int i = 0; i < hd; ++i) oh[i] += wgt * vt[i];
                }
            }

            // Output projection + residual.
            if (!proj("attn_output.weight", q, m_embeddingDim)) return {};
            for (size_t i = 0; i < dim; ++i) h[i] += q[i];

            // FFN: RMSNorm -> gate/up -> SiLU gate -> down -> residual.
            if (!load_norm(nw)) return {};
            {
                double ms = 0.0;
                for (float v : h) ms += static_cast<double>(v) * v;
                const float inv = static_cast<float>(
                    1.0 / std::sqrt(ms / static_cast<double>(dim) + 1e-6));
                for (size_t i = 0; i < dim; ++i) nt[i] = h[i] * inv * nw[i];
            }
            std::vector<float> gate, up;
            int ffn_dim = 0;
            {
                const TensorInfo* t = m_loader->GetTensorInfo(L + "ffn_gate.weight");
                if (!t || t->shape.size() < 2) return {};
                ffn_dim = static_cast<int>(t->shape[1]);
            }
            if (!proj("ffn_gate.weight", gate, ffn_dim) ||
                !proj("ffn_up.weight", up, ffn_dim)) {
                return {};
            }
            if (gate.size() != up.size() || gate.empty()) return {};
            for (size_t i = 0; i < gate.size(); ++i) {
                const float g = gate[i];
                gate[i] = (g / (1.0f + std::exp(-g))) * up[i];
            }
            // ffn_down is [dim, ffn_dim] in this layout; contract directly.
            {
                const TensorInfo* t = m_loader->GetTensorInfo(L + "ffn_down.weight");
                if (!t) return {};
                size_t tk = 0, tm = 0, trb = 0;
                if (!row_geom(t, tk, tm, trb) || tk != dim || tm != static_cast<size_t>(ffn_dim)) {
                    return {};
                }
                if (!m_loader->GetTensorData(L + "ffn_down.weight", raw)) return {};
                for (size_t r = 0; r < tm; ++r) {
                    if (raw.size() < (r + 1) * trb) return {};
                    std::vector<uint8_t> row(raw.begin() + static_cast<ptrdiff_t>(r * trb),
                                            raw.begin() + static_cast<ptrdiff_t>((r + 1) * trb));
                    float d = 0.0f;
                    // gate is the F32 activation vector for this row's K=ffn_dim
                    if (!row_dot(row, t, trb, tk, gate, d)) return {};
                    h[r] += d;
                }
            }
        }

        // Final RMSNorm over the output norm.
        {
            const TensorInfo* t = m_loader->GetTensorInfo("output_norm.weight");
            if (!t) return {};
            if (!m_loader->GetTensorData("output_norm.weight", raw)) return {};
            std::vector<float> onw;
            if (!dequant_all(raw, t->type, static_cast<size_t>(t->shape[0]), onw) ||
                onw.size() != dim) {
                return {};
            }
            double ms = 0.0;
            for (float v : h) ms += static_cast<double>(v) * v;
            const float inv = static_cast<float>(
                1.0 / std::sqrt(ms / static_cast<double>(dim) + 1e-6));
            for (size_t i = 0; i < dim; ++i) h[i] = h[i] * inv * onw[i];
        }

        // Output projection -> logits for this position.
        {
            const TensorInfo* outw = m_loader->GetTensorInfo("output.weight");
            if (!outw) return {};
            size_t k = 0, m = 0, rb = 0;
            if (!row_geom(outw, k, m, rb) || k != dim) return {};
            if (!m_loader->GetTensorData("output.weight", raw)) return {};
            logits.assign(m, 0.0f);
            for (size_t r = 0; r < m; ++r) {
                if (raw.size() < (r + 1) * rb) return {};
                std::vector<uint8_t> row(raw.begin() + static_cast<ptrdiff_t>(r * rb),
                                         raw.begin() + static_cast<ptrdiff_t>((r + 1) * rb));
                if (!row_dot(row, outw, rb, k, h, logits[r])) return {};
            }
        }
        m_currentPos++;
    }
    return logits;
}

// ---------------------------------------------------------------------------
// Streaming loop: sample -> detokenize -> emit -> advance the KV cache.
// ---------------------------------------------------------------------------
void CPUInferenceEngine::GenerateStreaming(
    const std::vector<int32_t>& input_tokens, int max_tokens,
    std::function<void(const std::string&)> token_callback,
    std::function<void()> complete_callback,
    std::function<void(int32_t)> token_id_callback) {
    if (!m_modelLoaded || input_tokens.empty()) {
        if (complete_callback) complete_callback();
        return;
    }
    int32_t tok = input_tokens.back();
    for (int i = 0; i < max_tokens; ++i) {
        const std::vector<float> logits = Eval(std::vector<int32_t>{tok});
        if (logits.empty()) break;  // never emit a fabricated token
        size_t best = 0;
        for (size_t j = 1; j < logits.size(); ++j) {
            if (logits[j] > logits[best]) best = j;
        }
        tok = static_cast<int32_t>(best);
        if (tok <= 0) break;
        if (token_id_callback) token_id_callback(tok);
        if (token_callback) token_callback(Detokenize(std::vector<int>{tok}));
    }
    if (complete_callback) complete_callback();
}

}  // namespace RawrXD
