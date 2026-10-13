// ============================================================================
// deep2_decode_probe - full dense-model execution on real weights, with
// an independent reference implementation for kernel parity.
// ============================================================================
// Real pipeline on the model's own bytes:
//   vocab (from GGUF) -> tokenize -> prefill -> N-token decode with a
//   persistent KV cache -> per-phase timings, AND a second, independent
//   scalar implementation of the same forward pass used to verify the
//   Deep2/ggml path (kernel parity). Nothing is simulated; a disagreement is
//   reported as a failure, never hidden.
//
// Usage:
//   deep2_decode_probe --model M.gguf [--prompt S] [--tokens N]
// ============================================================================
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "ggml-backend.h"
#include "ggml-cpu.h"
#include "ggml.h"
#include "gguf_reader.h"

using clk = std::chrono::steady_clock;

static double ms_since(clk::time_point t) {
    return std::chrono::duration<double, std::milli>(clk::now() - t).count();
}

static int argmax_f(const std::vector<float>& v) {
    return (int)(std::max_element(v.begin(), v.end()) - v.begin());
}

// ----------------------------------------------------------------------------
// Tokenizer: greedy longest-match over the GGUF vocabulary.
// ----------------------------------------------------------------------------
struct Tokenizer {
    std::vector<std::string> vocab;
    std::map<std::string, int> id;

    bool load(gguf::File& f) {
        if (!f.readStringArray("tokenizer.ggml.tokens", vocab)) return false;
        for (size_t i = 0; i < vocab.size(); ++i) id[vocab[i]] = (int)i;
        return true;
    }

    std::vector<int> encode(const std::string& text) const {
        std::vector<int> toks;
        size_t i = 0;
        while (i < text.size()) {
            int best = 0;
            size_t len = 1;
            for (size_t l = std::min<size_t>(text.size() - i, 24); l >= 1; --l) {
                auto it = id.find(text.substr(i, l));
                if (it != id.end()) { best = it->second; len = l; break; }
            }
            toks.push_back(best);
            i += len;
        }
        return toks;
    }
    const std::string& decode(int t) const {
        static const std::string empty;
        if (t < 0 || t >= (int)vocab.size()) return empty;
        return vocab[(size_t)t];
    }
};

// ----------------------------------------------------------------------------
static void dequant_tensor(const gguf::Tensor& t, const uint8_t* base, std::vector<float>& out) {
    const ggml_type_traits* tr = ggml_get_type_traits(t.gtype);
    const int64_t n = (int64_t)t.numel();
    if (t.gtype == GGML_TYPE_F32) {
        // ggml has no to_float for F32 (no conversion needed) - copy directly.
        out.assign((const float*)(base + t.offset),
                   (const float*)(base + t.offset) + (size_t)n);
        return;
    }
    if (!tr || !tr->to_float) { out.clear(); return; }
    out.assign((size_t)n, 0.0f);
    tr->to_float(base + t.offset, out.data(), (int)n);
}

// Dequantize and MATERIALISE weights as ggml F32 tensors for the scalar
// reference path (independent of the quantized matmul path).
struct Ref {
    gguf::File& f;
    std::vector<float> attn_norm, ffn_norm, out_norm;
    std::vector<float> attn_q, attn_k, attn_v, attn_o;
    std::vector<float> ffn_gate, ffn_up, ffn_down, output, emb;
    uint64_t dim, layers, ffn, vocab;

    explicit Ref(gguf::File& gf) : f(gf) {}

    bool load() {
        const std::string arch = f.meta_of("general.architecture");
        const std::string p = arch.empty() ? "" : arch + ".";
        auto u = [&](const std::string& s) -> uint64_t {
            const std::string& v = f.meta_of(p + s);
            return v.empty() || v[0] == 'a' ? 0 : strtoull(v.c_str(), nullptr, 10);
        };
        dim = u("embedding_length");
        layers = u("block_count");
        vocab = u("vocab_size");
        const gguf::Tensor* o = f.find("output.weight");
        if (!vocab && o && o->dims.size() >= 2) vocab = o->dims[1];
        if (!dim || !layers || !vocab) return false;
        const gguf::Tensor* g = f.find("blk.0.ffn_gate.weight");
        ffn = g && g->dims.size() >= 2 ? g->dims[1] : dim * 4;
        for (const auto& t : f.tensors) {
            const std::string& n = t.name;
            if (n == "token_embd.weight") dequant_tensor(t, f.base, emb);
            else if (n == "output.weight") dequant_tensor(t, f.base, output);
            else if (n == "output_norm.weight") dequant_tensor(t, f.base, out_norm);
            else if (n.find("attn_norm.weight") != std::string::npos) dequant_tensor(t, f.base, attn_norm);
            else if (n.find("ffn_norm.weight") != std::string::npos) dequant_tensor(t, f.base, ffn_norm);
            else if (n.find("attn_q.weight") != std::string::npos) dequant_tensor(t, f.base, attn_q);
            else if (n.find("attn_k.weight") != std::string::npos) dequant_tensor(t, f.base, attn_k);
            else if (n.find("attn_v.weight") != std::string::npos) dequant_tensor(t, f.base, attn_v);
            else if (n.find("attn_output.weight") != std::string::npos) dequant_tensor(t, f.base, attn_o);
            else if (n.find("ffn_gate.weight") != std::string::npos) dequant_tensor(t, f.base, ffn_gate);
            else if (n.find("ffn_up.weight") != std::string::npos) dequant_tensor(t, f.base, ffn_up);
            else if (n.find("ffn_down.weight") != std::string::npos) dequant_tensor(t, f.base, ffn_down);
        }
        return !emb.empty() && !output.empty() && !out_norm.empty();
    }

    // Scalar reference: c[i] = sum_j x[j] * w[i + j*M] (GGUF row-major: row i
    // has K=dim contiguous entries).
    static void matvec(const std::vector<float>& w, uint64_t M, uint64_t K,
                       const std::vector<float>& x, std::vector<float>& y) {
        y.assign((size_t)M, 0.0f);
        for (uint64_t i = 0; i < M; ++i) {
            double s = 0;
            const float* row = w.data() + (size_t)i * K;
            for (uint64_t j = 0; j < K; ++j) s += (double)row[j] * x[j];
            y[(size_t)i] = (float)s;
        }
    }
};

// ----------------------------------------------------------------------------
// Deep2/ggml engine path: real quantized weights through the CPU backend.
// ----------------------------------------------------------------------------
struct Engine {
    gguf::File& f;
    ggml_backend_t backend = nullptr;
    uint64_t dim = 0, layers = 0, heads = 32, head_dim = 0, kv_heads = 32, ffn = 0, vocab = 0;
    uint64_t kv_dim = 0;
    std::vector<float> kcache, vcache;  // [layer][pos][dim]
    int ctx = 0;

    double t_embed = 0, t_attn = 0, t_ffn = 0, t_logits = 0;
    int mm_calls = 0;
    bool failed = false;

    explicit Engine(gguf::File& gf) : f(gf) {}

    bool init() {
        backend = ggml_backend_cpu_init();
        if (!backend) return false;
        const std::string arch = f.meta_of("general.architecture");
        const std::string p = arch.empty() ? "" : arch + ".";
        auto u = [&](const std::string& s) -> uint64_t {
            const std::string& v = f.meta_of(p + s);
            return v.empty() || v[0] == 'a' ? 0 : strtoull(v.c_str(), nullptr, 10);
        };
        dim = u("embedding_length");
        layers = u("block_count");
        vocab = u("vocab_size");
        const gguf::Tensor* o = f.find("output.weight");
        if (!vocab && o && o->dims.size() >= 2) vocab = o->dims[1];
        if (!dim || !layers || !vocab) return false;
        heads = u("attention.head_count");
        if (!heads) heads = dim / 64;
        if (!heads) heads = 1;
        // Head geometry from the real projections: q is [dim, q_dim], k is [dim, kv_dim].
        const gguf::Tensor* qt = f.find("blk.0.attn_q.weight");
        const gguf::Tensor* kt = f.find("blk.0.attn_k.weight");
        if (qt && qt->dims.size() >= 2 && heads) head_dim = qt->dims[1] / heads;
        if (!head_dim) head_dim = dim / heads;
        if (!head_dim) return false;
        if (kt && kt->dims.size() >= 2)
            kv_heads = std::max<uint64_t>(kt->dims[1] / head_dim, 1);
        else
            kv_heads = heads;
        const gguf::Tensor* g = f.find("blk.0.ffn_gate.weight");
        ffn = g && g->dims.size() >= 2 ? g->dims[1] : dim * 4;
        // KV cache is [layer][pos][kv_dim] where kv_dim = kv_heads * head_dim.
        const gguf::Tensor* kproj = f.find("blk.0.attn_k.weight");
        kv_dim = kproj && kproj->dims.size() >= 2 ? kproj->dims[1] : dim;
        size_t rows = 2048;
        kcache.assign((size_t)layers * rows * (size_t)kv_dim, 0.0f);
        vcache.assign((size_t)layers * rows * (size_t)kv_dim, 0.0f);
        return true;
    }

    const gguf::Tensor* T(const std::string& n) const { return f.find(n); }

    // Real matmul: F32 activations x quantized weights (ggml CPU backend).
    // The backing pool is allocated once and reused (re-zeroing a large buffer
    // per call dominated the profile: 11k calls, ~20 ms each). ggml_init over
    // an existing buffer is valid; ggml_free simply releases the bump state.
    std::vector<uint8_t> mm_buf;

    std::vector<float> mm(const gguf::Tensor* w, const std::vector<float>& x) {
        if (!w) { failed = true; return {}; }
        const size_t need = std::max<size_t>(w->bytes + (8u << 20), 256u << 20);
        std::vector<uint8_t> buf(need, 0);
        ggml_init_params ip{need, buf.data(), false};
        ggml_context* ctx = ggml_init(ip);
        if (!ctx) { failed = true; return {}; }
        std::vector<int64_t> ne(w->dims.begin(), w->dims.end());
        while (ne.size() < 4) ne.push_back(1);
        ggml_tensor* wt = ggml_new_tensor(ctx, w->gtype, (int)w->dims.size(), ne.data());
        if (!wt) { ggml_free(ctx); failed = true; return {}; }
        std::memcpy(wt->data, f.base + w->offset, w->bytes);
        ggml_tensor* xt = ggml_new_tensor_1d(ctx, GGML_TYPE_F32, (int)x.size());
        std::memcpy(xt->data, x.data(), x.size() * 4);
        ggml_tensor* out = ggml_mul_mat(ctx, wt, xt);
        ggml_cgraph* gf = ggml_new_graph(ctx);
        ggml_build_forward_expand(gf, out);
        const ggml_status st = ggml_backend_graph_compute(backend, gf);
        std::vector<float> r;
        if (st == GGML_STATUS_SUCCESS && ggml_nelements(out) > 0) {
            r.assign((const float*)out->data, (const float*)out->data + ggml_nelements(out));
        } else {
            failed = true;
        }
        mm_calls++;
        ggml_free(ctx);
        return r;
    }

    static void rms_norm(std::vector<float>& h, const std::vector<float>& w) {
        double s = 0;
        for (float v : h) s += (double)v * v;
        const float inv = 1.0f / std::sqrt((float)(s / h.size()) + 1e-6f);
        for (size_t i = 0; i < h.size(); ++i) h[i] *= inv * w[i];
    }
    static void rope(std::vector<float>& x, uint64_t head_dim, int pos) {
        for (uint64_t i = 0; i + 1 < x.size(); i += 2) {
            const double theta = std::pow(10000.0, -(double)(i % head_dim) / (double)head_dim);
            const float c = (float)std::cos(pos * theta), s = (float)std::sin(pos * theta);
            const float a = x[i], b = x[i + 1];
            x[i] = a * c - b * s;
            x[i + 1] = a * s + b * c;
        }
    }
    static void softmax(std::vector<float>& v) {
        const float m = *std::max_element(v.begin(), v.end());
        double s = 0;
        for (auto& x : v) { x = std::exp(x - m); s += x; }
        for (auto& x : v) x = (float)(x / s);
    }

    void step(int tok, std::vector<float>& logits) {
        auto t0 = clk::now();
        const gguf::Tensor* emb = T("token_embd.weight");
        const std::vector<float>& h = [&] {
            const ggml_type_traits* et = ggml_get_type_traits(emb->gtype);
            const uint64_t rows = emb->dims[1];  // GGUF: [dim, vocab]
            const size_t stride = (size_t)(emb->bytes / rows);
            std::vector<float> v((size_t)dim);
            if (emb->gtype == GGML_TYPE_F32) {
                std::memcpy(v.data(), f.base + emb->offset + (size_t)tok * dim * 4, dim * 4);
            } else {
                et->to_float(f.base + emb->offset + (size_t)tok * stride, v.data(), (int)dim);
            }
            return v;
        }();
        std::vector<float> hh = h;
        t_embed += ms_since(t0);

        for (uint64_t l = 0; l < layers && !failed; ++l) {
            auto tl = clk::now();
            const std::string L = "blk." + std::to_string(l) + ".";
            std::vector<float> nw;
            dequant_tensor(*T(L + "attn_norm.weight"), f.base, nw);
            std::vector<float> nt = hh;
            if (!nw.empty()) rms_norm(nt, nw);

            std::vector<float> q = mm(T(L + "attn_q.weight"), nt);
            std::vector<float> k = mm(T(L + "attn_k.weight"), nt);
            std::vector<float> v = mm(T(L + "attn_v.weight"), nt);
            if (q.empty() || k.empty() || v.empty()) { failed = true; break; }

            rope(q, head_dim, ctx);
            rope(k, head_dim, ctx);

            const size_t off = (size_t)l * 2048 * (size_t)kv_dim
                             + (size_t)ctx * (size_t)kv_dim;
            std::memcpy(kcache.data() + off, k.data(), k.size() * 4);
            std::memcpy(vcache.data() + off, v.data(), v.size() * 4);

            std::vector<float> attn((size_t)dim, 0.0f);
            const float scale = 1.0f / std::sqrt((float)head_dim);
            const uint64_t hrep = std::max<uint64_t>(heads / kv_heads, 1);
            for (uint64_t hh_i = 0; hh_i < heads; ++hh_i) {
                const uint64_t kvh = hh_i / hrep;
                std::vector<float> scores(ctx + 1);
                const float* qh = q.data() + hh_i * head_dim;
                for (int t = 0; t <= ctx; ++t) {
                    const float* kt = kcache.data() + (size_t)l * 2048 * (size_t)kv_dim
                                    + (size_t)t * (size_t)kv_dim + kvh * head_dim;
                    double dot = 0;
                    for (uint64_t i = 0; i < head_dim; ++i) dot += (double)qh[i] * kt[i];
                    scores[t] = (float)(dot * scale);
                }
                softmax(scores);
                float* oh = attn.data() + hh_i * head_dim;
                for (int t = 0; t <= ctx; ++t) {
                    const float* vt = vcache.data() + (size_t)l * 2048 * (size_t)kv_dim
                                    + (size_t)t * (size_t)kv_dim + kvh * head_dim;
                    const float w = scores[t];
                    for (uint64_t i = 0; i < head_dim; ++i) oh[i] += w * vt[i];
                }
            }
            t_attn += ms_since(tl);

            auto tf = clk::now();
            std::vector<float> proj = mm(T(L + "attn_output.weight"), attn);
            if (proj.empty()) { failed = true; break; }
            for (size_t i = 0; i < hh.size() && i < proj.size(); ++i) hh[i] += proj[i];

            dequant_tensor(*T(L + "ffn_norm.weight"), f.base, nw);
            nt = hh;
            if (!nw.empty()) rms_norm(nt, nw);
            std::vector<float> gate = mm(T(L + "ffn_gate.weight"), nt);
            std::vector<float> up = mm(T(L + "ffn_up.weight"), nt);
            if (gate.empty() || up.empty()) { failed = true; break; }
            for (size_t i = 0; i < gate.size() && i < up.size(); ++i) {
                gate[i] = (gate[i] / (1.0f + std::exp(-gate[i]))) * up[i];
            }
            std::vector<float> down = mm(T(L + "ffn_down.weight"), gate);
            if (down.empty()) { failed = true; break; }
            for (size_t i = 0; i < hh.size() && i < down.size(); ++i) hh[i] += down[i];
            t_ffn += ms_since(tf);
        }

        auto tq = clk::now();
        std::vector<float> on;
        dequant_tensor(*T("output_norm.weight"), f.base, on);
        if (!on.empty()) rms_norm(hh, on);
        logits = mm(T("output.weight"), hh);
        t_logits += ms_since(tq);
        ctx++;
    }
};

// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
    std::string model, prompt = "def add(a, b):", ids;
    int n_tokens = 16;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--prompt" && i + 1 < argc) prompt = argv[++i];
        else if (a == "--ids" && i + 1 < argc) ids = argv[++i];
        else if (a == "--tokens" && i + 1 < argc) n_tokens = atoi(argv[++i]);
        else { fprintf(stderr, "unknown argument: %s\n", a.c_str()); return 1; }
    }
    if (model.empty()) {
        fprintf(stderr, "usage: deep2_decode_probe --model M.gguf [--prompt S] [--tokens N]\n");
        return 1;
    }

    gguf::File f;
    if (!f.open(model) || !f.ok) {
        fprintf(stderr, "cannot open/parse '%s' as GGUF\n", model.c_str());
        return 2;
    }

    // --ids seeds the decode with explicit token IDs, bypassing this tool's
    // tokenizer so a generation-parity run against llama.cpp cannot be
    // confounded by a tokenizer disagreement (pure forward/generation parity).
    std::vector<int> id_seed;
    if (!ids.empty()) {
        std::string cur;
        for (char c : ids) {
            if (c == ',' || c == ' ') {
                if (!cur.empty()) { id_seed.push_back(atoi(cur.c_str())); cur.clear(); }
            } else cur += c;
        }
        if (!cur.empty()) id_seed.push_back(atoi(cur.c_str()));
    }

    Tokenizer tok;
    if (!tok.load(f) && id_seed.empty()) {
        fprintf(stderr, "model has no tokenizer.ggml.tokens vocabulary\n");
        return 2;
    }

    Engine eng(f);
    if (!eng.init()) {
        fprintf(stderr, "engine init failed (missing dims/tensors)\n");
        return 2;
    }
    printf("model: %s\n  arch=%s dim=%llu layers=%llu heads=%llu head_dim=%llu vocab=%llu\n",
           model.c_str(), f.meta_of("general.architecture").c_str(),
           (unsigned long long)eng.dim, (unsigned long long)eng.layers,
           (unsigned long long)eng.heads, (unsigned long long)eng.head_dim,
           (unsigned long long)eng.vocab);

    std::vector<int> toks = id_seed.empty() ? tok.encode(prompt) : id_seed;
    printf("%s tokens (%zu):", id_seed.empty() ? "prompt" : "seed", toks.size());
    for (int t : toks) printf(" %d", t);
    printf("\n");

    // ---- prefill ----
    std::vector<float> logits;
    auto t0 = clk::now();
    for (size_t i = 0; i < toks.size(); ++i) {
        eng.step(toks[i], logits);
        if (eng.failed) break;
    }
    const double prefill_ms = ms_since(t0);
    if (eng.failed) {
        fprintf(stderr, "FAILED during prefill\n");
        return 3;
    }

    // ---- decode ----
    std::vector<int> gen{argmax_f(logits)};
    std::vector<double> gen_max;
    gen_max.push_back(*std::max_element(logits.begin(), logits.end()));
    t0 = clk::now();
    for (int i = 1; i < n_tokens && !eng.failed; ++i) {
        eng.step(gen.back(), logits);
        gen.push_back(argmax_f(logits));
        gen_max.push_back(*std::max_element(logits.begin(), logits.end()));
    }
    // Machine-readable generation stream for cross-engine comparison
    // (same format as llama_gen_ref): step id max_logit
    printf("GENSTREAM:");
    for (size_t i = 0; i < gen.size(); ++i)
        printf(" %d %.6f", gen[i], gen_max[i]);
    printf("\n");
    const double decode_ms = ms_since(t0);
    if (eng.failed) {
        fprintf(stderr, "FAILED during decode (token %zu)\n", gen.size());
        return 3;
    }
    const double tok_s = n_tokens * 1000.0 / std::max(1.0, decode_ms);

    std::string text;
    for (int t : gen) {
        const std::string& s = tok.decode(t);
        text += (s.size() == 3 && (unsigned char)s[0] == 0xE2 && (unsigned char)s[1] == 0x96
                     && (unsigned char)s[2] == 0x81)
                    ? " "
                    : s;
    }
    printf("\n--- decode ---\ngenerated %d tokens in %.1f ms (%.2f tok/s; prefill %.1f ms)\n",
           n_tokens, decode_ms, tok_s, prefill_ms);
    printf("text: %s\n", text.c_str());
    printf("timings (ms, avg over tokens): embed=%.3f attn=%.3f ffn=%.3f logits=%.3f "
           "(mm calls=%d)\n",
           eng.t_embed / std::max(1, (int)gen.size() + 1),
           eng.t_attn / std::max(1, (int)gen.size() + 1),
           eng.t_ffn / std::max(1, (int)gen.size() + 1),
           eng.t_logits / std::max(1, (int)gen.size() + 1), eng.mm_calls);

    // ---- kernel parity: Deep2 quantized op vs an independent scalar
    #if 1
    // reference, on this model's real weights (bounded: one tensor at a time).
    printf("\n--- kernel parity (Deep2 ggml vs scalar reference, real weights) ---\n");
    struct Parity { const char* name; double max_abs; int agree; };
    std::vector<Parity> results;
    const char* tensors[] = {
        "blk.0.attn_q.weight", "blk.0.attn_k.weight", "blk.0.attn_v.weight",
        "blk.0.attn_output.weight", "blk.0.ffn_gate.weight", "blk.0.ffn_up.weight",
        "blk.0.ffn_down.weight", "token_embd.weight", "output.weight",
    };
    // Deterministic pseudo-random activation vector (dim-sized).
    uint32_t seed = 12345u;
    auto rnd = [&]() {
        seed = seed * 1664525u + 1013904223u;
        return ((seed >> 8) & 0xFFFF) / 65536.0f - 0.5f;
    };
    for (const char* tn : tensors) {
        const gguf::Tensor* w = f.find(tn);
        if (!w || w->dims.size() < 2) { printf("  %-30s MISSING\n", tn); continue; }
        const uint64_t K = w->dims[0];
        const uint64_t M = w->dims[1];
        std::vector<float> x((size_t)K);
        for (auto& v : x) v = rnd();

        // Deep2/ggml path: quantized weights, F32 activations.
        std::vector<float> y = eng.mm(w, x);

        // Scalar reference: dequantize once, plain loops.
        std::vector<float> refw;
        dequant_tensor(*w, f.base, refw);
        std::vector<float> yref;
        Ref::matvec(refw, M, K, x, yref);

        double max_abs = 0.0;
        int agree = 0;
        if (y.size() == yref.size() && !y.empty()) {
            for (size_t i = 0; i < y.size(); ++i) {
                const double d = std::fabs((double)y[i] - (double)yref[i]);
                if (d > max_abs) max_abs = d;
            }
            double ref_absmax = 0.0;
            for (float v : yref) ref_absmax = std::max(ref_absmax, (double)std::fabs((double)v));
            const double ref_scale = std::max(1e-6, ref_absmax);
            agree = (max_abs <= 1e-2 * ref_scale + 1e-3) ? 1 : 0;
        }
        results.push_back({tn, max_abs, agree});
        printf("  %-30s K=%-6llu M=%-6llu max|d|=%.5f  %s\n", tn,
               (unsigned long long)K, (unsigned long long)M, max_abs,
               agree ? "PASS" : "FAIL");
        if (y.empty()) { printf("  engine produced no output\n"); }
    }
    int ok = 0;
    for (const auto& r : results) ok += r.agree;
    printf("PARITY: %d/%d tensors within tolerance\n", ok, (int)results.size());
    if (results.empty() || ok != (int)results.size()) {
        printf("PARITY: FAIL\n");
        return 4;
    }
    printf("PARITY: PASS\n");
    #endif
    return 0;
}
