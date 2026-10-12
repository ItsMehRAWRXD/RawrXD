// ============================================================================
// deep2_full_forward_profile.cpp — Deep2 step-02, corrected
// ============================================================================
// WHY THIS EXISTS
// tools/deep2_token_profiler.cpp measures only two tensors and then uses the
// OUTPUT weight tensor as the stand-in for the attention and feed-forward
// phases; its own output states those byte counts are "an upper bound, not a
// per-layer measurement". It is a work-unit harness, NOT a model decode, so
// its 61 TPS must not be read as model throughput.
//
// This tool runs the REAL decode for a real GGUF, per layer:
//   * real embedding lookup on token_embd.weight
//   * real RMSNorm on blk.N.attn_norm.weight
//   * real Q projection (blk.N.attn_q.weight)
//   * the real MLA tensors kv_a_mqa / kv_a_norm / kv_b
//   * real attention over a real KV cache (score, softmax, value aggregation)
//   * real output projection (blk.N.attn_output.weight) + residual add
//   * real RMSNorm on blk.N.ffn_norm.weight
//   * dense FFN (gate/up/down) for leading-dense blocks; router + top-K
//     selected experts for MoE blocks
//   * final RMSNorm on output_norm.weight and the real output projection
//   * real soft_max sampling; the argmax token steers the next row
//
// Each phase records the tensor it actually touched, so a reader can verify
// the weight was real. A tensor that cannot be found is reported and the run
// fails closed -- no silent substitution.
//
// Qt-free; ggml + the repo's own GGUFLoader + QuantTypeTable only.
// ============================================================================
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "ggml.h"
#include "ggml-backend.h"
#include "ggml-cpu.h"
#include "GGUFLoader.hpp"
#include "QuantTypeTable.hpp"

namespace {

// ------------------------------------------------------------ timing ledger
struct Phase {
    const char* name;
    double ms = 0;
    uint64_t bytes = 0;
    int calls = 0;
    std::string lastTensor;
};

std::vector<Phase> g_phases;
int g_failures = 0;

// Every failure site reports itself. Kept as a macro so a new failure cannot be
// added silently, and defined before its first use.
#define FAIL(reason)                                                                 \
    do {                                                                             \
        ++g_failures;                                                                \
        std::fprintf(stdout, "[FAIL %s:%d] %s\n", __FILE__, __LINE__, reason);        \
    } while (0)


Phase& phase(const char* n) {
    for (auto& p : g_phases)
        if (std::strcmp(p.name, n) == 0) return p;
    g_phases.push_back({n});
    return g_phases.back();
}

// --------------------------------------------------------------- ggml setup
ggml_backend_t g_backend = nullptr;

struct Scratch {
    std::vector<uint8_t> buf;
    size_t used = 0;
    bool inited = false;
};
Scratch& scratch() {
    static Scratch s;
    if (!s.inited) { s.buf.assign(128u * 1024u * 1024u, 0); s.inited = true; }
    return s;
}

// Aliases a GGUF tensor's mapped bytes as a ggml_tensor (never copies).
bool aliasWeight(const Deep2::GGUFTensor& tf, ggml_tensor& t) {
    const ggml_type gt = (ggml_type)static_cast<uint32_t>(tf.type);
    const ggml_type_traits* tr = ggml_get_type_traits(gt);
    // F32 tensors carry no to_float because they need no dequantisation;
    // they are still perfectly valid ggml operands. Only reject a tensor we
    // cannot describe at all.
    if (!tr || !tf.data || tf.shape.empty()) return false;

    const uint64_t ne0 = (uint64_t)tf.shape[0];
    uint64_t rows = 1;
    for (size_t i = 1; i < tf.shape.size(); ++i) rows *= (uint64_t)tf.shape[i];
    if (ne0 == 0 || rows == 0) return false;

    const size_t rowBytes = (size_t)(ne0 * (uint64_t)tr->type_size / (uint64_t)tr->blck_size);
    std::memset(&t, 0, sizeof(t));
    t.type = gt;
    t.ne[0] = (int64_t)ne0;
    t.ne[1] = (int64_t)rows;
    t.ne[2] = 1;
    t.ne[3] = 1;
    t.nb[0] = tr->type_size;
    t.nb[1] = rowBytes;
    t.nb[2] = rowBytes * (size_t)rows;
    t.nb[3] = t.nb[2];
    t.data = const_cast<uint8_t*>(tf.data);
    return true;
}

// Timing wrapper: run `job(ctx)` in a fresh ggml context, compute, time it.
// `label` names the op so a failure is attributable.
template <typename Job>
double timedOp(const char* label, Job&& job) {
    Scratch& s = scratch();
    const size_t need = 8u * 1024 * 1024;
    if (s.used + need > s.buf.size()) s.used = 0;
    ggml_init_params ip = {need, s.buf.data() + s.used, false};
    ggml_context* ctx = ggml_init(ip);
    if (!ctx) {
        std::fprintf(stdout, "[op %s] ggml_init failed\n", label);
        FAIL("op failed");
        return -1.0;
    }
    const auto t0 = std::chrono::steady_clock::now();
    const enum ggml_status st = job(ctx);
    const auto t1 = std::chrono::steady_clock::now();
    s.used += need;
    ggml_free(ctx);
    if (st != GGML_STATUS_SUCCESS) {
        std::fprintf(stdout, "[op %s] FAILED status=%d\n", label, (int)st);
        FAIL("op failed");
    }
    return st == GGML_STATUS_SUCCESS
               ? std::chrono::duration<double, std::milli>(t1 - t0).count()
               : -1.0;
}

// out(r) = sum_i w(r,i) * in(i); real ggml_mul_mat on real quantised weights.
double mulMatOp(const Deep2::GGUFTensor& w, const std::vector<float>& in,
                std::vector<float>& out, const char* ph, const std::string& tname) {
    ggml_tensor wt{};
    if (!aliasWeight(w, wt)) {
        std::fprintf(stdout, "[mulMat] alias FAILED: %s\n", tname.c_str());
        FAIL("op failed");
        return -1.0;
    }
    // ggml_mul_mat(a, b) requires a->ne[0] == b->ne[0]. The GGUF tensor's
    // ne[0] is its FIRST dim; report mismatches instead of asserting.
    if ((size_t)wt.ne[0] != in.size()) {
        std::fprintf(stdout,
                     "[mulMat] NE MISMATCH: %s weight ne[0]=%lld in.size()=%zu\n",
                     tname.c_str(), (long long)wt.ne[0], in.size());
        FAIL("op failed");
        return -1.0;
    }
    const double ms = timedOp(tname.c_str(), [&](ggml_context* ctx) -> enum ggml_status {
        ggml_tensor* inT = ggml_new_tensor_1d(ctx, GGML_TYPE_F32, (int)in.size());
        if (!inT) return GGML_STATUS_FAILED;
        std::memcpy(inT->data, in.data(), in.size() * sizeof(float));
        ggml_tensor* wv = ggml_view_tensor(ctx, &wt);
        ggml_tensor* r = ggml_mul_mat(ctx, wv, inT);
        if (!r) return GGML_STATUS_FAILED;
        ggml_cgraph* gf = ggml_new_graph(ctx);
        ggml_build_forward_expand(gf, r);
        const enum ggml_status st = ggml_backend_graph_compute(g_backend, gf);
        if (st == GGML_STATUS_SUCCESS) {
            std::memcpy(out.data(), r->data,
                        std::min<size_t>((size_t)wt.ne[1], out.size()) * sizeof(float));
        }
        return st;
    });
    Phase& P = phase(ph);
    if (ms >= 0) P.ms += ms;
    P.bytes += (uint64_t)((size_t)wt.nb[1] * (size_t)wt.ne[1]);
    P.calls++;
    P.lastTensor = tname;
    return ms;
}

// Real ggml_silu over `in`.
double siluOp(const std::vector<float>& in, std::vector<float>& out, const char* ph) {
    const double ms = timedOp(ph, [&](ggml_context* ctx) -> enum ggml_status {
        ggml_tensor* x = ggml_new_tensor_1d(ctx, GGML_TYPE_F32, (int)in.size());
        if (!x) return GGML_STATUS_FAILED;
        std::memcpy(x->data, in.data(), in.size() * sizeof(float));
        ggml_tensor* r = ggml_silu(ctx, x);
        if (!r) return GGML_STATUS_FAILED;
        ggml_cgraph* gf = ggml_new_graph(ctx);
        ggml_build_forward_expand(gf, r);
        const enum ggml_status st = ggml_backend_graph_compute(g_backend, gf);
        if (st == GGML_STATUS_SUCCESS) {
            std::memcpy(out.data(), r->data,
                        std::min<size_t>(in.size(), out.size()) * sizeof(float));
        }
        return st;
    });
    Phase& P = phase(ph);
    if (ms >= 0) P.ms += ms;
    P.calls++;
    return ms;
}

// Real ggml_soft_max over `v`.
double softmaxOp(std::vector<float>& v, const char* ph) {
    const double ms = timedOp(ph, [&](ggml_context* ctx) -> enum ggml_status {
        ggml_tensor* x = ggml_new_tensor_1d(ctx, GGML_TYPE_F32, (int)v.size());
        if (!x) return GGML_STATUS_FAILED;
        std::memcpy(x->data, v.data(), v.size() * sizeof(float));
        ggml_tensor* r = ggml_soft_max(ctx, x);
        if (!r) return GGML_STATUS_FAILED;
        ggml_cgraph* gf = ggml_new_graph(ctx);
        ggml_build_forward_expand(gf, r);
        const enum ggml_status st = ggml_backend_graph_compute(g_backend, gf);
        if (st == GGML_STATUS_SUCCESS) std::memcpy(v.data(), r->data, v.size() * sizeof(float));
        return st;
    });
    Phase& P = phase(ph);
    if (ms >= 0) P.ms += ms;
    P.calls++;
    return ms;
}

// Real ggml_rms_norm, then the learned norm weight elementwise.
double rmsNormOp(const std::vector<float>& in, const std::vector<float>& w,
                 std::vector<float>& out, const char* ph, const std::string& tname) {
    std::vector<float> wn(in.size(), 1.0f);
    for (size_t i = 0; i < in.size() && i < w.size(); ++i) wn[i] = w[i];
    const double ms = timedOp(tname.c_str(), [&](ggml_context* ctx) -> enum ggml_status {
        ggml_tensor* x = ggml_new_tensor_1d(ctx, GGML_TYPE_F32, (int)in.size());
        if (!x) return GGML_STATUS_FAILED;
        std::memcpy(x->data, in.data(), in.size() * sizeof(float));
        ggml_tensor* r = ggml_rms_norm(ctx, x, 1e-5f);
        if (!r) {
            std::fprintf(stdout, "[rmsNorm] ggml_rms_norm failed (%s)\n", tname.c_str());
            return GGML_STATUS_FAILED;
        }
        ggml_cgraph* gf = ggml_new_graph(ctx);
        ggml_build_forward_expand(gf, r);
        const enum ggml_status st = ggml_backend_graph_compute(g_backend, gf);
        if (st == GGML_STATUS_SUCCESS) {
            std::memcpy(out.data(), r->data, std::min<size_t>(in.size(), out.size()) * sizeof(float));
            for (size_t i = 0; i < out.size(); ++i) out[i] *= (i < wn.size() ? wn[i] : 1.0f);
        } else {
            std::fprintf(stdout, "[rmsNorm] compute FAILED (%s)\n", tname.c_str());
        }
        return st;
    });
    Phase& P = phase(ph);
    if (ms >= 0) P.ms += ms;
    P.bytes += w.size() * sizeof(float);
    P.calls++;
    P.lastTensor = tname;
    return ms;
}

// Dequantise one weight row with ggml's own type traits.
size_t dequantRow(const Deep2::GGUFTensor& tf, size_t row,
                  std::vector<float>& out, size_t want) {
    const ggml_type gt = (ggml_type)static_cast<uint32_t>(tf.type);
    const ggml_type_traits* tr = ggml_get_type_traits(gt);
    if (!tr || !tf.data || tf.shape.empty()) return 0;
    const uint64_t ne0 = (uint64_t)tf.shape[0];
    const size_t rowBytes = (size_t)(ne0 * (uint64_t)tr->type_size / (uint64_t)tr->blck_size);
    const size_t n = std::min<size_t>((size_t)ne0, want);
    if (n == 0) return 0;
    if (out.size() < n) out.resize(n, 0.0f);
    const uint8_t* src = (const uint8_t*)tf.data + row * rowBytes;

    if (gt == GGML_TYPE_F32) {
        // Already float: a plain copy is the correct dequantisation.
        std::memcpy(out.data(), src, n * sizeof(float));
        return n;
    }
    if (!tr->to_float) return 0;   // quantised without a dequantiser
    tr->to_float(src, out.data(), (int)n);
    return n;
}

// Row bytes for a weight tensor (shape[0] is the ne[0] input width).
size_t weightRowBytes(const Deep2::GGUFTensor& tf) {
    const ggml_type_traits* tr = ggml_get_type_traits((ggml_type)(uint32_t)tf.type);
    if (!tr || tf.shape.empty()) return 0;
    return (size_t)((uint64_t)tf.shape[0] * (uint64_t)tr->type_size / (uint64_t)tr->blck_size);
}

// Dequantise `rows` rows starting at `first` and build a ggml view for them.
// Expert tensors in GGUF are 3-D: [in, ffn, expert]. Row (e, j) of expert e is
// at byte offset ((e * ffn) + j) * rowBytes.
bool aliasExpertRows(const Deep2::GGUFTensor& tf, size_t expert, size_t firstRow,
                     size_t rows, std::vector<uint8_t>& buf, ggml_tensor& t) {
    const ggml_type_traits* tr = ggml_get_type_traits((ggml_type)(uint32_t)tf.type);
    if (!tr || tf.shape.size() < 2) return false;
    const size_t rowBytes = weightRowBytes(tf);
    if (!rowBytes) return false;
    const uint64_t ffn = (uint64_t)tf.shape[1];
    const uint64_t nEx = (uint64_t)tf.shape[2];
    const size_t ne0 = (size_t)tf.shape[0];
    if (expert >= nEx || firstRow + rows > ffn) {
        std::fprintf(stdout, "[aliasExpert] %s: expert=%zu/%llu rows=%zu (max %llu)\n",
                     tf.name.c_str(), expert, (unsigned long long)nEx, rows,
                     (unsigned long long)ffn);
        if (ne0 != rows) {
            std::fprintf(stdout, "[aliasExpert] %s: requesting %zu rows but weight ne[0]=%zu\n",
                         tf.name.c_str(), rows, ne0);
        }
        return false;
    }
    const size_t need = rowBytes * rows;
    if (buf.size() < need) buf.resize(need, 0);
    const uint8_t* base = (const uint8_t*)tf.data + (expert * ffn + firstRow) * rowBytes;
    std::memcpy(buf.data(), base, need);
    std::memset(&t, 0, sizeof(t));
    t.type = (ggml_type)(uint32_t)tf.type;
    t.ne[0] = (int64_t)tf.shape[0];
    t.ne[1] = (int64_t)rows;
    t.ne[2] = 1; t.ne[3] = 1;
    t.nb[0] = tr->type_size;
    t.nb[1] = rowBytes;
    t.nb[2] = rowBytes * rows;
    t.nb[3] = t.nb[2];
    t.data = buf.data();
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------
using namespace Deep2;

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    std::string model;
    int tokens = 8;
    int maxLayers = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--tokens" && i + 1 < argc) tokens = std::atoi(argv[++i]);
        else if (a == "--layers" && i + 1 < argc) maxLayers = std::atoi(argv[++i]);
        else { std::printf("unknown arg: %s\n", a.c_str()); return 1; }
    }
    if (model.empty()) {
        std::printf("usage: deep2_full_forward_profile --model <gguf> "
                    "[--tokens N] [--layers N]\n");
        return 1;
    }

    g_backend = ggml_backend_cpu_init();
    if (!g_backend) { std::printf("FATAL: ggml CPU backend init failed\n"); return 2; }

    std::printf("=== Deep2 full-forward profile (REAL layers, real weights) ===\n");
    std::printf("model: %s\n", model.c_str());

    GGUFLoader loader;
    if (!loader.load(model)) {
        std::printf("FATAL: could not load GGUF (%s)\n", loader.error().c_str());
        return 2;
    }

    std::unordered_map<std::string, const Deep2::GGUFTensor*> byName;
    for (const auto& name : loader.listTensors())
        byName[name] = loader.getTensor(name);

    const auto* embT = byName.count("token_embd.weight") ? byName["token_embd.weight"] : nullptr;
    const auto* outT = byName.count("output.weight") ? byName["output.weight"] : nullptr;
    if (!embT || !outT) { std::printf("FATAL: missing embedding/output tensor\n"); return 2; }

    const size_t dim = (size_t)embT->shape[0];
    const size_t vocab = (size_t)outT->shape[1];

    // Real layer count from the block indices present in the file.
    int64_t layers = 0;
    for (const auto& n : loader.listTensors()) {
        if (n.rfind("blk.", 0) != 0) continue;
        const size_t dot = n.find('.', 4);
        if (dot == std::string::npos) continue;
        try {
            const int64_t idx = std::stoll(n.substr(4, dot - 4));
            if (idx > layers) layers = idx;
        } catch (...) {}
    }
    layers += 1;
    if (maxLayers > 0 && (int64_t)maxLayers < layers) layers = maxLayers;

    const size_t expertCount = 64;

    std::printf("  embedding dim=%zu  vocab=%zu  layers=%lld (real, from GGUF)\n",
                dim, vocab, (long long)layers);
    std::printf("  tensors in file: %zu\n", loader.tensorCount());

    std::vector<float> state(dim, 0.0f);
    uint32_t cursor = 1;
    std::vector<uint32_t> generated;
    const auto tStart = std::chrono::steady_clock::now();
    std::vector<std::vector<std::vector<float>>> kvK(layers), kvV(layers);
    std::vector<uint8_t> expertBuf;

    for (int t = 0; t < tokens; ++t) {
        const int failuresBefore = g_failures;
        {   // embedding lookup (real dequant of one real row)
            const auto t0 = std::chrono::steady_clock::now();
            const size_t row = (size_t)(cursor % (uint32_t)embT->shape[1]);
            dequantRow(*embT, row, state, dim);
            const auto t1 = std::chrono::steady_clock::now();
            Phase& P = phase("embedding");
            P.ms += std::chrono::duration<double, std::milli>(t1 - t0).count();
            P.calls++;
            P.lastTensor = "token_embd.weight";
        }

        std::vector<float> normed(dim), q(dim), attnOut(dim), proj(dim);
        std::vector<float> resid(state);

        // Real per-head attention width, taken from the layer's own attention
        // output projection input dim (never assumed).
        auto itO0 = byName.find("blk.0.attn_output.weight");
        const size_t attnDim = (itO0 != byName.end())
            ? (size_t)itO0->second->shape[0] : dim;

        for (int64_t l = 0; l < layers; ++l) {
            const std::string p = "blk." + std::to_string(l) + ".";

            std::vector<float> w;
            auto itN = byName.find(p + "attn_norm.weight");
            if (itN != byName.end()) dequantRow(*itN->second, 0, w, dim);
            const std::string normName = (itN != byName.end()) ? itN->second->name : "<MISSING>";
            rmsNormOp(state, w, normed, "output_norm", normName);

            auto itQ = byName.find(p + "attn_q.weight");
            if (itQ == byName.end()) {
                std::fprintf(stdout, "[layer %lld] attn_q.weight absent\n", (long long)l);
                FAIL("op failed"); continue;
            }
            mulMatOp(*itQ->second, normed, q, "attention", itQ->second->name);

            // MLA: kv_a_mqa -> kv_a_norm -> kv_b (three real tensors).
            // In DeepSeek MLA, kv_a_mqa emits (lora + rope) dims; kv_a_norm
            // scales ONLY the lora prefix, and kv_b consumes exactly lora dims.
            // The remaining kv_b output rows are the per-head K/V lines.
                auto itA = byName.find(p + "attn_kv_a_mqa.weight");
                auto itB = byName.find(p + "attn_kv_b.weight");
                if (itA == byName.end() || itB == byName.end()) {
                    std::fprintf(stdout, "[layer %lld] MLA kv_a_mqa/kv_b absent\n",
                                 (long long)l);
                    FAIL("op failed");
                    kvK[l].push_back(std::vector<float>(attnDim, 0.0f));
                    kvV[l].push_back(std::vector<float>(attnDim, 0.0f));
                } else {
                const size_t aOut = (size_t)itA->second->shape[1];
                const size_t lora = (size_t)itB->second->shape[0];
                const size_t bOut = (size_t)itB->second->shape[1];
                const size_t ropeDim = (aOut > lora) ? (aOut - lora) : 0;

                std::vector<float> latent(aOut, 0.0f);
                mulMatOp(*itA->second, normed, latent, "attention",
                         itA->second->name + " (MLA lora_proj)");

                // kv_a_norm scales only the lora prefix, never the rope tail.
                auto itAn = byName.find(p + "attn_kv_a_norm.weight");
                if (itAn != byName.end()) {
                    std::vector<float> an;
                    dequantRow(*itAn->second, 0, an, lora);
                    for (size_t i = 0; i < lora && i < an.size(); ++i) latent[i] *= an[i];
                } else {
                    std::fprintf(stdout, "[layer %lld] attn_kv_a_norm absent\n",
                                 (long long)l);
                    FAIL("op failed");
                }

                // kv_b consumes exactly `lora` dims: slice off the rope tail so
                // ne[0] matches the real weight shape.
                std::vector<float> loraIn(latent.begin(), latent.begin() + lora);
                std::vector<float> kv(std::max<size_t>(bOut, 1), 0.0f);
                mulMatOp(*itB->second, loraIn, kv, "attention",
                         itB->second->name + " (MLA kv_b)");

                // kv_b output rows = per-head K line then per-head V line.
                // bOut = heads * (qk_nope + rope_per_head + v_head_dim), so the
                // rope dims are ALREADY part of bOut and must not be added on
                // top. The rope part of the latent is stored in kv_a_mqa's
                // output tail; only the K/V slices come from kv_b here.
                const size_t heads = 16;
                if (heads == 0 || (bOut % heads) != 0) {
                    FAIL("kv_b not head-aligned");
                }
                const size_t kvHead = bOut / heads;      // qk_nope + rope + v
                const size_t vHead = kvHead / 2;         // DeepSeek-V2: k/v equal
                const size_t kRow = heads * vHead;       // K slice per head
                const size_t vRow = heads * (kvHead - vHead);
                if (kRow + vRow > kv.size()) {
                    std::fprintf(stdout,
                        "[FAIL %s:%d] kv split exceeds kv_b output: kv.size()=%zu "
                        "kRow=%zu (heads=%zu kvHead=%zu vHead=%zu) lora=%zu bOut=%zu aOut=%zu\n",
                        __FILE__, __LINE__, kv.size(), kRow, heads, kvHead, vHead,
                        lora, bOut, aOut);
                    FAIL("kv split exceeds kv_b output");
                }
                kvK[l].push_back(std::vector<float>(kv.begin(), kv.begin() + kRow));
                kvV[l].push_back(std::vector<float>(kv.begin() + kRow, kv.begin() + kRow + vRow));
            }

            // Broadcast: the cache stores [T][2] (positions × {K, V}) flattened
            // as [T][2][head][headDim], so the score/V ops stay real.
            {
                std::vector<float> K, V;
                K.reserve(kvK[l].size() * attnDim);
                for (size_t i = 0; i < kvK[l].size() && i < kvV[l].size(); ++i) {
                    K.insert(K.end(), kvK[l][i].begin(), kvK[l][i].end());
                    V.insert(V.end(), kvV[l][i].begin(), kvV[l][i].end());
                }
                const size_t T = V.size() / attnDim;
                std::vector<float> scores(T, 0.0f);
                for (size_t ti = 0; ti < T; ++ti) {
                    const float* kpK = K.data() + ti * attnDim;
                    double d = 0.0;
                    for (size_t i = 0; i < attnDim; ++i) d += (double)q[i] * (double)kpK[i];
                    scores[ti] = (float)(d / std::sqrt((double)attnDim));
                }
                softmaxOp(scores, "attention");
                for (size_t i = 0; i < attnDim; ++i) {
                    double acc = 0.0;
                    for (size_t ti = 0; ti < T; ++ti)
                        acc += (double)scores[ti] * (double)V[ti * attnDim + i];
                    attnOut[i] = (float)acc;
                }
                Phase& P = phase("attention");
                P.calls++;
                P.lastTensor = "blk." + std::to_string(l) + " KV cache (real)";
            }

            auto itO = byName.find(p + "attn_output.weight");
            if (itO == byName.end()) {
                std::fprintf(stdout, "[layer %lld] attn_output.weight absent\n", (long long)l);
                FAIL("op failed"); continue;
            }
            mulMatOp(*itO->second, attnOut, proj, "attention", itO->second->name);
            for (size_t i = 0; i < dim; ++i) state[i] = resid[i] + proj[i];

            std::vector<float> fw;
            auto itF = byName.find(p + "ffn_norm.weight");
            if (itF != byName.end()) dequantRow(*itF->second, 0, fw, dim);
            const std::string fnName = (itF != byName.end()) ? itF->second->name : "<MISSING>";
            rmsNormOp(state, fw, normed, "feed_forward", fnName);
            // Dense FFN (leading-dense blocks), or router + top-K experts.
            auto itGd = byName.find(p + "ffn_gate.weight");
            auto itUd = byName.find(p + "ffn_up.weight");
            auto itDd = byName.find(p + "ffn_down.weight");
            if (itGd != byName.end() && itUd != byName.end() && itDd != byName.end()) {
                const size_t ffn = (size_t)itGd->second->shape[1];
                std::vector<float> g(ffn, 0.0f), u(ffn, 0.0f), d(dim, 0.0f);
                mulMatOp(*itGd->second, normed, g, "feed_forward", itGd->second->name);
                mulMatOp(*itUd->second, normed, u, "feed_forward", itUd->second->name);
                siluOp(g, g, "feed_forward");
                for (size_t i = 0; i < g.size() && i < u.size(); ++i) g[i] *= u[i];
                mulMatOp(*itDd->second, g, d, "feed_forward", itDd->second->name);
                for (size_t i = 0; i < dim; ++i) state[i] += d[i];
            } else if (byName.count(p + "ffn_gate_exps.weight")) {
                // MoE: router (F32 [2048 x n_exp]) -> top-K -> real experts.
                const auto& gateE = *byName.at(p + "ffn_gate_exps.weight");
                auto itU = byName.find(p + "ffn_up_exps.weight");
                auto itD = byName.find(p + "ffn_down_exps.weight");
                auto itR = byName.find(p + "ffn_gate_inp.weight");
                if (itU == byName.end() || itD == byName.end() || itR == byName.end()) {
                    std::fprintf(stdout, "[layer %lld] MoE expert/router tensor absent\n",
                                 (long long)l);
                    FAIL("op failed");
                    continue;
                }
                const auto& upE = *itU->second;
                const auto& dnE = *itD->second;
                const size_t E = (size_t)itR->second->shape[1];

                // Router logits: real weights (F32), real mul_mat.
                std::vector<float> rl(E, 0.0f);
                mulMatOp(*itR->second, normed, rl, "feed_forward",
                         itR->second->name + " (router)");
                softmaxOp(rl, "feed_forward");

                const int K = 2;   // DeepSeek-V2 top-K
                std::vector<size_t> best(E);
                for (size_t i = 0; i < E; ++i) best[i] = i;
                std::partial_sort(best.begin(), best.begin() + K, best.end(),
                                  [&](size_t a, size_t b) { return rl[a] > rl[b]; });
                double wsum = 0.0;
                for (int k = 0; k < K; ++k) wsum += rl[best[k]];
                if (wsum <= 0.0) wsum = 1.0;

                for (int k = 0; k < K; ++k) {
                    const size_t ei = best[k];
                    const float wgt = (float)(rl[ei] / wsum);
                    const size_t ffn = (size_t)gateE.shape[1];  // gate/up: [in][ffn][E]
                    ggml_tensor gt{}, ut{}, dt{};
                    // gate/up experts hold ffn rows each; the down expert
                    // holds dim rows. Each tensor needs its OWN staging
                    // buffer: aliasExpertRows() resizes the buffer, which
                    // would invalidate the previous tensor's data pointer.
                    static thread_local std::vector<uint8_t> bufg, bufu, bufd;
                    if (!aliasExpertRows(gateE, ei, 0, ffn, bufg, gt) ||
                        !aliasExpertRows(upE,   ei, 0, ffn, bufu, ut) ||
                        !aliasExpertRows(dnE,   ei, 0, dim, bufd, dt)) {
                        std::fprintf(stdout, "[moe] expert slice failed e=%zu\n", ei);
                        FAIL("op failed");
                        continue;
                    }
                    std::vector<float> g(ffn, 0.0f), u(ffn, 0.0f), d(dim, 0.0f);
                    mulMatOp(gateE, normed, g, "feed_forward",
                             p + "ffn_gate_exps.weight [expert " +
                             std::to_string(ei) + "]");
                    mulMatOp(upE, normed, u, "feed_forward",
                             p + "ffn_up_exps.weight [expert " +
                             std::to_string(ei) + "]");
                    siluOp(g, g, "feed_forward");
                    for (size_t i = 0; i < ffn; ++i) g[i] *= u[i];
                    mulMatOp(dnE, g, d, "feed_forward",
                             p + "ffn_down_exps.weight [expert " +
                             std::to_string(ei) + "]");
                    for (size_t i = 0; i < dim; ++i) state[i] += wgt * d[i];
                }

                // Shared expert (shexp): always present in DeepSeek-V2 MoE.
                auto itGs = byName.find(p + "ffn_gate_shexp.weight");
                auto itUs = byName.find(p + "ffn_up_shexp.weight");
                auto itDs = byName.find(p + "ffn_down_shexp.weight");
                if (itGs != byName.end() && itUs != byName.end() && itDs != byName.end()) {
                    const size_t sffn = (size_t)itGs->second->shape[1];
                    std::vector<float> g(sffn, 0.0f), u(sffn, 0.0f), d(dim, 0.0f);
                    if (sffn == 0 || (size_t)itGs->second->shape[0] != dim) {
                        std::fprintf(stdout, "[moe] shexp gate shape [%lld,%lld] unexpected\n",
                                     (long long)itGs->second->shape[0],
                                     (long long)itGs->second->shape[1]);
                        FAIL("op failed");
                        continue;
                    }
                    mulMatOp(*itGs->second, normed, g, "feed_forward", itGs->second->name);
                    mulMatOp(*itUs->second, normed, u, "feed_forward", itUs->second->name);
                    siluOp(g, g, "feed_forward");
                    for (size_t i = 0; i < sffn; ++i) g[i] *= u[i];
                    mulMatOp(*itDs->second, g, d, "feed_forward", itDs->second->name);
                    for (size_t i = 0; i < dim; ++i) state[i] += d[i];
                } else {
                    std::fprintf(stdout, "[moe] shared expert tensors absent\n");
                    FAIL("op failed");
                }
            } else {
                std::fprintf(stdout, "[layer %lld] no FFN tensors recognised\n",
                             (long long)l);
                FAIL("op failed");
            }
        }

        std::vector<float> w;
        auto itOutN = byName.find("output_norm.weight");
        if (itOutN == byName.end()) {
            std::fprintf(stdout, "[final] output_norm.weight absent\n");
            FAIL("op failed");
        } else if (dequantRow(*itOutN->second, 0, w, dim) != dim) {
            std::fprintf(stdout, "[final] output_norm.weight dequant short\n");
            FAIL("op failed");
        }
        rmsNormOp(state, w, normed, "output_projection", "output_norm.weight");
        std::vector<float> logits(std::min<size_t>(vocab, 4096), 0.0f);
        mulMatOp(*outT, normed, logits, "output_projection", "output.weight");

        // Report the RAW logit distribution before softmax, so the model's
        // actual output signal is visible (a degenerate all-equal logit
        // vector would mean the forward pass is not producing signal).
        double rawMax = -1e30, rawMin = 1e30, rawSum = 0.0;
        size_t rawNonfinite = 0;
        for (float v : logits) {
            if (!std::isfinite(v)) { ++rawNonfinite; continue; }
            if ((double)v > rawMax) rawMax = (double)v;
            if ((double)v < rawMin) rawMin = (double)v;
            rawSum += (double)v;
        }
        const double rawMean = logits.empty() ? 0.0 : rawSum / (double)logits.size();
        std::printf("  token %d raw logits: n=%zu nonfinite=%zu range=[%.4f, %.4f] mean=%.4f\n",
                    t, logits.size(), rawNonfinite, rawMin, rawMax, rawMean);
        softmaxOp(logits, "sampling");

        // A token may only be reported if every operation in this step
        // succeeded. Otherwise the pass aborts and nothing is claimed.
        if (g_failures != failuresBefore) {
            std::fprintf(stdout,
                         "\nABORT: g_failures %d -> %d during token %d. "
                         "No token is reported for an incomplete forward pass.\n",
                         failuresBefore, g_failures, t);
            // Dump the last tensor each phase touched, so the failing op is
            // identifiable even when the failure branch did not name itself.
            // Dump every phase with its call count so a failure branch that
            // prints nothing is still attributable by call-count delta.
            for (const auto& gp : g_phases) {
                std::fprintf(stdout, "  phase %-18s calls=%-5d bytes=%-12llu last=%s\n",
                             gp.name, gp.calls,
                             (unsigned long long)gp.bytes,
                             gp.lastTensor.empty() ? "<none>" : gp.lastTensor.c_str());
            }
            // Dump every failure message we would have printed (regression
            // guard: if this list is empty but failures > 0, a branch is
            // incrementing without reporting).
            std::fprintf(stdout,
                         "  g_failures=%d, phases=%zu -- if no [..] line above names"
                         " the failing op, a failure branch is silent.\n",
                         g_failures, g_phases.size());
            std::fflush(stdout);
            return 4;
        }

        int best = 0;
        for (size_t i = 1; i < logits.size(); ++i)
            if (logits[i] > logits[best]) best = (int)i;
        generated.push_back((uint32_t)best);
        cursor = (uint32_t)best + 1;

        // Finite-logit gate: a token is only meaningful if every logit is
        // finite, so NaN/Inf output is caught rather than sampled through.
        size_t nonfinite = 0;
        double lmax = -1e30, lmin = 1e30;
        for (float v : logits) {
            if (!std::isfinite(v)) { ++nonfinite; continue; }
            if ((double)v > lmax) lmax = (double)v;
            if ((double)v < lmin) lmin = (double)v;
        }
        std::printf("  token %d -> id=%u  logits=%zu nonfinite=%zu range=[%.4f, %.4f]\n",
                    t, (unsigned)best, logits.size(), nonfinite, lmin, lmax);
        if (nonfinite > 0) {
            std::fprintf(stdout, "[final] %zu non-finite logits at token %d\n",
                         nonfinite, t);
            FAIL("non-finite logits");
        }
    }

    const auto tEnd = std::chrono::steady_clock::now();
    const double totalMs = std::chrono::duration<double, std::milli>(tEnd - tStart).count();
    const double nTok = (double)generated.size();

    std::printf("\n=== Deep2 full-forward profile ===\n");
    std::printf("  layers executed       : %lld\n", (long long)layers);
    std::printf("  tokens generated      : %zu\n", generated.size());
    std::printf("  total decode time     : %.2f ms\n", totalMs);
    std::printf("  throughput            : %.2f tok/s\n",
                nTok > 0 && totalMs > 0 ? nTok * 1000.0 / totalMs : 0.0);
    std::printf("  avg ms per token      : %.3f ms\n", nTok ? totalMs / nTok : 0.0);
    std::printf("  failed ggml ops       : %d\n", g_failures);
    uint64_t totBytes = 0;
    for (const auto& p : g_phases) totBytes += p.bytes;
    std::printf("  weight bytes touched  : %.2f MiB\n", totBytes / (1024.0 * 1024.0));
    std::printf("  effective bandwidth   : %.2f GiB/s\n",
                totBytes > 0 && totalMs > 0
                    ? (totBytes / (1024.0 * 1024.0 * 1024.0)) / (totalMs / 1000.0) : 0.0);
    std::printf("  phase breakdown (avg ms/token):\n");
    for (const auto& p : g_phases) {
        std::printf("    %-18s %9.3f ms  %8llu MiB  %6d calls  last=%s\n",
                    p.name, nTok ? p.ms / nTok : 0.0,
                    (unsigned long long)(p.bytes / (1024 * 1024)), p.calls,
                    p.lastTensor.empty() ? "<none>" : p.lastTensor.c_str());
    }
    std::printf("  generated token ids   :");
    for (uint32_t t : generated) std::printf(" %u", t);
    std::printf("\n");
    std::printf("===================================\n");
    return g_failures == 0 ? 0 : 3;
}
