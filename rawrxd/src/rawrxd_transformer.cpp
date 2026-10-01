#include "rawrxd_transformer.hpp"
#include "rawrxd_cpu_math.hpp"
#include <cmath>
#include <numeric>
#include <algorithm>
#include <chrono>
#include <mutex>
#include <string>
#include <stdexcept>

namespace rawrxd {

namespace {
    // Phase clock. Every call is guarded by the profiling flag so the disabled
    // path costs one predictable branch per phase.
    struct PhaseClock {
        using Time = std::chrono::steady_clock;
        bool on = false;
        std::chrono::duration<double, std::milli> acc{0.0};
        Time::time_point mark;
        void Start() { if (on) mark = Time::now(); }
        double Stop() {
            if (!on) return 0.0;
            const auto d = std::chrono::duration<double, std::milli>(Time::now() - mark);
            return d.count();
        }
    };

    float Sqrt(float x) { return std::sqrt(x); }
    float Exp(float x) { return std::exp(x); }

    void RmsNorm(std::vector<float>& out, const std::vector<float>& x,
                 const std::vector<float>& weight, float eps) {
        out.resize(x.size());
        if (weight.size() != x.size()) {
            // Norm weights must match the hidden size; fall back to unit scale
            // rather than reading past the end.
            for (size_t i = 0; i < x.size(); ++i) out[i] = x[i];
            return;
        }
        cpu::RmsNorm(out.data(), x.data(), weight.data(), x.size(), eps);
    }

    void Softmax(std::vector<float>& out, const std::vector<float>& x) {
        float max_val = *std::max_element(x.begin(), x.end());
        float sum = 0.0f;
        out.resize(x.size());
        for (size_t i = 0; i < x.size(); ++i) {
            out[i] = Exp(x[i] - max_val);
            sum += out[i];
        }
        if (sum > 0.0f) for (auto& v : out) v /= sum;
    }

    // In-place numerically stable softmax over the first `n` elements.
    void Softmax(float* x, size_t n) {
        cpu::Softmax(x, n);
    }

    // y[0..n) = W (n x k) applied to x[0..k), i.e. one row of a [k, n] weight
    // matrix stored row-major as w[row * k + col].
    void MatMulRow(std::vector<float>& y, const std::vector<float>& x,
                   const std::vector<float>& w, size_t k, size_t n) {
        if (n == 0 || k == 0 || x.size() < k || w.size() < n * k) {
            y.assign(n, 0.0f);
            return;
        }
        cpu::MatMulRow(y, x.data(), w.data(), k, n);
    }

    // In-place rotary embedding over head_dim/2 interleaved pairs. GGUF stores
    // RoPE with the first half holding the real part and the second half the
    // imaginary part (HuggingFace "rotate_half" convention).
    void ApplyRope(float* v, size_t head_dim, float pos,
                   const std::vector<float>& inv_freq) {
        cpu::ApplyRope(v, head_dim, pos, inv_freq.data());
    }

    void MatMul(std::vector<float>& out, const std::vector<float>& a,
                const std::vector<float>& b, size_t m, size_t k, size_t n) {
        out.assign(m * n, 0.0f);
        for (size_t i = 0; i < m; ++i) {
            for (size_t j = 0; j < n; ++j) {
                float sum = 0.0f;
                for (size_t l = 0; l < k; ++l) {
                    sum += a[i * k + l] * b[l * n + j];
                }
                out[i * n + j] = sum;
            }
        }
    }
}

class TransformerRuntime::Impl {
public:
    mutable std::mutex mutex_;
    TransformerConfig config_;
    TransformerWeights weights_;
    std::vector<KVCacheEntry> kv_cache_;
    bool loaded_ = false;
    StageTimes stage_;

    void ResetStage() { stage_ = StageTimes{}; }

    // ---- coarse-grained parallel work units -------------------------------
    //
    // Each unit writes a DISJOINT output range and only reads shared state, so
    // no reduction across workers is required. That is the property the
    // single-row GEMV fan-out lacked, and it is why these are expected to
    // scale where the fine-grained matmul path did not.

    // One MLP token: gate/up rows [b,e) of `inter`, then the gated product.
    // gate and up are computed together because they share the same input.
    struct MlpCtx {
        const float* x;          // [hidden]  shared input
        const float* w_gate;     // [inter, hidden]
        const float* w_up;       // [inter, hidden]
        const float* w_down;     // [hidden, inter]
        size_t hidden;
        size_t inter;
        float* gate;             // [inter]
        float* up;               // [inter]
        float* out;              // [hidden]  (residual target contribution)
        float* vsum;             // scratch [hidden]
    };
    static void MlpGateUpTask(void* p, size_t b, size_t e) {
        MlpCtx* c = static_cast<MlpCtx*>(p);
        for (size_t i = b; i < e; ++i) {
            c->gate[i] = cpu::Dot(c->w_gate + i * c->hidden, c->x, c->hidden);
            c->up[i]   = cpu::Dot(c->w_up   + i * c->hidden, c->x, c->hidden);
        }
    }
    static void MlpDownTask(void* p, size_t b, size_t e) {
        MlpCtx* c = static_cast<MlpCtx*>(p);
        for (size_t i = b; i < e; ++i) {
            c->vsum[i] = cpu::Dot(c->w_down + i * c->inter, c->gate, c->inter);
        }
    }

    // One attention head does the whole ctx-length QK + softmax + value sum.
    // Heads are independent, so this is a large natural unit at long context.
    struct AttnCtx {
        const std::vector<std::vector<float>>* Q;   // [n_tokens][hidden]
        const KVCacheEntry* kv;
        std::vector<std::vector<float>>* attn;   // [n_tokens][hidden]
        // Per-head scores. Each head owns the slice [h*score_stride,
        // h*score_stride + ctx). A SINGLE shared scores buffer was a data race:
        // concurrent heads overwrote each other's scores, so parallel attention
        // produced different argmax sequences than the serial path. Depth 16
        // masked it; depth 1024 exposed it as argmax_match=0.
        float* scores;
        size_t score_stride;
        float* vsum;
        size_t n_tokens;
        size_t n_heads;
        size_t head_dim;
        size_t kv_dim;
        size_t kv_group;
        int start_pos;
    };
    static void AttnHeadsTask(void* p, size_t b, size_t e) {
        AttnCtx* c = static_cast<AttnCtx*>(p);
        for (size_t h = b; h < e; ++h) {
            const size_t kvh = h / c->kv_group;
            float* sc = c->scores + h * c->score_stride;
            for (size_t t = 0; t < c->n_tokens; ++t) {
                const float* q = (*c->Q)[t].data() + h * c->head_dim;
                const size_t limit = static_cast<size_t>(c->start_pos + t) + 1;
                for (size_t pos = 0; pos < limit; ++pos) {
                    const float* k = c->kv->key_cache.data() + pos * c->kv_dim + kvh * c->head_dim;
                    sc[pos] = cpu::Dot(q, k, c->head_dim);
                }
                cpu::Softmax(sc, limit);
                float* dst = (*c->attn)[t].data() + h * c->head_dim;
                cpu::WeightedSum(dst, sc,
                                 c->kv->value_cache.data() + kvh * c->head_dim,
                                 c->kv_dim, c->head_dim, limit,
                                 c->vsum + h * c->head_dim);
            }
        }
    }

    bool AllocateKVCache() {
        // The cache is keyed by KV-head width, not full hidden size; under GQA
        // n_kv_heads < n_heads and a hidden-size stride would over-allocate and
        // mis-index.
        const size_t head_dim = config_.hidden_size / config_.num_attention_heads;
        const size_t kv_dim = config_.num_key_value_heads * head_dim;
        kv_cache_.resize(config_.num_hidden_layers);
        // Start small and grow on demand. Preallocating max_position_embeddings
        // costs 256 MiB for an 8L/h512 model even when the caller only ever
        // decodes a few tokens; that churn was enough to make allocation fail
        // under repeated use and cascade into spurious decode failures.
        const size_t initial = std::min<size_t>(config_.max_position_embeddings, 256);
        for (auto& entry : kv_cache_) {
            entry.key_cache.assign(initial * kv_dim, 0.0f);
            entry.value_cache.assign(initial * kv_dim, 0.0f);
            entry.capacity = initial;
            entry.allocated = true;
        }
        return true;
    }

    // Grow every layer's cache so that `need` rows are addressable. Geometric
    // growth keeps reallocation amortized; never exceeds max_position_embeddings
    // because Forward rejects out-of-range positions before reaching here.
    bool EnsureKVCapacity(size_t need, size_t kv_dim) {
        size_t cap = kv_cache_.empty() ? 0 : kv_cache_.front().capacity;
        if (need <= cap) return true;
        size_t want = cap ? cap : 256;
        while (want < need) want *= 2;
        const size_t limit = config_.max_position_embeddings;
        if (want > limit) want = limit;
        if (need > want) want = need;
        for (auto& e : kv_cache_) {
            e.key_cache.resize(want * kv_dim, 0.0f);
            e.value_cache.resize(want * kv_dim, 0.0f);
            e.capacity = want;
        }
        return true;
    }

    // Dequantize `name` into `out` and require an exact element count. This is
    // the only place tensors become usable floats.
    bool LoadTensor(const GGUFLoader& loader, const std::string& name,
                    std::vector<float>& out, size_t expected) {
        auto view = loader.GetTensor(name);
        if (!view) return false;
        std::vector<float> tmp;
        if (!view->ToFloat32(tmp)) return false;
        if (tmp.size() != expected) return false;
        out.swap(tmp);
        return true;
    }

    // Populate weights_ from a loaded GGUF model. Returns false when any
    // required tensor is absent or the wrong size, so a partially-loaded model
    // can never masquerade as a working one.
    bool LoadAllWeights(GGUFLoader& loader) {
        const uint32_t H = config_.hidden_size;
        const uint32_t nH = config_.num_attention_heads;
        const uint32_t nKV = config_.num_key_value_heads;
        const uint32_t L = config_.num_hidden_layers;
        const uint32_t I = config_.intermediate_size;
        const uint32_t V = config_.vocab_size;
        const uint32_t head_dim = H / nH;
        const uint32_t q_dim = nH * head_dim;
        const uint32_t kv_dim = nKV * head_dim;

        std::string arch = "llama";
        if (auto a = loader.GetStringMetadata("general.architecture"); a && !a->empty()) {
            arch = *a;
        }

        TransformerWeights w;
        if (!LoadTensor(loader, "token_embd.weight", w.token_embedding_table,
                        static_cast<size_t>(V) * H)) {
            return false;
        }

        // lm_head may be absent when it is tied to the embedding table.
        if (!LoadTensor(loader, "output.weight", w.wcls, static_cast<size_t>(V) * H)) {
            w.wcls = w.token_embedding_table;
            w.lm_head_tied = true;
        }

        if (!LoadTensor(loader, "output_norm.weight", w.rms_final_weight, H)) {
            return false;
        }

        w.layers.resize(L);
        for (uint32_t l = 0; l < L; ++l) {
            const std::string base = "blk." + std::to_string(l) + ".";
            LayerWeights& lw = w.layers[l];
            if (!LoadTensor(loader, base + "attn_norm.weight", lw.rms_att_weight, H)) return false;
            if (!LoadTensor(loader, base + "ffn_norm.weight", lw.rms_ffn_weight, H)) return false;
            if (!LoadTensor(loader, base + "attn_q.weight", lw.wq, static_cast<size_t>(q_dim) * H)) return false;
            if (!LoadTensor(loader, base + "attn_k.weight", lw.wk, static_cast<size_t>(kv_dim) * H)) return false;
            if (!LoadTensor(loader, base + "attn_v.weight", lw.wv, static_cast<size_t>(kv_dim) * H)) return false;
            if (!LoadTensor(loader, base + "attn_output.weight", lw.wo, static_cast<size_t>(q_dim) * H)) return false;
            // LLaMA-family FFN is gated: gate/up share [I, H], down is [H, I].
            if (!LoadTensor(loader, base + "ffn_gate.weight", lw.w_gate, static_cast<size_t>(I) * H)) return false;
            if (!LoadTensor(loader, base + "ffn_up.weight", lw.w_up, static_cast<size_t>(I) * H)) return false;
            if (!LoadTensor(loader, base + "ffn_down.weight", lw.w_down, static_cast<size_t>(H) * I)) return false;
        }
        (void)arch;

        weights_ = std::move(w);
        return true;
    }

    ForwardResult DoForward(const std::vector<uint32_t>& tokens, int start_pos, bool profiling) {
        PhaseClock pc;
        pc.on = profiling;
        StageTimes local;
        const auto t_begin = pc.on ? PhaseClock::Time::now() : PhaseClock::Time::time_point{};

        ForwardResult result;
        if (tokens.empty()) {
            result.error_message = "Empty token list";
            return result;
        }
        if (!loaded_ || weights_.layers.empty()) {
            result.error_message = "Weights not loaded";
            return result;
        }

        const size_t n_tokens = tokens.size();
        const size_t H = config_.hidden_size;
        const size_t I = config_.intermediate_size;
        const size_t nH = config_.num_attention_heads;
        const size_t nKV = config_.num_key_value_heads;
        const size_t head_dim = H / nH;
        const size_t kv_dim = nKV * head_dim;
        const size_t kv_group = nH / nKV;
        const size_t max_pos = config_.max_position_embeddings;

        const long long last_pos = static_cast<long long>(start_pos) +
                                   static_cast<long long>(n_tokens) - 1;
        if (start_pos < 0 || last_pos >= static_cast<long long>(max_pos)) {
            result.error_message = "Sequence exceeds max_position_embeddings";
            return result;
        }

        // RoPE inverse-frequency table, computed once per call.
        std::vector<float> inv_freq(head_dim / 2, 0.0f);
        for (size_t i = 0; i < head_dim / 2; ++i) {
            const float denom = std::pow(config_.rope_theta,
                                         static_cast<float>(2 * i) / static_cast<float>(head_dim));
            inv_freq[i] = 1.0f / denom;
        }

        // x[t] holds the residual stream for absolute position start_pos + t.
        pc.Start();
        std::vector<std::vector<float>> x(n_tokens, std::vector<float>(H, 0.0f));
        for (size_t t = 0; t < n_tokens; ++t) {
            uint32_t tok = tokens[t];
            if (tok >= config_.vocab_size) tok = 0;
            const float* src = weights_.token_embedding_table.data() +
                               static_cast<size_t>(tok) * H;
            std::memcpy(x[t].data(), src, H * sizeof(float));
        }
        local.embed_ms += pc.Stop();
        local.layers += config_.num_hidden_layers;

        // Two-regime parallel policy with a FIXED context boundary, so the
        // scheduler is not itself a variable in the experiment:
        //     ctx <= threshold -> parallelize MLP
        //     ctx >  threshold -> parallelize attention heads
        // Each is independently overridable so a policy cannot be credited
        // with the other's gain.
        const int thr = cpu::EnvCtxThreshold();
        const unsigned mlp_threads_env = static_cast<unsigned>(
            cpu::EnvThreads("RAWRXD_MLP_THREADS") < 0 ? 1 : cpu::EnvThreads("RAWRXD_MLP_THREADS"));
        const unsigned attn_threads_env = static_cast<unsigned>(
            cpu::EnvThreads("RAWRXD_ATTN_THREADS") < 0 ? 1 : cpu::EnvThreads("RAWRXD_ATTN_THREADS"));

        for (uint32_t l = 0; l < config_.num_hidden_layers; ++l) {
            const LayerWeights& lw = weights_.layers[l];

            pc.Start();
            std::vector<std::vector<float>> xb(n_tokens);
            for (size_t t = 0; t < n_tokens; ++t) {
                xb[t].resize(H);
                RmsNorm(xb[t], x[t], lw.rms_att_weight, config_.rms_norm_eps);
            }
            local.norm_ms += pc.Stop();

            // QKV projections for every token in the batch.
            pc.Start();
            std::vector<std::vector<float>> Q(n_tokens, std::vector<float>(H, 0.0f));
            std::vector<std::vector<float>> K(n_tokens, std::vector<float>(kv_dim, 0.0f));
            std::vector<std::vector<float>> Vv(n_tokens, std::vector<float>(kv_dim, 0.0f));
            for (size_t t = 0; t < n_tokens; ++t) {
                MatMulRow(Q[t], xb[t], lw.wq, H, H);
                MatMulRow(K[t], xb[t], lw.wk, H, kv_dim);
                MatMulRow(Vv[t], xb[t], lw.wv, H, kv_dim);
            }
            local.proj_qkv_ms += pc.Stop();

            // RoPE on Q and K, using absolute positions.
            pc.Start();
            if (config_.use_rope) {
                for (size_t t = 0; t < n_tokens; ++t) {
                    const float pos = static_cast<float>(start_pos + t);
                    for (size_t h = 0; h < nH; ++h) {
                        ApplyRope(Q[t].data() + h * head_dim, head_dim, pos, inv_freq);
                    }
                    for (size_t h = 0; h < nKV; ++h) {
                        ApplyRope(K[t].data() + h * head_dim, head_dim, pos, inv_freq);
                    }
                }
            }
            local.rope_ms += pc.Stop();

            // Append this chunk to the KV cache.
            pc.Start();
            auto& kv = kv_cache_[l];
            const size_t need = static_cast<size_t>(last_pos) + 1;
            if (need > kv.capacity) {
                // Growing invalidates the pointer held in `kv` and every other
                // layer's, so re-read it after the resize.
                if (!EnsureKVCapacity(need, kv_dim)) {
                    result.error_message = "KV cache growth failed";
                    return result;
                }
            }
            for (size_t t = 0; t < n_tokens; ++t) {
                const size_t pos = static_cast<size_t>(start_pos + t);
                std::memcpy(kv_cache_[l].key_cache.data() + pos * kv_dim, K[t].data(),
                            kv_dim * sizeof(float));
                std::memcpy(kv_cache_[l].value_cache.data() + pos * kv_dim, Vv[t].data(),
                            kv_dim * sizeof(float));
            }
            local.kv_write_ms += pc.Stop();

            // Causal attention over [0, last_pos].
            const size_t ctx = static_cast<size_t>(last_pos) + 1;
            std::vector<std::vector<float>> attn(n_tokens, std::vector<float>(H, 0.0f));
            // Per-head scratch so concurrent heads never share writable state.
            std::vector<float> scores_all(nH * ctx, 0.0f);
            std::vector<float> vsum_all(nH * head_dim, 0.0f);
            {
                AttnCtx ac;
                ac.Q = &Q;
                ac.kv = &kv_cache_[l];
                ac.attn = &attn;
                ac.scores = scores_all.data();
                ac.score_stride = ctx;
                ac.vsum = vsum_all.data();
                ac.n_tokens = n_tokens;
                ac.n_heads = nH;
                ac.head_dim = head_dim;
                ac.kv_dim = kv_dim;
                ac.kv_group = kv_group;
                ac.start_pos = start_pos;

                // Attention regime: parallelize whole heads. Each head owns a
                // disjoint slice of attn[] and only reads the shared KV cache,
                // so no reduction is required.
                const bool attn_regime = (static_cast<int>(ctx) > thr);
                unsigned nt = attn_regime ? attn_threads_env : 1u;
                if (nt > nH) nt = static_cast<unsigned>(nH);
                pc.Start();
                cpu::ParallelRows(&AttnHeadsTask, &ac, nH, nt);
                local.attention_fused_ms += pc.Stop();
            }
            local.heads += nH;

            // Output projection + residual.
            pc.Start();
            std::vector<float> proj(H, 0.0f);
            for (size_t t = 0; t < n_tokens; ++t) {
                MatMulRow(proj, attn[t], lw.wo, H, H);
                cpu::AddInPlace(x[t].data(), proj.data(), H);
            }
            local.out_proj_ms += pc.Stop();

            // SwiGLU FFN + residual. gate and up share the same input, so they
            // are computed back to back before the gated product.
            pc.Start();
            std::vector<float> gate(I, 0.0f), up(I, 0.0f);
            std::vector<float> ffn_in(H, 0.0f);
            std::vector<float> down_out(H, 0.0f);
            for (size_t t = 0; t < n_tokens; ++t) {
                RmsNorm(ffn_in, x[t], lw.rms_ffn_weight, config_.rms_norm_eps);
                MlpCtx mc;
                mc.x = ffn_in.data();
                mc.w_gate = lw.w_gate.data();
                mc.w_up = lw.w_up.data();
                mc.w_down = lw.w_down.data();
                mc.hidden = H; mc.inter = I;
                mc.gate = gate.data(); mc.up = up.data();
                mc.out = down_out.data(); mc.vsum = down_out.data();

                // MLP regime: parallelize gate/up rows, then down rows.
                // Units are coarse (I rows and H rows) and disjoint.
                const bool mlp_regime = (static_cast<int>(ctx) <= thr);
                unsigned nt = mlp_regime ? mlp_threads_env : 1u;
                cpu::ParallelRows(&MlpGateUpTask, &mc, I, nt);
                cpu::SiluInPlace(gate.data(), I);
                cpu::MulInPlace(gate.data(), up.data(), I);
                cpu::ParallelRows(&MlpDownTask, &mc, H, nt);
                cpu::AddInPlace(x[t].data(), down_out.data(), H);
            }
            local.mlp_ms += pc.Stop();
        }

        pc.Start();
        std::vector<float> last(H, 0.0f);
        RmsNorm(last, x[n_tokens - 1], weights_.rms_final_weight, config_.rms_norm_eps);
        result.logits.resize(config_.vocab_size);
        MatMulRow(result.logits, last, weights_.wcls, H, config_.vocab_size);
        result.hidden_states = std::move(last);
        result.success = true;
        local.lm_head_ms += pc.Stop();

        float max_logit = *std::max_element(result.logits.begin(), result.logits.end());
        float sum_exp = 0.0f;
        for (float l : result.logits) sum_exp += Exp(l - max_logit);
        if (sum_exp > 0.0f) {
            result.perplexity = -std::log(sum_exp / static_cast<float>(result.logits.size()));
        }
        if (pc.on) {
            local.total_ms = std::chrono::duration<double, std::milli>(
                PhaseClock::Time::now() - t_begin).count();
            stage_ = local;
        }
        return result;
    }
};

TransformerRuntime::TransformerRuntime() : impl_(std::make_unique<Impl>()) {}
TransformerRuntime::~TransformerRuntime() = default;

bool TransformerRuntime::LoadWeights(const std::string& gguf_path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    GGUFLoader loader;
    if (!loader.LoadFromFile(gguf_path)) return false;
    impl_->config_ = InferConfigFromGGUF(loader);
    // LoadAllWeights derives expected tensor shapes from config_, so geometry
    // must be resolved before the tensors are read.
    if (!impl_->LoadAllWeights(loader)) {
        impl_->weights_ = TransformerWeights{};
        return false;
    }
    impl_->AllocateKVCache();
    impl_->loaded_ = true;
    return true;
}

bool TransformerRuntime::LoadWeightsFromMemory(const std::vector<uint8_t>& buffer) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    GGUFLoader loader;
    if (!loader.LoadFromMemory(buffer)) return false;
    impl_->config_ = InferConfigFromGGUF(loader);
    if (!impl_->LoadAllWeights(loader)) {
        impl_->weights_ = TransformerWeights{};
        return false;
    }
    impl_->AllocateKVCache();
    impl_->loaded_ = true;
    return true;
}

void TransformerRuntime::SetConfig(const TransformerConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->config_ = config;
    impl_->AllocateKVCache();
}

const TransformerConfig& TransformerRuntime::GetConfig() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->config_;
}

bool TransformerRuntime::IsLoaded() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->loaded_;
}

ForwardResult TransformerRuntime::Forward(const std::vector<uint32_t>& tokens, int start_pos) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->DoForward(tokens, start_pos, profiling_);
}

StageTimes TransformerRuntime::StageTimesResult() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->stage_;
}

void TransformerRuntime::ResetStageTimes() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->ResetStage();
}

ForwardResult TransformerRuntime::Forward(const std::vector<uint32_t>& tokens,
                                          std::vector<KVCacheEntry>& kv_cache,
                                          int start_pos) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->kv_cache_ = kv_cache;
    auto result = impl_->DoForward(tokens, start_pos, profiling_);
    kv_cache = impl_->kv_cache_;
    return result;
}

void TransformerRuntime::ResetKVCache() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (auto& entry : impl_->kv_cache_) {
        std::fill(entry.key_cache.begin(), entry.key_cache.end(), 0.0f);
        std::fill(entry.value_cache.begin(), entry.value_cache.end(), 0.0f);
    }
}

std::vector<float> TransformerRuntime::GetEmbedding(uint32_t token_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<float> emb;
    if (!impl_->loaded_ || token_id >= impl_->config_.vocab_size) return emb;
    size_t hidden = impl_->config_.hidden_size;
    emb.resize(hidden);
    for (size_t i = 0; i < hidden; ++i) {
        emb[i] = impl_->weights_.token_embedding_table[token_id * hidden + i];
    }
    return emb;
}

namespace {
    // GGUF metadata keys are namespaced by architecture, e.g.
    // "llama.embedding_length" or "qwen3.block_count". A model may also carry
    // un-prefixed fallbacks. Try the prefixed key first, then the bare key.
    std::optional<uint32_t> LookupU32(const GGUFLoader& loader,
                                      const std::string& arch,
                                      const std::string& bare) {
        if (!arch.empty()) {
            auto v = loader.GetUint32Metadata(arch + "." + bare);
            if (v) return v;
        }
        return loader.GetUint32Metadata(bare);
    }

    std::optional<float> LookupF32(const GGUFLoader& loader,
                                   const std::string& arch,
                                   const std::string& bare) {
        if (!arch.empty()) {
            auto v = loader.GetFloat32Metadata(arch + "." + bare);
            if (v) return v;
        }
        return loader.GetFloat32Metadata(bare);
    }
}

TransformerConfig TransformerRuntime::InferConfigFromGGUF(const GGUFLoader& loader) {
    TransformerConfig config = DefaultConfig();

    // Architecture prefix, e.g. "llama". Defaults to the most common one when
    // the file omits it rather than probing every namespace blindly.
    std::string arch = "llama";
    if (auto a = loader.GetStringMetadata("general.architecture"); a && !a->empty()) {
        arch = *a;
    }

    // Namespaced keys (authoritative), then bare HF-style keys (what the
    // original code queried, which never match a real GGUF file).
    if (auto v = LookupU32(loader, arch, "embedding_length"); v) config.hidden_size = *v;
    if (auto v = LookupU32(loader, arch, "block_count"); v) config.num_hidden_layers = *v;
    if (auto v = LookupU32(loader, arch, "attention.head_count"); v) config.num_attention_heads = *v;
    if (auto v = LookupU32(loader, arch, "attention.head_count_kv"); v) config.num_key_value_heads = *v;
    if (auto v = LookupU32(loader, arch, "feed_forward_length"); v) config.intermediate_size = *v;
    if (auto v = LookupU32(loader, arch, "context_length"); v) config.max_position_embeddings = *v;
    // The vocabulary size is stored as an ARRAY under tokenizer.ggml.tokens,
    // not as a scalar, so it needs its own lookup.
    {
        if (auto mv = loader.GetMetadata("tokenizer.ggml.tokens")) {
            if (std::holds_alternative<std::vector<std::string>>(mv->value)) {
                config.vocab_size = static_cast<uint32_t>(
                    std::get<std::vector<std::string>>(mv->value).size());
            } else if (std::holds_alternative<std::vector<uint32_t>>(mv->value)) {
                config.vocab_size = static_cast<uint32_t>(
                    std::get<std::vector<uint32_t>>(mv->value).size());
            }
        }
        if (!config.vocab_size) {
            if (auto v = LookupU32(loader, "", "vocab_size"); v) config.vocab_size = *v;
        }
    }

    if (auto v = LookupF32(loader, arch, "rope.freq_base"); v) config.rope_theta = *v;
    if (auto v = LookupF32(loader, arch, "attention.layer_norm_rms_epsilon"); v) config.rms_norm_eps = *v;

    if (config.num_key_value_heads == 0) config.num_key_value_heads = config.num_attention_heads;
    config.use_gqa = (config.num_key_value_heads != config.num_attention_heads);

    // Guard against a malformed header producing nonsensical geometry.
    if (config.num_attention_heads == 0) config.num_attention_heads = 1;
    if (config.num_attention_heads > config.hidden_size) config.num_attention_heads = config.hidden_size;
    if (config.num_key_value_heads > config.num_attention_heads) {
        config.num_key_value_heads = config.num_attention_heads;
    }
    if (config.hidden_size % config.num_attention_heads != 0) {
        config.num_attention_heads = 1;
        config.num_key_value_heads = 1;
    }
    return config;
}

TransformerConfig TransformerRuntime::DefaultConfig() {
    TransformerConfig c;
    c.vocab_size = 32000;
    c.hidden_size = 4096;
    c.intermediate_size = 11008;
    c.num_hidden_layers = 32;
    c.num_attention_heads = 32;
    c.num_key_value_heads = 32;
    c.max_position_embeddings = 2048;
    c.rms_norm_eps = 1e-6f;
    c.rope_theta = 10000.0f;
    c.use_rope = true;
    c.use_gqa = false;
    return c;
}

bool TransformerRuntime::ExportWeights(const std::string& /*path*/) const {
    return false;
}

size_t TransformerRuntime::GetWeightBytes() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t total = 0;
    auto add = [&total](const std::vector<float>& v) { total += v.size() * sizeof(float); };
    add(impl_->weights_.token_embedding_table);
    add(impl_->weights_.rms_final_weight);
    if (!impl_->weights_.lm_head_tied) add(impl_->weights_.wcls);
    for (const auto& layer : impl_->weights_.layers) {
        add(layer.rms_att_weight);
        add(layer.rms_ffn_weight);
        add(layer.wq); add(layer.wk); add(layer.wv); add(layer.wo);
        add(layer.w_gate); add(layer.w_up); add(layer.w_down);
    }
    return total;
}

size_t TransformerRuntime::GetActivationBytes() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t hidden = impl_->config_.hidden_size;
    size_t layers = impl_->config_.num_hidden_layers;
    return layers * hidden * sizeof(float) * 6;
}

} // namespace rawrxd
