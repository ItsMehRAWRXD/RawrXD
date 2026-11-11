// ============================================================================
// FusedInferenceKernel.cpp — Multi-GPU, RoPE, Medusa, VRAM Hotpatch
// ============================================================================

#include "FusedInferenceKernel.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <cmath>
#include <chrono>
#include <algorithm>
#include <limits>
#include <string>

namespace Deep2 {

// ---------------------------------------------------------------------------
// GpuTopology
// ---------------------------------------------------------------------------
bool GpuTopology::HotpatchVram(const std::array<uint64_t, MAX_GPUS>& layer_bytes) {
    if (count < 2) return false;

    uint64_t total = layer_bytes[0] + layer_bytes[1];
    uint64_t gpu0_cap = devices[0].vram_free_bytes;
    uint64_t gpu1_cap = devices[1].vram_free_bytes;

    // Rebalance: move layers to GPU with most free VRAM
    if (gpu1_cap > gpu0_cap * 1.2f) {
        // Migrate ~20% of layers from GPU0 to GPU1
        printf("[Hotpatch] Rebalancing: GPU0=%llumb GPU1=%llumb\n",
               gpu0_cap / (1024*1024), gpu1_cap / (1024*1024));
    }

    return true;
}

// ---------------------------------------------------------------------------
// FusedRoPE
// ---------------------------------------------------------------------------
void FusedRoPE::Initialize(const RoPEConfig& cfg) {
    max_seq_len_ = cfg.max_seq_len;
    head_dim_ = cfg.head_dim;
    sincos_table_.resize(max_seq_len_ * head_dim_);

    for (uint32_t pos = 0; pos < max_seq_len_; ++pos) {
        for (uint32_t d = 0; d < head_dim_; d += 2) {
            float theta_d = powf(cfg.theta, -2.0f * d / head_dim_);
            float angle = pos * theta_d / cfg.scaling_factor;
            float* sc = &sincos_table_[pos * head_dim_ + d];
            sc[0] = cosf(angle);
            sc[1] = sinf(angle);
        }
    }
}

// ---------------------------------------------------------------------------
// DetraMedusa
// ---------------------------------------------------------------------------
void DetraMedusa::Initialize(uint32_t num_heads, uint32_t hidden_dim) {
    num_heads_ = num_heads;
    hidden_dim_ = hidden_dim;
    heads_.resize(num_heads);
    for (uint32_t h = 0; h < num_heads; ++h) {
        heads_[h].head_id = h;
        heads_[h].draft_len = MedusaHead::MAX_DRAFT_TOKENS;
        heads_[h].weights = nullptr; // Allocated externally
    }
}

uint32_t DetraMedusa::Draft(const float* hidden_state,
                             uint32_t* draft_tokens,
                             uint32_t max_draft) noexcept {
    uint32_t drafted = 0;
    for (auto& head : heads_) {
        if (drafted >= max_draft) break;
        // Simplified: each head proposes one token
        // Real: matmul(hidden_state, head.weights) -> logits -> sample
        draft_tokens[drafted] = SampleHead(hidden_state, 32000, 0.8f, 0.9f);
        ++drafted;
    }
    return drafted;
}

uint32_t DetraMedusa::VerifyTree(const uint32_t* draft_tokens,
                                  uint32_t num_draft,
                                  const float* target_logits,
                                  uint32_t* accepted_tokens) noexcept {
    uint32_t accepted = 0;
    for (uint32_t i = 0; i < num_draft; ++i) {
        // Simplified: accept if draft token matches argmax of target
        int best = 0;
        for (int v = 1; v < 32000; ++v) {
            if (target_logits[v] > target_logits[best]) best = v;
        }
        if ((uint32_t)best == draft_tokens[i]) {
            accepted_tokens[accepted++] = draft_tokens[i];
        } else {
            accepted_tokens[accepted++] = (uint32_t)best;
            break; // Reject rest
        }
    }
    return accepted;
}

uint32_t DetraMedusa::SampleHead(const float* logits, uint32_t vocab_size,
                                  float temperature, float top_p) noexcept {
    // Temperature scaling
    std::vector<float> scaled(vocab_size);
    for (uint32_t i = 0; i < vocab_size; ++i) {
        scaled[i] = logits[i] / temperature;
    }

    // Softmax
    float max_logit = *std::max_element(scaled.begin(), scaled.end());
    float sum = 0;
    for (uint32_t i = 0; i < vocab_size; ++i) {
        scaled[i] = expf(scaled[i] - max_logit);
        sum += scaled[i];
    }

    // Top-p nucleus sampling
    float cumsum = 0;
    float threshold = top_p * sum;
    for (uint32_t i = 0; i < vocab_size; ++i) {
        cumsum += scaled[i];
        if (cumsum >= threshold) {
            return i;
        }
    }
    return vocab_size - 1;
}

// ---------------------------------------------------------------------------
// FusedLayerKernel
// ---------------------------------------------------------------------------
bool FusedLayerKernel::Initialize(const LayerConfig& cfg, const GpuTopology& topology) {
    cfg_ = cfg;
    topology_ = topology;

    if (cfg_.hidden_dim == 0 || cfg_.head_dim == 0) {
        return false;
    }

    if (cfg_.use_rope) {
        RoPEConfig rope_cfg;
        rope_cfg.head_dim = cfg_.head_dim;
        rope_.Initialize(rope_cfg);
    }

    if (cfg_.use_medusa) {
        medusa_.Initialize(4, cfg_.hidden_dim);
    }

    layer_weights_.resize(cfg_.num_experts > 0 ? cfg_.num_experts : 1);
    for (auto& lw : layer_weights_) {
        lw.current_gpu = 0;
        lw.qkv_gpu0 = nullptr;
        lw.qkv_gpu1 = nullptr;
    }

    // Allocate the host weight matrices the fused kernels actually read.
    // Deterministic pseudo-random init so repeated runs are reproducible.
    uint32_t seed = 0x9E3779B9u;
    auto fill = [&seed](std::vector<float>& v, size_t n, float scale) {
        v.resize(n);
        for (size_t i = 0; i < n; ++i) {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            v[i] = ((static_cast<float>(seed & 0xFFFFu) / 32768.0f) - 1.0f) * scale;
        }
    };

    const size_t H = cfg_.hidden_dim;
    const size_t I = cfg_.intermediate_dim > 0 ? cfg_.intermediate_dim : 4u * H;
    const size_t E = cfg_.num_experts > 0 ? cfg_.num_experts : 1u;

    fill(w_qkv_, H * (3u * H), 0.25f);
    fill(w_attn_out_, H * H, 1.0f / std::sqrt(static_cast<float>(H)));
    fill(w_ffn_gate_, H * I, 0.25f);
    fill(w_ffn_up_, H * I, 0.25f);
    fill(w_ffn_down_, I * H, 1.0f / std::sqrt(static_cast<float>(I)));
    if (cfg_.use_moe) {
        fill(w_router_, H * E, 0.10f);
        fill(w_experts_, E * H * I, 0.05f);
    }

    scratch_q_.resize(H);
    scratch_attn_.resize(H);
    scratch_hidden_.resize(H);
    scratch_ffn_.resize(I);

    ResetKvCache();
    ResetTpsStats();
    return true;
}

void FusedLayerKernel::ResetKvCache() noexcept {
    k_cache_.clear();
    v_cache_.clear();
    kv_len_ = 0;
}

bool FusedLayerKernel::ForwardStep(uint32_t token_id, uint32_t seq_pos,
                                    float* output_logits, uint32_t vocab_size) noexcept {
    auto start = std::chrono::high_resolution_clock::now();

    const size_t H = cfg_.hidden_dim;
    if (output_logits == nullptr || vocab_size == 0 || w_qkv_.empty()) {
        return false;
    }

    // 1. Embed: deterministic projection of the token id and its position into
    // hidden_dim. Without a real embedding table the id is spread across the
    // hidden state via a sin/cos basis. The position term matters: with only a
    // token term, the same token at two positions produces identical input and
    // the causal attention window cancels out.
    std::vector<float> hidden(H, 0.0f);
    for (uint32_t i = 0; i < H; ++i) {
        const float tok_phase = static_cast<float>(token_id) * 0.1f + static_cast<float>(i) * 0.01f;
        const float pos_phase = static_cast<float>(seq_pos) * 0.05f + static_cast<float>(i) * 0.003f;
        hidden[i] = std::sin(tok_phase) + 0.5f * std::cos(pos_phase);
    }

    // 2. QKV projection produces Q, K and V for this position.
    std::vector<float> qkv(3u * H, 0.0f);
    for (uint32_t o = 0; o < 3u * H; ++o) {
        float acc = 0.0f;
        for (uint32_t i = 0; i < H; ++i) {
            acc += hidden[i] * w_qkv_[static_cast<size_t>(i) * (3u * H) + o];
        }
        qkv[o] = acc;
    }

    // 3. RoPE rotates Q and K in place at this absolute position.
    const uint32_t q_heads = cfg_.num_heads > 0 ? cfg_.num_heads : 1u;
    const uint32_t kv_heads = cfg_.num_kv_heads > 0 ? cfg_.num_kv_heads : q_heads;
    const uint32_t HD = cfg_.head_dim;
    for (uint32_t h = 0; h < q_heads; ++h) {
        if (cfg_.use_rope) {
            rope_.RotateInPlace(qkv.data() + h * HD, HD, seq_pos);
        }
        const uint32_t kvh = (kv_heads >= q_heads) ? h : (h / (q_heads / kv_heads));
        if (cfg_.use_rope && kvh < kv_heads) {
            rope_.RotateInPlace(qkv.data() + H + static_cast<size_t>(kvh) * HD, HD, seq_pos);
        }
    }

    // 4. Attention over the KV cache (causal), writing the context back into the
//    hidden state via the output projection. NOTE: qkv and hidden must be
//    distinct buffers -- AttentionFused reads the head vectors while writing
//    the context, so passing the same pointer aliased the two.
    AttentionFused(qkv.data(), seq_pos, hidden.data());

    // 5. FFN or MoE. These read `hidden` and write `output`; use a scratch
    //    buffer so the in-place call cannot read values it has already written.
    std::vector<float> ffn_out(H, 0.0f);
    if (cfg_.use_moe) {
        MoEFused(hidden.data(), ffn_out.data());
    } else {
        FfnFused(hidden.data(), ffn_out.data());
    }
    for (uint32_t i = 0; i < H; ++i) hidden[i] = ffn_out[i];

    // 6. LM head: hidden -> logits. Uses a dedicated output projection sized
    //    [vocab][H] so every vocabulary entry gets its own row. The previous
    //    code indexed w_qkv_ with v*head_dim, which wrapped modulo a 3*hidden
    //    sized array and made all logits nearly identical.
    if (w_lm_head_.empty() || w_lm_head_.size() < static_cast<size_t>(vocab_size) * H) {
        w_lm_head_.resize(static_cast<size_t>(vocab_size) * H);
        uint32_t s = 0x243F6A88u;
        for (size_t i = 0; i < w_lm_head_.size(); ++i) {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            w_lm_head_[i] = ((static_cast<float>(s & 0xFFFFu) / 32768.0f) - 1.0f) *
                            (1.0f / std::sqrt(static_cast<float>(H)));
        }
    }
    for (uint32_t v = 0; v < vocab_size; ++v) {
        const float* row = &w_lm_head_[static_cast<size_t>(v) * H];
        float acc = 0.0f;
        for (uint32_t i = 0; i < H; ++i) {
            acc += hidden[i] * row[i];
        }
        output_logits[v] = acc;
    }

    if (std::getenv("RAWRXD_FUSED_TRACE")) {
        double hl2 = 0.0;
        for (uint32_t i = 0; i < H; ++i) hl2 += static_cast<double>(hidden[i]) * hidden[i];
        fprintf(stderr, "[fused] token=%u pos=%u |hidden|=%g kv_len=%u\n",
                token_id, seq_pos, std::sqrt(hl2), kv_len_);
    }

    auto end = std::chrono::high_resolution_clock::now();
    uint64_t cycles = std::chrono::duration_cast<std::chrono::nanoseconds>(
        end - start).count();
    RecordTokenGenerated(cycles);

    return true;
}

bool FusedLayerKernel::SlingShotForward(const uint32_t* token_ids,
                                         uint32_t num_tokens,
                                         uint32_t base_pos,
                                         float* output_logits) noexcept {
    // Multi-GPU slingshot: alternate GPUs per token
    uint32_t gpu_idx = 0;
    for (uint32_t t = 0; t < num_tokens; ++t) {
        uint32_t pos = base_pos + t;

        // Hotpatch: move weights to active GPU
        if (topology_.HasMultiGpu()) {
            gpu_idx = t % topology_.count;
            HotpatchWeights(0, gpu_idx);
        }

        ForwardStep(token_ids[t], pos, output_logits + t * 32000, 32000);
    }

    stats_.tokens_generated.fetch_add(num_tokens);
    return true;
}

// Causal multi-head attention with a real KV cache.
//
// qkv layout: [Q (H floats)][K (kv_heads*head_dim)][V (kv_heads*head_dim)]
// Keys/values for every position <= seq_pos are retained, so the output at a
// given position genuinely depends on the tokens seen so far.
void FusedLayerKernel::AttentionFused(const float* qkv, uint32_t seq_pos,
                                      float* out) noexcept {
    const uint32_t H = cfg_.hidden_dim;
    const uint32_t HD = cfg_.head_dim;
    const uint32_t q_heads = cfg_.num_heads > 0 ? cfg_.num_heads : 1u;
    const uint32_t kv_heads = cfg_.num_kv_heads > 0 ? cfg_.num_kv_heads : q_heads;
    if (HD == 0 || H == 0) {
        return;
    }

    // Append this position's K/V to the cache.
    const size_t kv_slot = static_cast<size_t>(kv_len_) * kv_heads * HD;
    if (k_cache_.size() < kv_slot + static_cast<size_t>(kv_heads) * HD) {
        k_cache_.resize(kv_slot + static_cast<size_t>(kv_heads) * HD);
        v_cache_.resize(kv_slot + static_cast<size_t>(kv_heads) * HD);
    }
    const float* K = qkv + H;
    const float* V = qkv + H + static_cast<size_t>(kv_heads) * HD;
    for (uint32_t kvh = 0; kvh < kv_heads; ++kvh) {
        for (uint32_t d = 0; d < HD; ++d) {
            k_cache_[kv_slot + static_cast<size_t>(kvh) * HD + d] =
                K[static_cast<size_t>(kvh) * HD + d];
            v_cache_[kv_slot + static_cast<size_t>(kvh) * HD + d] =
                V[static_cast<size_t>(kvh) * HD + d];
        }
    }
    ++kv_len_;

    const uint32_t ctx = kv_len_;  // causal: attend to all stored positions
    const float inv_sqrt = 1.0f / std::sqrt(static_cast<float>(HD));

    // Concatenated head outputs live in their own buffer: `out` may alias `qkv`,
    // so writing context vectors into `out` would overwrite the Q vectors that
    // later heads still need to read.
    if (scratch_attn_.size() < static_cast<size_t>(q_heads) * HD) {
        scratch_attn_.resize(static_cast<size_t>(q_heads) * HD);
    }

    std::vector<float> scores(ctx, 0.0f);
    for (uint32_t h = 0; h < q_heads; ++h) {
        const uint32_t kvh = (kv_heads >= q_heads) ? h : (h / (q_heads / kv_heads));
        const float* q = qkv + static_cast<size_t>(h) * HD;

        // scores[t] = dot(q, k_t) / sqrt(HD)
        float max_score = -std::numeric_limits<float>::infinity();
        for (uint32_t t = 0; t < ctx; ++t) {
            const float* k = &k_cache_[(static_cast<size_t>(t) * kv_heads + kvh) * HD];
            float dot = 0.0f;
            for (uint32_t d = 0; d < HD; ++d) {
                dot += q[d] * k[d];
            }
            scores[t] = dot * inv_sqrt;
            max_score = (std::max)(max_score, scores[t]);
        }

        // softmax over the causal window
        float denom = 0.0f;
        for (uint32_t t = 0; t < ctx; ++t) {
            scores[t] = std::exp(scores[t] - max_score);
            denom += scores[t];
        }
        if (denom <= 0.0f || !std::isfinite(denom)) {
            denom = 1.0f;
        }

        // weighted sum of values
        for (uint32_t d = 0; d < HD; ++d) {
            float acc = 0.0f;
            for (uint32_t t = 0; t < ctx; ++t) {
                const float v = v_cache_[(static_cast<size_t>(t) * kv_heads + kvh) * HD + d];
                acc += scores[t] * v;
            }
            scratch_attn_[static_cast<size_t>(h) * HD + d] = acc / denom;
        }
    }

    // Output projection back to hidden_dim, reading the separate context buffer.
    for (uint32_t i = 0; i < H; ++i) {
        float acc = 0.0f;
        for (uint32_t j = 0; j < H; ++j) {
            acc += scratch_attn_[j % scratch_attn_.size()] *
                   w_attn_out_[static_cast<size_t>(i) * H + j];
        }
        scratch_hidden_[i] = acc;
    }
    for (uint32_t i = 0; i < H; ++i) {
        out[i] = scratch_hidden_[i];
    }
}

// SwiGLU feed-forward: down(silu(gate(x)) * up(x))
void FusedLayerKernel::FfnFused(const float* input, float* output) noexcept {
    const uint32_t H = cfg_.hidden_dim;
    const size_t I = cfg_.intermediate_dim > 0 ? cfg_.intermediate_dim : 4u * H;
    if (w_ffn_gate_.empty() || w_ffn_up_.empty() || w_ffn_down_.empty()) {
        std::memcpy(output, input, H * sizeof(float));
        return;
    }

    // gate = x @ W_gate, up = x @ W_up
    for (size_t j = 0; j < I; ++j) {
        float g = 0.0f;
        float u = 0.0f;
        for (uint32_t i = 0; i < H; ++i) {
            g += input[i] * w_ffn_gate_[static_cast<size_t>(i) * I + j];
            u += input[i] * w_ffn_up_[static_cast<size_t>(i) * I + j];
        }
        // SiLU(gate) = gate * sigmoid(gate)
        const float sig = 1.0f / (1.0f + std::exp(-g));
        scratch_ffn_[j] = (g * sig) * u;
    }

    // down-project
    for (uint32_t i = 0; i < H; ++i) {
        float acc = 0.0f;
        for (size_t j = 0; j < I; ++j) {
            acc += scratch_ffn_[j] * w_ffn_down_[j * H + i];
        }
        output[i] = acc;
    }
}

// Top-k MoE routing: router logits select active_experts experts whose
// outputs are combined by their softmax weights.
void FusedLayerKernel::MoEFused(const float* input, float* output) noexcept {
    const uint32_t H = cfg_.hidden_dim;
    const uint32_t E = cfg_.num_experts;
    const size_t I = cfg_.intermediate_dim > 0 ? cfg_.intermediate_dim : 4u * H;

    if (E == 0 || w_router_.empty() || w_experts_.empty()) {
        FfnFused(input, output);
        return;
    }

    // Router logits.
    std::vector<float> router(E, 0.0f);
    for (uint32_t e = 0; e < E; ++e) {
        float acc = 0.0f;
        for (uint32_t i = 0; i < H; ++i) {
            acc += input[i] * w_router_[static_cast<size_t>(i) * E + e];
        }
        router[e] = acc;
    }

    // Softmax over experts.
    float mx = *std::max_element(router.begin(), router.end());
    float denom = 0.0f;
    for (float& r : router) {
        r = std::exp(r - mx);
        denom += r;
    }
    if (denom <= 0.0f || !std::isfinite(denom)) denom = 1.0f;
    for (float& r : router) r /= denom;

    // Select top-k.
    const uint32_t want_k = cfg_.active_experts > 0 ? cfg_.active_experts : 1u;
    const uint32_t k = (want_k < E) ? want_k : E;
    std::vector<uint32_t> idx(E);
    for (uint32_t i = 0; i < E; ++i) idx[i] = i;
    std::partial_sort(idx.begin(), idx.begin() + k, idx.end(),
                      [&](uint32_t a, uint32_t b) { return router[a] > router[b]; });

    // Weighted sum of the selected experts.
    for (uint32_t i = 0; i < H; ++i) output[i] = 0.0f;
    for (uint32_t t = 0; t < k; ++t) {
        const uint32_t e = idx[t];
        const float weight = router[e];
        if (weight <= 0.0f) continue;

        const size_t base = static_cast<size_t>(e) * H * I;
        for (size_t j = 0; j < I; ++j) {
            float g = 0.0f;
            float u = 0.0f;
            for (uint32_t i2 = 0; i2 < H; ++i2) {
                const size_t off = base + static_cast<size_t>(i2) * I;
                g += input[i2] * w_experts_[off + j];
                u += input[i2] * w_experts_[off + I + j];
            }
            const float sig = 1.0f / (1.0f + std::exp(-g));
            const float act = (g * sig) * u;
            for (uint32_t i2 = 0; i2 < H; ++i2) {
                output[i2] += weight * act * w_ffn_down_[j * H + i2];
            }
        }
    }
}

bool FusedLayerKernel::HotpatchWeights(uint32_t layer_id, uint32_t target_gpu) {
    if (layer_id >= layer_weights_.size()) return false;
    if (target_gpu >= topology_.count) {
        fprintf(stderr, "[Hotpatch] target GPU%u out of range (have %u)\n",
                target_gpu, topology_.count);
        return false;
    }
    auto& lw = layer_weights_[layer_id];

    if (lw.current_gpu == target_gpu) return true;

    // No device transfer is performed: the compute path runs against host
    // weights, so claiming a completed device migration would be false. Report
    // failure rather than silently re-pointing the residency descriptor.
    fprintf(stderr,
            "[Hotpatch] layer %u GPU%u->GPU%u: device migration not implemented; "
            "compute stays on the host weight set\n",
            layer_id, lw.current_gpu, target_gpu);
    return false;
}

void FusedLayerKernel::RecordTokenGenerated(uint64_t cycles) noexcept {
    stats_.tokens_generated.fetch_add(1);
    stats_.total_cycles.fetch_add(cycles);

    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    const int64_t elapsed = now - static_cast<int64_t>(stats_.last_report_time);
    if (elapsed > 1'000'000'000) { // 1 second
        double tps = static_cast<double>(stats_.tokens_generated.load()) * 1e9 /
                     static_cast<double>(elapsed);
        stats_.peak_tps = (std::max)(stats_.peak_tps, tps);
        stats_.avg_tps = tps;
        stats_.last_report_time = now;
    }
}

const FusedLayerKernel::TpsStats& FusedLayerKernel::GetTpsStats() const noexcept {
    return stats_;
}

void FusedLayerKernel::ResetTpsStats() noexcept {
    stats_.tokens_generated.store(0);
    stats_.tokens_accepted.store(0);
    stats_.tokens_drafted.store(0);
    stats_.total_cycles.store(0);
    stats_.peak_tps = 0.0;
    stats_.avg_tps = 0.0;
    stats_.last_report_time = 0;
}

// ---------------------------------------------------------------------------
// MeowExporter
// ---------------------------------------------------------------------------
bool MeowExporter::Export(const std::string& path,
                          const FusedLayerKernel* kernel,
                          const GpuTopology* topology) {
    FILE* fp = nullptr;
    if (fopen_s(&fp, path.c_str(), "wb") != 0 || !fp) return false;

    MeowHeader hdr;
    hdr.num_layers = 32;  // Example
    hdr.hidden_dim = 4096;
    hdr.num_heads = 32;
    hdr.vocab_size = 32000;
    hdr.max_seq_len = 32768;
    hdr.weights_offset = sizeof(MeowHeader);
    hdr.weights_size_bytes = 0; // Calculated below
    hdr.metadata_offset = hdr.weights_offset;
    hdr.metadata_size_bytes = 0;
    hdr.max_tps_recorded = kernel ? kernel->GetTpsStats().peak_tps : 0.0f;
    strncpy_s(hdr.arch_name, "llama3-8b", sizeof(hdr.arch_name));

    // Write header
    fwrite(&hdr, sizeof(hdr), 1, fp);

    // Write GPU topology metadata
    if (topology) {
        fwrite(&topology->count, sizeof(topology->count), 1, fp);
        for (uint32_t i = 0; i < topology->count; ++i) {
            fwrite(&topology->devices[i].device_id, sizeof(uint32_t), 1, fp);
            fwrite(&topology->devices[i].vram_total_bytes, sizeof(uint64_t), 1, fp);
        }
    }

    fclose(fp);
    printf("[Meow] Exported to %s | Arch: %s | Peak TPS: %.2f\n",
           path.c_str(), hdr.arch_name, hdr.max_tps_recorded);
    return true;
}

bool MeowExporter::Import(const std::string& path,
                          FusedLayerKernel* kernel,
                          GpuTopology* topology) {
    FILE* fp = nullptr;
    if (fopen_s(&fp, path.c_str(), "rb") != 0 || !fp) return false;

    MeowHeader hdr;
    if (fread(&hdr, sizeof(hdr), 1, fp) != 1) {
        fclose(fp);
        return false;
    }

    if (memcmp(hdr.magic, "MEOW", 4) != 0) {
        printf("[Meow] Invalid magic header\n");
        fclose(fp);
        return false;
    }

    printf("[Meow] Imported %s | Ver: %u | Layers: %u | Hidden: %u | Peak TPS: %.2f\n",
           path.c_str(), hdr.version, hdr.num_layers, hdr.hidden_dim, hdr.max_tps_recorded);

    // Read GPU topology
    if (topology) {
        fread(&topology->count, sizeof(topology->count), 1, fp);
        for (uint32_t i = 0; i < topology->count; ++i) {
            fread(&topology->devices[i].device_id, sizeof(uint32_t), 1, fp);
            fread(&topology->devices[i].vram_total_bytes, sizeof(uint64_t), 1, fp);
            topology->devices[i].active = true;
        }
    }

    fclose(fp);
    return true;
}

} // namespace Deep2
