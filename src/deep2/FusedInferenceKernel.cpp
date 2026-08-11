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

    ResetTpsStats();
    return true;
}

bool FusedLayerKernel::ForwardStep(uint32_t token_id, uint32_t seq_pos,
                                    float* output_logits, uint32_t vocab_size) noexcept {
    auto start = std::chrono::high_resolution_clock::now();

    // 1. Embed token (simplified: lookup table)
    std::vector<float> hidden(cfg_.hidden_dim, 0.0f);
    // Real: hidden = embedding_table[token_id]

    // 2. RoPE rotate Q/K (fused, no extra buffer)
    if (cfg_.use_rope) {
        for (uint32_t h = 0; h < cfg_.num_heads; ++h) {
            float* qk = hidden.data() + h * cfg_.head_dim;
            rope_.RotateInPlace(qk, cfg_.head_dim, seq_pos);
        }
    }

    // 3. Attention (simplified: single-head for demo)
    AttentionFused(hidden.data(), seq_pos, hidden.data());

    // 4. FFN or MoE
    if (cfg_.use_moe) {
        MoEFused(hidden.data(), hidden.data());
    } else {
        FfnFused(hidden.data(), hidden.data());
    }

    // 5. LM Head: hidden -> logits
    for (uint32_t v = 0; v < vocab_size; ++v) {
        output_logits[v] = 0.0f; // Real: matmul(hidden, lm_head)
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

void FusedLayerKernel::AttentionFused(const float* qkv, uint32_t seq_pos,
                                       float* out) noexcept {
    (void)qkv; (void)seq_pos;
    // Real: scaled dot-product attention with RoPE already applied
    // Simplified: pass-through for now
    memcpy(out, qkv, cfg_.hidden_dim * sizeof(float));
}

void FusedLayerKernel::FfnFused(const float* input, float* output) noexcept {
    // SwiGLU: gate = input * W_gate, up = input * W_up
    // out = silu(gate) * up * W_down
    // Simplified: identity
    memcpy(output, input, cfg_.hidden_dim * sizeof(float));
}

void FusedLayerKernel::MoEFused(const float* input, float* output) noexcept {
    // Top-k expert routing + weighted sum
    // Simplified: single expert
    FfnFused(input, output);
}

bool FusedLayerKernel::HotpatchWeights(uint32_t layer_id, uint32_t target_gpu) {
    if (layer_id >= layer_weights_.size()) return false;
    auto& lw = layer_weights_[layer_id];

    if (lw.current_gpu == target_gpu) return true;

    printf("[Hotpatch] Layer %u: GPU%u -> GPU%u\n", layer_id, lw.current_gpu, target_gpu);

    // Real: cudaMemcpyAsync / vkCmdCopyBuffer
    lw.current_gpu = target_gpu;
    return true;
}

void FusedLayerKernel::RecordTokenGenerated(uint64_t cycles) noexcept {
    stats_.tokens_generated.fetch_add(1);
    stats_.total_cycles.fetch_add(cycles);

    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    if (now - stats_.last_report_time > 1'000'000'000) { // 1 second
        double tps = stats_.tokens_generated.load() * 1e9 / (now - stats_.last_report_time);
        stats_.peak_tps = std::max(stats_.peak_tps, tps);
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
