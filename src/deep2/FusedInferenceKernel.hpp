// ============================================================================
// FusedInferenceKernel.hpp — Multi-GPU, RoPE, Medusa, VRAM Hotpatch, TPS Max
// Decoded from: xDim*() countMulti dim*() _layer-----'gNop 'gNop unPing-
//   floatBuffers*hidden slingshotseqPos+RoPE; reunInt gpuBool(VRAMgpu())
//   hotVRAM / bytesHotpatch (gpu0;gpu1) ... detraMedusa ... wasdSpit(mAX*TPS)
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include <math>
#include <array>
#include <atomic>
#include <chrono>
#include <immintrin.h>

#ifdef _WIN32
#include <windows.h>
#endif

namespace Deep2 {

// ---------------------------------------------------------------------------
// GPU Topology — dual-GPU VRAM hotpatch descriptor
// ---------------------------------------------------------------------------
struct GpuDevice {
    uint32_t device_id;
    uint64_t vram_total_bytes;
    uint64_t vram_free_bytes;
    void*    context;           // Vulkan device or CUDA handle
    bool     active;
    float    temperature_c;     // NVMe-style thermal telemetry
};

struct GpuTopology {
    static constexpr uint32_t MAX_GPUS = 2;
    std::array<GpuDevice, MAX_GPUS> devices;
    uint32_t count = 0;

    __forceinline bool HasMultiGpu() const noexcept { return count > 1; }

    // Hotpatch: rebalance VRAM across GPUs based on layer weights
    bool HotpatchVram(const std::array<uint64_t, MAX_GPUS>& layer_bytes);
};

// ---------------------------------------------------------------------------
// RoPE (Rotary Position Embedding) — fused into attention, not separate pass
// ---------------------------------------------------------------------------
struct RoPEConfig {
    uint32_t max_seq_len = 32768;
    uint32_t head_dim = 128;
    float    theta = 10000.0f;
    float    scaling_factor = 1.0f;  // YaRN / NTK-aware
};

class FusedRoPE {
public:
    void Initialize(const RoPEConfig& cfg);

    // In-place rotate Q/K by position — no extra buffer, fused into attention
    // qk: [num_heads, head_dim] — modified in place
    // seq_pos: absolute position in sequence
    __forceinline void RotateInPlace(float* qk, uint32_t head_dim,
                                        uint32_t seq_pos) const noexcept {
        // Precomputed sin/cos pairs for each position
        const float* sincos = sincos_table_.data() + (seq_pos % max_seq_len_) * head_dim;

        for (uint32_t d = 0; d < head_dim; d += 2) {
            float x0 = qk[d];
            float x1 = qk[d + 1];
            float cos_t = sincos[d];
            float sin_t = sincos[d + 1];
            qk[d]     = x0 * cos_t - x1 * sin_t;
            qk[d + 1] = x0 * sin_t + x1 * cos_t;
        }
    }

private:
    uint32_t max_seq_len_ = 0;
    uint32_t head_dim_ = 0;
    std::vector<float> sincos_table_;  // [max_seq_len, head_dim]
};

// ---------------------------------------------------------------------------
// Medusa Speculative Decoder — multi-head draft, tree attention verify
// ---------------------------------------------------------------------------
struct MedusaHead {
    static constexpr uint32_t MAX_DRAFT_TOKENS = 4;
    float* weights;           // [draft_len, hidden_dim] for each head
    uint32_t draft_len;
    uint32_t head_id;
};

class DetraMedusa {
public:
    void Initialize(uint32_t num_heads, uint32_t hidden_dim);

    // Generate draft tokens from current hidden state
    // Returns: number of draft tokens accepted (0 = all rejected)
    uint32_t Draft(const float* hidden_state,
                   uint32_t* draft_tokens,
                   uint32_t max_draft) noexcept;

    // Tree attention: verify all draft tokens in parallel
    // Returns: number of accepted tokens + their positions
    uint32_t VerifyTree(const uint32_t* draft_tokens,
                        uint32_t num_draft,
                        const float* target_logits,
                        uint32_t* accepted_tokens) noexcept;

    // Advance position counter after accept/reject
    __forceinline void AdvancePos(uint32_t accepted) noexcept {
        current_pos_ += accepted;
    }

    __forceinline uint32_t CurrentPos() const noexcept { return current_pos_; }

private:
    uint32_t num_heads_ = 0;
    uint32_t hidden_dim_ = 0;
    uint32_t current_pos_ = 0;
    std::vector<MedusaHead> heads_;

    // Temperature-scaled top-p sampling for draft heads
    uint32_t SampleHead(const float* logits, uint32_t vocab_size,
                        float temperature, float top_p) noexcept;
};

// ---------------------------------------------------------------------------
// Fused Layer Kernel — gNop (gate no-op) fused with slingshot seqPos
// ---------------------------------------------------------------------------
struct LayerConfig {
    uint32_t hidden_dim;
    uint32_t num_heads;
    uint32_t num_kv_heads;     // GQA
    uint32_t head_dim;
    uint32_t intermediate_dim; // FFN expansion
    uint32_t num_experts;      // MoE
    uint32_t active_experts;   // top-k
    bool     use_rope;
    bool     use_medusa;
    bool     use_gqa;
    bool     use_moe;
};

class FusedLayerKernel {
public:
    bool Initialize(const LayerConfig& cfg, const GpuTopology& topology);

    // Single forward step: embed -> RoPE -> attention -> FFN/MoE -> logits
    // All fused into one kernel dispatch where possible
    bool ForwardStep(uint32_t token_id,
                     uint32_t seq_pos,
                     float* output_logits,
                     uint32_t vocab_size) noexcept;

    // Multi-GPU slingshot: alternate GPUs per layer to maximize bandwidth
    bool SlingShotForward(const uint32_t* token_ids,
                          uint32_t num_tokens,
                          uint32_t base_pos,
                          float* output_logits) noexcept;

    // TPS telemetry
    struct TpsStats {
        std::atomic<uint64_t> tokens_generated{0};
        std::atomic<uint64_t> tokens_accepted{0};   // Medusa accept count
        std::atomic<uint64_t> tokens_drafted{0};
        std::atomic<uint64_t> total_cycles{0};
        double peak_tps = 0.0;
        double avg_tps = 0.0;
        uint64_t last_report_time = 0;
    };

    TpsStats GetTpsStats() const noexcept;
    void ResetTpsStats() noexcept;

    // VRAM hotpatch: move weights between GPU0/GPU1 mid-inference
    bool HotpatchWeights(uint32_t layer_id, uint32_t target_gpu);

private:
    LayerConfig cfg_;
    GpuTopology topology_;
    FusedRoPE   rope_;
    DetraMedusa medusa_;
    TpsStats    stats_;

    // Layer weights split across GPUs
    struct LayerWeights {
        void* qkv_gpu0;        // [hidden_dim, qkv_dim]
        void* qkv_gpu1;
        void* ffn_up_gpu0;     // [hidden_dim, intermediate_dim]
        void* ffn_down_gpu1;   // [intermediate_dim, hidden_dim]
        void* expert_gate;     // [num_experts] — stays on GPU0
        uint32_t current_gpu;
    };
    std::vector<LayerWeights> layer_weights_;

    // Internal fused kernels
    void AttentionFused(const float* qkv, uint32_t seq_pos,
                        float* out) noexcept;
    void FfnFused(const float* input, float* output) noexcept;
    void MoEFused(const float* input, float* output) noexcept;

    // TPS measurement
    void RecordTokenGenerated(uint64_t cycles) noexcept;
};

// ---------------------------------------------------------------------------
// Model Export — "model.meow" format (compact binary checkpoint)
// ---------------------------------------------------------------------------
struct MeowHeader {
    char     magic[4] = {'M', 'E', 'O', 'W'};
    uint32_t version = 1;
    uint32_t num_layers;
    uint32_t hidden_dim;
    uint32_t num_heads;
    uint32_t vocab_size;
    uint32_t max_seq_len;
    uint64_t weights_offset;
    uint64_t weights_size_bytes;
    uint64_t metadata_offset;
    uint64_t metadata_size_bytes;
    float    max_tps_recorded;
    char     arch_name[32];
};

class MeowExporter {
public:
    bool Export(const std::string& path,
                const FusedLayerKernel* kernel,
                const GpuTopology* topology);

    bool Import(const std::string& path,
                FusedLayerKernel* kernel,
                GpuTopology* topology);

private:
    static constexpr uint32_t MEOW_VERSION = 1;

    bool WriteHeader(FILE* fp, const MeowHeader& hdr);
    bool ReadHeader(FILE* fp, MeowHeader& hdr);
    uint32_t Crc32(const uint8_t* data, size_t len);
};

// ---------------------------------------------------------------------------
// wasdSpit — TPS output formatter
// ---------------------------------------------------------------------------
inline void wasdSpit(const FusedLayerKernel::TpsStats& stats) {
    printf("[wasdSpit] Tokens: %llu | Accepted: %llu | Drafted: %llu | Peak TPS: %.2f | Avg TPS: %.2f\n",
           stats.tokens_generated.load(),
           stats.tokens_accepted.load(),
           stats.tokens_drafted.load(),
           stats.peak_tps,
           stats.avg_tps);
}

} // namespace Deep2
