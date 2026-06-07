// SovereignInferenceEngine.hpp
// Phase 3.1 — Sovereign-native inference engine (no llama.dll dependency)
// Wires: RawrXDTokenizer + TransformerStackOrchestrator + SovereignLayerExecutor + KVCacheManager
//
// For deterministic replay, temperature=0.0f and top_k=1 enforce greedy sampling.

#pragma once

#include "SovereignLayerExecutor.h"
#include "SovereignKVCache.hpp"
#include "kv_cache_manager.h"
#include "transformer_stack_orchestrator.hpp"
#include "rawrxd_tokenizer.h"
#include "streaming_gguf_loader.h"
#include "rawr_linear_allocator.h"

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <cmath>

namespace RawrXD {
namespace AI {

struct SovereignEngineConfig {
    const char* model_path = nullptr;          // GGUF path
    uint32_t    max_context_length = 4096;
    float       temperature = 0.0f;            // 0.0 = deterministic greedy
    uint32_t    top_k = 1;                     // 1 = greedy
    uint64_t    seed = 0;                      // RNG seed (reserved for future sampling)
    uint32_t    max_batch = 1;
};

// ---------------------------------------------------------------------------
// Minimal forward-pass state for a single token step
// ---------------------------------------------------------------------------
struct TokenStepState {
    std::vector<uint32_t> token_ids;   // prompt + generated so far
    std::vector<float>    hidden;      // current hidden state (n_embd floats)
    size_t                seq_len = 0;
    bool                  prefill_done = false;
};

// ---------------------------------------------------------------------------
// SovereignInferenceEngine
// ---------------------------------------------------------------------------
class SovereignInferenceEngine {
public:
    explicit SovereignInferenceEngine(const SovereignEngineConfig& cfg);
    ~SovereignInferenceEngine();

    // Load model weights + tokenizer from GGUF
    bool Initialize();

    // Synchronous generate: prompt in, tokens out
    bool Generate(const char* prompt,
                  std::vector<uint32_t>& out_tokens,
                  uint32_t max_new_tokens);

    // Per-step control for streaming / replay harness
    bool Prefill(const char* prompt);               // encode prompt, run prefill
    bool Step(uint32_t& out_token_id, bool& done);  // generate one token

    // Determinism helpers
    void ResetState();                              // clear generation state
    bool StatesIdentical(const SovereignInferenceEngine& other) const;

    // Stats
    struct Stats {
        uint64_t prefill_us = 0;
        uint64_t generate_us = 0;
        uint64_t tokens_generated = 0;
        float    tokens_per_second = 0.0f;
        float    kv_cache_hit_rate = 0.0f;
    };
    Stats GetStats() const;

    // Attention core micro-harness entry point
    struct AttentionStageHashes {
        uint64_t hash_input = 0;
        uint64_t hash_q = 0;
        uint64_t hash_k = 0;
        uint64_t hash_v = 0;
        uint64_t hash_scores = 0;
        uint64_t hash_softmax = 0;
        uint64_t hash_context = 0;
        uint64_t hash_attn_out = 0;   // post attn_output.weight projection
    };
    bool RunAttentionCore(const float* input, uint32_t n_embd, AttentionStageHashes& out);

    // FFN core micro-harness entry point
    struct FFNStageHashes {
        uint64_t hash_input = 0;
        uint64_t hash_gate = 0;
        uint64_t hash_up = 0;
        uint64_t hash_silu = 0;
        uint64_t hash_down = 0;
    };
    bool RunFFNCore(const float* input, uint32_t n_embd, FFNStageHashes& out);

    // Tokenizer access for harnesses
    const RawrXDTokenizer& Tokenizer() const { return tokenizer_; }

    // Full transformer layer forward (public for certification harnesses)
    bool RunLayerForward(uint32_t token_id, std::vector<float>& out_logits) {
        return RunTokenForward(token_id, out_logits);
    }

private:
    SovereignEngineConfig cfg_;

    // Subsystems
    RawrXDTokenizer tokenizer_;
    std::shared_ptr<KVCacheManager> kv_cache_;
    std::unique_ptr<SovereignKVCache> kv_cache_flat_;
    std::unique_ptr<TransformerStackOrchestrator> orchestrator_;

    // Model metadata (loaded from GGUF)
    uint32_t n_vocab_ = 0;
    uint32_t n_embd_ = 0;
    uint32_t n_layer_ = 0;
    uint32_t n_head_ = 0;
    uint32_t n_ctx_ = 0;

    // Model weights (loaded from GGUF during init)
    struct WeightSlot {
        void*  data = nullptr;
        size_t size = 0;
        SovereignTensorRef desc;
    };
    // Single-layer weights (blk.0) — kept for backward compat with micro-harnesses
    WeightSlot wq_, wk_, wv_, wo_;
    WeightSlot ffn_gate_, ffn_up_, ffn_down_;
    WeightSlot attn_norm_, ffn_norm_;
    // Multi-layer weight tables (34 layers for ministral3)
    std::vector<WeightSlot> wq_layers_, wk_layers_, wv_layers_, wo_layers_;
    std::vector<WeightSlot> ffn_gate_layers_, ffn_up_layers_, ffn_down_layers_;
    std::vector<WeightSlot> attn_norm_layers_, ffn_norm_layers_;
    // Final head weights (norm + output projection)
    WeightSlot output_norm_;      // final RMSNorm scale (n_embd F32)
    WeightSlot output_weight_;    // LM head (n_vocab × n_embd)
    // Tied embeddings: token_embd.weight converted to F32 for output projection
    WeightSlot token_embd_f32_;   // n_vocab × n_embd F32 (converted from F16)
    bool       weights_loaded_ = false;

    // Generation state
    TokenStepState step_state_;
    Stats stats_;

    // Scratch buffers: pre-allocated, reused across all layers (zero per-layer alloc)
    struct LayerScratch {
        float* x_norm   = nullptr;   // n_embd_  (RMSNorm output)
        float* attn_out = nullptr;   // n_embd_  (attention output)
        float* ffn_gate = nullptr;   // ffn_dim  (FFN gate projection)
        float* ffn_up   = nullptr;   // ffn_dim  (FFN up projection)
        float* ffn_silu = nullptr;   // ffn_dim  (SiLU(gate) * up)
        float* ffn_out  = nullptr;   // n_embd_  (FFN down projection)
    };
    LayerScratch scratch_;
    uint32_t scratch_ffn_dim_ = 14336;  // ministral3 default

    // Logits scratch: aligned buffer for output projection (MASM kernel needs 512-byte align)
    float* logits_scratch_ = nullptr;
    size_t logits_scratch_size_ = 0;

    // Forward pass: real GEMV via certified kernel + deterministic logit mapping
    bool RunTokenForward(uint32_t token_id, std::vector<float>& out_logits);

    // Greedy sample from logits
    uint32_t SampleGreedy(const float* logits, size_t count) const;
    uint32_t SampleWithTemperature(const float* logits, size_t count, float temperature) const;

    // Helpers
    bool LoadAttentionWeights(const char* model_path);
    bool LoadFFNWeights(const char* model_path);
    bool LoadNormWeights(const char* model_path);
    bool LoadAllLayerWeights(const char* model_path);  // 34-layer stack
    bool LoadWeightSlot(StreamingGGUFLoader& loader, const char* name, WeightSlot& slot);
    static float* AlignedAllocF32(size_t count, size_t align);
    static void   AlignedFree(void* ptr);
    static void   ConvertF16ToF32(const uint16_t* src, float* dst, size_t n);
    static uint64_t HashFloatVector(const float* vec, size_t n);
    static void Softmax(float* vec, size_t n);
    static void SiLU(float* vec, size_t n);
    static void RMSNorm(float* vec, size_t n, const float* scale, float eps);
};

} // namespace AI
} // namespace RawrXD
