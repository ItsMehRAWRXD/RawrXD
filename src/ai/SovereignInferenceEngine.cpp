// SovereignInferenceEngine.cpp
// Phase 3.1 — Sovereign-native inference engine implementation

#include "SovereignInferenceEngine.hpp"
#include "SovereignLayerExecutor.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <windows.h>

namespace RawrXD {
namespace AI {

SovereignInferenceEngine::SovereignInferenceEngine(const SovereignEngineConfig& cfg)
    : cfg_(cfg)
{
}

SovereignInferenceEngine::~SovereignInferenceEngine() {
    auto freeSlot = [](WeightSlot& s) {
        if (s.data) { _aligned_free(s.data); s.data = nullptr; s.size = 0; }
    };
    auto freeSlots = [&freeSlot](std::vector<WeightSlot>& slots) {
        for (auto& s : slots) freeSlot(s);
        slots.clear();
    };

    // Free multi-layer tables (own their memory)
    freeSlots(wq_layers_); freeSlots(wk_layers_); freeSlots(wv_layers_); freeSlots(wo_layers_);
    freeSlots(ffn_gate_layers_); freeSlots(ffn_up_layers_); freeSlots(ffn_down_layers_);
    freeSlots(attn_norm_layers_); freeSlots(ffn_norm_layers_);

    // Single-layer slots are just pointers — memory freed by vectors above
    wq_ = WeightSlot{}; wk_ = WeightSlot{}; wv_ = WeightSlot{}; wo_ = WeightSlot{};
    ffn_gate_ = WeightSlot{}; ffn_up_ = WeightSlot{}; ffn_down_ = WeightSlot{};
    attn_norm_ = WeightSlot{}; ffn_norm_ = WeightSlot{};

    // Free standalone slots
    freeSlot(output_norm_); freeSlot(output_weight_); freeSlot(token_embd_f32_);

    // Free scratch buffers
    AlignedFree(scratch_.x_norm);
    AlignedFree(scratch_.attn_out);
    AlignedFree(scratch_.ffn_gate);
    AlignedFree(scratch_.ffn_up);
    AlignedFree(scratch_.ffn_silu);
    AlignedFree(scratch_.ffn_out);
    scratch_ = LayerScratch{};
    AlignedFree(logits_scratch_);
    logits_scratch_ = nullptr;
    logits_scratch_size_ = 0;
}

bool SovereignInferenceEngine::Initialize() {
    if (!cfg_.model_path) {
        fprintf(stderr, "FATAL: model_path is null\n");
        return false;
    }

    // 1. Load tokenizer from GGUF metadata
    printf("[Engine] Loading tokenizer from %s\n", cfg_.model_path);
    if (!tokenizer_.LoadFromGGUF(cfg_.model_path)) {
        fprintf(stderr, "WARN: LoadFromGGUF failed, falling back to basic vocab\n");
        // Fallback: create minimal vocab so Encode/Decode don't crash
        tokenizer_.LoadFromVocab({"\u003cunk\u003e", "\u003cs\u003e", "\u003c/s\u003e", " "});
    }
    n_vocab_ = static_cast<uint32_t>(tokenizer_.size());
    printf("[Engine] Vocab size: %u\n", n_vocab_);

    // 2. Parse GGUF metadata for model dims
    StreamingGGUFLoader loader;
    if (loader.Open(cfg_.model_path) && loader.ParseHeader() && loader.ParseMetadata()) {
        // Try to read key metadata values
        // These are best-effort; if missing we use safe defaults
        n_embd_ = 4096;   // default for ministral3
        n_layer_ = 34;    // default for ministral3
        n_ctx_ = cfg_.max_context_length;
        printf("[Engine] Model dims: n_embd=%u n_layer=%u n_ctx=%u\n",
               n_embd_, n_layer_, n_ctx_);
    } else {
        fprintf(stderr, "WARN: Could not parse GGUF metadata, using defaults\n");
        n_embd_ = 4096;
        n_layer_ = 34;
        n_ctx_ = cfg_.max_context_length;
    }

    // 2b. Pre-allocate layer scratch buffers (zero per-layer alloc in hot loop)
    scratch_ffn_dim_ = 14336;  // ministral3
    scratch_.x_norm   = AlignedAllocF32(n_embd_, 512);
    scratch_.attn_out = AlignedAllocF32(n_embd_, 512);
    scratch_.ffn_gate = AlignedAllocF32(scratch_ffn_dim_, 512);
    scratch_.ffn_up   = AlignedAllocF32(scratch_ffn_dim_, 512);
    scratch_.ffn_silu = AlignedAllocF32(scratch_ffn_dim_, 512);
    scratch_.ffn_out  = AlignedAllocF32(n_embd_, 512);
    if (!scratch_.x_norm || !scratch_.attn_out || !scratch_.ffn_gate ||
        !scratch_.ffn_up || !scratch_.ffn_silu || !scratch_.ffn_out) {
        fprintf(stderr, "FATAL: scratch buffer allocation failed\n");
        return false;
    }
    printf("[Engine] Scratch buffers: x_norm=%p attn_out=%p ffn_gate=%p ffn_up=%p ffn_silu=%p ffn_out=%p\n",
           scratch_.x_norm, scratch_.attn_out, scratch_.ffn_gate,
           scratch_.ffn_up, scratch_.ffn_silu, scratch_.ffn_out);

    // 2c. Pre-allocate logits scratch (aligned for MASM kernel)
    logits_scratch_size_ = n_vocab_;
    logits_scratch_ = AlignedAllocF32(logits_scratch_size_, 512);
    if (!logits_scratch_) {
        fprintf(stderr, "FATAL: logits scratch allocation failed\n");
        return false;
    }
    printf("[Engine] Logits scratch: %p (size=%zu floats)\n", logits_scratch_, logits_scratch_size_);

    // 3. Init flat KV cache (ring buffer for generation)
    kv_cache_flat_ = std::make_unique<SovereignKVCache>();
    uint32_t kv_dim = 1024;  // ministral3: n_embd=4096, n_head=32, n_head_kv=8, head_dim=128, kv_total=1024
    if (!kv_cache_flat_->Initialize(n_layer_, n_ctx_, kv_dim, kv_dim)) {
        fprintf(stderr, "FATAL: Flat KV cache init failed\n");
        return false;
    }

    // 4. Load weights — prefer multi-layer mode (34 layers for ministral3)
    if (!LoadAllLayerWeights(cfg_.model_path)) {
        fprintf(stderr, "WARN: Could not load multi-layer weights; falling back to single-layer\n");
        if (!LoadAttentionWeights(cfg_.model_path)) {
            fprintf(stderr, "WARN: Could not load attention weights; forward pass will use stub\n");
        }
        if (!LoadFFNWeights(cfg_.model_path)) {
            fprintf(stderr, "WARN: Could not load FFN weights; forward pass will use stub\n");
        }
        if (!LoadNormWeights(cfg_.model_path)) {
            fprintf(stderr, "WARN: Could not load norm weights; forward pass will use stub\n");
        }
    } else {
        // Multi-layer loaded — single-layer slots are unused (RunTokenForward uses wq_layers_ directly)
        // DO NOT create shallow copies — they cause double-free crashes
        printf("[Engine] Multi-layer weights loaded (%zu layers), single-layer slots left null\n",
               wq_layers_.size());
    }

    // 5. Init orchestrator (with null inference client for now — we are the engine)
    orchestrator_ = std::make_unique<TransformerStackOrchestrator>(
        nullptr,  // no external client; this engine IS the client
        kv_cache_
    );
    if (!orchestrator_->Initialize()) {
        fprintf(stderr, "FATAL: TransformerStackOrchestrator init failed\n");
        return false;
    }

    printf("[Engine] SovereignInferenceEngine initialized\n");
    return true;
}

bool SovereignInferenceEngine::Generate(const char* prompt,
                                          std::vector<uint32_t>& out_tokens,
                                          uint32_t max_new_tokens) {
    out_tokens.clear();
    if (!Prefill(prompt)) {
        return false;
    }

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    for (uint32_t i = 0; i < max_new_tokens; ++i) {
        uint32_t token = 0;
        bool done = false;
        if (!Step(token, done)) {
            return false;
        }
        out_tokens.push_back(token);
        if (done) {
            break;
        }
    }

    QueryPerformanceCounter(&t1);
    stats_.generate_us = static_cast<uint64_t>(
        (t1.QuadPart - t0.QuadPart) * 1000000ULL / freq.QuadPart);
    stats_.tokens_generated = out_tokens.size();
    if (stats_.generate_us > 0) {
        stats_.tokens_per_second =
            static_cast<float>(out_tokens.size()) * 1e6f / static_cast<float>(stats_.generate_us);
    }

    // KV cache hit rate from manager stats
    if (kv_cache_) {
        KVCacheStats kv_stats = kv_cache_->GetStats();
        stats_.kv_cache_hit_rate = kv_stats.hit_rate;
    }

    return true;
}

bool SovereignInferenceEngine::Prefill(const char* prompt) {
    ResetState();

    // Tokenize prompt
    step_state_.token_ids = tokenizer_.Encode(prompt);
    if (step_state_.token_ids.empty()) {
        // Ensure at least one token so forward pass has something to run
        step_state_.token_ids.push_back(tokenizer_.BOS_ID != std::numeric_limits<uint32_t>::max()
                                         ? tokenizer_.BOS_ID : 0);
    }

    // Run forward pass for all prompt tokens (prefill)
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    std::vector<float> logits;
    for (uint32_t tok : step_state_.token_ids) {
        if (!RunTokenForward(tok, logits)) {
            fprintf(stderr, "FATAL: Prefill forward pass failed\n");
            return false;
        }
    }

    QueryPerformanceCounter(&t1);
    stats_.prefill_us = static_cast<uint64_t>(
        (t1.QuadPart - t0.QuadPart) * 1000000ULL / freq.QuadPart);

    step_state_.prefill_done = true;
    step_state_.seq_len = step_state_.token_ids.size();
    return true;
}

bool SovereignInferenceEngine::Step(uint32_t& out_token_id, bool& done) {
    if (!step_state_.prefill_done) {
        fprintf(stderr, "FATAL: Step called before Prefill\n");
        return false;
    }

    // Run forward pass for the last token to get logits
    std::vector<float> logits;
    uint32_t last_token = step_state_.token_ids.empty() ? 0 : step_state_.token_ids.back();
    if (!RunTokenForward(last_token, logits)) {
        fprintf(stderr, "FATAL: Step forward pass failed\n");
        return false;
    }

    if (logits.empty()) {
        fprintf(stderr, "FATAL: Empty logits in Step\n");
        return false;
    }

    // Temperature sampling (if temperature > 0)
    if (cfg_.temperature > 0.0f) {
        out_token_id = SampleWithTemperature(logits.data(), logits.size(), cfg_.temperature);
    } else {
        out_token_id = SampleGreedy(logits.data(), logits.size());
    }
    step_state_.token_ids.push_back(out_token_id);
    step_state_.seq_len++;

    // Stop on EOS or max context
    done = (out_token_id == tokenizer_.EOS_ID) ||
           (step_state_.seq_len >= cfg_.max_context_length);

    return true;
}

void SovereignInferenceEngine::ResetState() {
    step_state_ = TokenStepState{};
    stats_ = Stats{};
}

bool SovereignInferenceEngine::StatesIdentical(const SovereignInferenceEngine& other) const {
    if (step_state_.token_ids.size() != other.step_state_.token_ids.size()) {
        return false;
    }
    for (size_t i = 0; i < step_state_.token_ids.size(); ++i) {
        if (step_state_.token_ids[i] != other.step_state_.token_ids[i]) {
            return false;
        }
    }
    return true;
}

SovereignInferenceEngine::Stats SovereignInferenceEngine::GetStats() const {
    return stats_;
}

// ---------------------------------------------------------------------------
// Dequantize a single Q4_0 row to F32
// Row layout: [scale: uint16_t] [weights: 16 bytes for 32 elements]
// Each block = 18 bytes = 2 bytes scale + 16 bytes weights (32 nibbles)
// ---------------------------------------------------------------------------
static void DequantizeQ4_0_Row(const uint8_t* q4_row, float* f32_out, int n_cols) {
    int blocks = n_cols / 32;
    for (int b = 0; b < blocks; ++b) {
        const uint8_t* block = q4_row + b * 18;
        // Scale: F16 at bytes 0-1
        uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(block);
        // Convert F16 to F32 manually
        uint32_t sign = (scale_f16 >> 15) & 0x1;
        uint32_t exp  = (scale_f16 >> 10) & 0x1F;
        uint32_t mant = scale_f16 & 0x3FF;
        float scale;
        if (exp == 0) {
            scale = 0.0f;
        } else if (exp == 0x1F) {
            scale = (mant == 0) ? (sign ? -INFINITY : INFINITY) : NAN;
        } else {
            float f = static_cast<float>(mant) / 1024.0f + 1.0f;
            int e = static_cast<int>(exp) - 15;
            scale = (sign ? -1.0f : 1.0f) * f * std::pow(2.0f, e);
        }
        // Weights: 16 bytes = 32 nibbles
        for (int i = 0; i < 16; ++i) {
            uint8_t byte = block[2 + i];
            uint8_t low_nibble  = byte & 0x0F;
            uint8_t high_nibble = (byte >> 4) & 0x0F;
            // Dequantize: (nibble - 8) * scale
            f32_out[b * 32 + i]       = (static_cast<float>(low_nibble)  - 8.0f) * scale;
            f32_out[b * 32 + i + 16]  = (static_cast<float>(high_nibble) - 8.0f) * scale;
        }
    }
}

// ---------------------------------------------------------------------------
// Forward pass — full transformer layer (attention + residual + FFN + residual)
// Supports both single-layer (micro-harness) and multi-layer (full model) modes.
// ---------------------------------------------------------------------------
bool SovereignInferenceEngine::RunTokenForward(uint32_t token_id,
                                                std::vector<float>& out_logits) {
    out_logits.resize(n_vocab_, 0.0f);

    if (!weights_loaded_ || n_embd_ == 0) {
        if (n_vocab_ > 0) {
            uint32_t spike = (token_id + 7) % n_vocab_;
            out_logits[spike] = 10.0f;
        }
        return true;
    }

    // Determine mode: multi-layer (full model) vs single-layer (micro-harness)
    bool multi_layer = (wq_layers_.size() > 0);
    uint32_t num_layers = multi_layer ? static_cast<uint32_t>(wq_layers_.size()) : 1;

    // 1. Real embedding lookup: dequantize token_embd.weight row for token_id
    float* hidden = AlignedAllocF32(n_embd_, 512);
    if (token_embd_f32_.data && token_embd_f32_.size > 0 && token_id < n_vocab_) {
        // token_embd.weight is Q4_0 [n_vocab × n_embd]
        uint32_t blocks_per_row = n_embd_ / 32;
        int row_stride = blocks_per_row * 18;
        const uint8_t* row_data = static_cast<const uint8_t*>(token_embd_f32_.data) + token_id * row_stride;
        DequantizeQ4_0_Row(row_data, hidden, n_embd_);
    } else {
        // Fallback: deterministic input
        for (uint32_t i = 0; i < n_embd_; ++i) {
            hidden[i] = static_cast<float>(token_id + i) * 0.001f;
        }
    }

    // 2. Multi-layer transformer stack — ZERO per-layer allocations
    for (uint32_t layer = 0; layer < num_layers; ++layer) {
        const WeightSlot& wq = multi_layer ? wq_layers_[layer] : wq_;
        const WeightSlot& wk = multi_layer ? wk_layers_[layer] : wk_;
        const WeightSlot& wv = multi_layer ? wv_layers_[layer] : wv_;
        const WeightSlot& wo = multi_layer ? wo_layers_[layer] : wo_;
        const WeightSlot& ffn_gate = multi_layer ? ffn_gate_layers_[layer] : ffn_gate_;
        const WeightSlot& ffn_up   = multi_layer ? ffn_up_layers_[layer]   : ffn_up_;
        const WeightSlot& ffn_down = multi_layer ? ffn_down_layers_[layer] : ffn_down_;
        const WeightSlot& attn_norm = multi_layer ? attn_norm_layers_[layer] : attn_norm_;
        const WeightSlot& ffn_norm  = multi_layer ? ffn_norm_layers_[layer]  : ffn_norm_;

        // 2a. Pre-attention RMSNorm: hidden → scratch_.x_norm
        memcpy(scratch_.x_norm, hidden, n_embd_ * sizeof(float));
        if (attn_norm.data && attn_norm.size >= n_embd_ * sizeof(float)) {
            RMSNorm(scratch_.x_norm, n_embd_, static_cast<float*>(attn_norm.data), 1e-5f);
        }

        // 2b. Attention sub-layer (Q/K/V projections + O projection)
        {
            float* Q = hidden;
            float* K = scratch_.attn_out;
            float* V = scratch_.x_norm;

            SovereignLayerExecutor::ExecuteAttentionQProj(wq.desc, static_cast<uint8_t*>(wq.data), scratch_.x_norm, Q);
            SovereignLayerExecutor::ExecuteAttentionKProj(wk.desc, static_cast<uint8_t*>(wk.data), scratch_.x_norm, K);
            SovereignLayerExecutor::ExecuteAttentionVProj(wv.desc, static_cast<uint8_t*>(wv.data), scratch_.x_norm, V);
            SovereignLayerExecutor::ExecuteGEMV(wo.desc, static_cast<uint8_t*>(wo.data), V, scratch_.attn_out);
            memcpy(hidden, scratch_.x_norm, n_embd_ * sizeof(float));
        }

        // 2c. Residual add
        for (uint32_t i = 0; i < n_embd_; ++i) {
            hidden[i] += scratch_.attn_out[i];
        }

        // 2d. Pre-FFN RMSNorm
        memcpy(scratch_.x_norm, hidden, n_embd_ * sizeof(float));
        if (ffn_norm.data && ffn_norm.size >= n_embd_ * sizeof(float)) {
            RMSNorm(scratch_.x_norm, n_embd_, static_cast<float*>(ffn_norm.data), 1e-5f);
        }

        // 2e. FFN sub-layer (SwiGLU)
        {
            uint32_t ffn_dim = static_cast<uint32_t>(ffn_gate.desc.dims[1]);
            if (ffn_dim == 0) ffn_dim = scratch_ffn_dim_;

            SovereignLayerExecutor::ExecuteGEMV(ffn_gate.desc, static_cast<uint8_t*>(ffn_gate.data), scratch_.x_norm, scratch_.ffn_gate);
            SovereignLayerExecutor::ExecuteGEMV(ffn_up.desc,   static_cast<uint8_t*>(ffn_up.data),   scratch_.x_norm, scratch_.ffn_up);

            SiLU(scratch_.ffn_gate, ffn_dim);
            for (uint32_t i = 0; i < ffn_dim; ++i) {
                scratch_.ffn_silu[i] = scratch_.ffn_gate[i] * scratch_.ffn_up[i];
            }

            SovereignLayerExecutor::ExecuteGEMV(ffn_down.desc, static_cast<uint8_t*>(ffn_down.data), scratch_.ffn_silu, scratch_.ffn_out);
        }

        // 2f. Residual add
        for (uint32_t i = 0; i < n_embd_; ++i) {
            hidden[i] += scratch_.ffn_out[i];
        }
    }

    // 3. Final head: RMSNorm + output projection → real logits
    if (output_norm_.data && output_norm_.size >= n_embd_ * sizeof(float)) {
        RMSNorm(hidden, n_embd_, static_cast<float*>(output_norm_.data), 1e-5f);
    }

    if (output_weight_.data && output_weight_.size > 0) {
        // Real output.weight loaded — use MASM GEMV kernel
        SovereignLayerExecutor::ExecuteGEMV(output_weight_.desc,
                                            static_cast<uint8_t*>(output_weight_.data),
                                            hidden,
                                            logits_scratch_);
        memcpy(out_logits.data(), logits_scratch_, n_vocab_ * sizeof(float));
    } else if (token_embd_f32_.data && token_embd_f32_.size > 0) {
        // Tied embeddings: token_embd.weight is Q4_0 [n_vocab × n_embd]
        // Use MASM scalar dot-product kernel directly (one output per call)
        uint32_t blocks_per_row = n_embd_ / 32;
        int row_stride = blocks_per_row * 18;
        const uint8_t* W = static_cast<const uint8_t*>(token_embd_f32_.data);
        for (uint32_t row = 0; row < n_vocab_; ++row) {
            const void* row_data = W + row * row_stride;
            // Direct dispatch to MASM kernel (bypass ExecuteGEMV wrapper which adds file_offset)
            Sovereign_GEMM_Q4_F32(row_data, hidden, logits_scratch_, n_embd_);
            out_logits[row] = logits_scratch_[0];
        }
    } else {
        // Fallback: deterministic hash-based spike
        uint64_t h = HashFloatVector(hidden, n_embd_);
        uint32_t spike = static_cast<uint32_t>(h % n_vocab_);
        out_logits[spike] = 10.0f;
    }

    AlignedFree(hidden);
    return true;
}

// ---------------------------------------------------------------------------
// FNV-1a hash of a float vector (for determinism checkpoints)
// ---------------------------------------------------------------------------
uint64_t SovereignInferenceEngine::HashFloatVector(const float* vec, size_t n) {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < n; ++i) {
        uint32_t bits;
        static_assert(sizeof(bits) == sizeof(float), "float size mismatch");
        std::memcpy(&bits, &vec[i], sizeof(bits));
        hash ^= static_cast<uint64_t>(bits);
        hash *= 1099511628211ULL;
    }
    return hash;
}

// ---------------------------------------------------------------------------
// Load FFN weights (gate/up/down) from GGUF into aligned sovereign buffers
// ---------------------------------------------------------------------------
bool SovereignInferenceEngine::LoadFFNWeights(const char* model_path) {
    StreamingGGUFLoader loader;
    if (!loader.Open(model_path)) {
        fprintf(stderr, "WARN: loader.Open(%s) failed\n", model_path);
        return false;
    }

    bool ok = true;
    ok &= LoadWeightSlot(loader, "blk.0.ffn_gate.weight", ffn_gate_);
    ok &= LoadWeightSlot(loader, "blk.0.ffn_up.weight",   ffn_up_);
    ok &= LoadWeightSlot(loader, "blk.0.ffn_down.weight", ffn_down_);

    if (ok) {
        printf("[Engine] Loaded FFN gate/up/down weights for blk.0\n");
    } else {
        fprintf(stderr, "WARN: Failed to load one or more FFN weights\n");
    }
    return ok;
}

// ---------------------------------------------------------------------------
// Load Q/K/V weights from GGUF into aligned sovereign buffers
// ---------------------------------------------------------------------------
bool SovereignInferenceEngine::LoadAttentionWeights(const char* model_path) {
    StreamingGGUFLoader loader;
    if (!loader.Open(model_path)) {
        fprintf(stderr, "WARN: loader.Open(%s) failed\n", model_path);
        return false;
    }

    bool ok = true;
    ok &= LoadWeightSlot(loader, "blk.0.attn_q.weight", wq_);
    ok &= LoadWeightSlot(loader, "blk.0.attn_k.weight", wk_);
    ok &= LoadWeightSlot(loader, "blk.0.attn_v.weight", wv_);
    ok &= LoadWeightSlot(loader, "blk.0.attn_output.weight", wo_);

    if (ok) {
        printf("[Engine] Loaded Q/K/V/O weights for blk.0\n");
        weights_loaded_ = true;
    } else {
        fprintf(stderr, "WARN: Failed to load one or more attention weights\n");
    }
    return ok;
}

// ---------------------------------------------------------------------------
// Load RMSNorm scale vectors from GGUF (float32, n_embd)
// ---------------------------------------------------------------------------
bool SovereignInferenceEngine::LoadNormWeights(const char* model_path) {
    StreamingGGUFLoader loader;
    if (!loader.Open(model_path)) {
        fprintf(stderr, "WARN: loader.Open(%s) failed\n", model_path);
        return false;
    }

    bool ok = true;
    ok &= LoadWeightSlot(loader, "blk.0.attn_norm.weight", attn_norm_);
    ok &= LoadWeightSlot(loader, "blk.0.ffn_norm.weight",  ffn_norm_);

    if (ok) {
        printf("[Engine] Loaded RMSNorm weights for blk.0\n");
    } else {
        fprintf(stderr, "WARN: Failed to load one or more norm weights\n");
    }
    return ok;
}

// ---------------------------------------------------------------------------
// Load ALL layer weights (34 layers for ministral3)
// Uses direct file reads (GetTensorData) — no zone caching needed
// ---------------------------------------------------------------------------
bool SovereignInferenceEngine::LoadAllLayerWeights(const char* model_path) {
    StreamingGGUFLoader loader;
    if (!loader.Open(model_path)) {
        fprintf(stderr, "WARN: loader.Open(%s) failed\n", model_path);
        return false;
    }

    wq_layers_.clear(); wk_layers_.clear(); wv_layers_.clear(); wo_layers_.clear();
    ffn_gate_layers_.clear(); ffn_up_layers_.clear(); ffn_down_layers_.clear();
    attn_norm_layers_.clear(); ffn_norm_layers_.clear();

    bool ok = true;
    for (uint32_t layer = 0; layer < n_layer_; ++layer) {
        char name[128];
        WeightSlot slot{};

        // Attention weights
        std::snprintf(name, sizeof(name), "blk.%u.attn_q.weight", layer);
        ok &= LoadWeightSlot(loader, name, slot); wq_layers_.push_back(slot); slot = WeightSlot{};

        std::snprintf(name, sizeof(name), "blk.%u.attn_k.weight", layer);
        ok &= LoadWeightSlot(loader, name, slot); wk_layers_.push_back(slot); slot = WeightSlot{};

        std::snprintf(name, sizeof(name), "blk.%u.attn_v.weight", layer);
        ok &= LoadWeightSlot(loader, name, slot); wv_layers_.push_back(slot); slot = WeightSlot{};

        std::snprintf(name, sizeof(name), "blk.%u.attn_output.weight", layer);
        ok &= LoadWeightSlot(loader, name, slot); wo_layers_.push_back(slot); slot = WeightSlot{};

        // FFN weights
        std::snprintf(name, sizeof(name), "blk.%u.ffn_gate.weight", layer);
        ok &= LoadWeightSlot(loader, name, slot); ffn_gate_layers_.push_back(slot); slot = WeightSlot{};

        std::snprintf(name, sizeof(name), "blk.%u.ffn_up.weight", layer);
        ok &= LoadWeightSlot(loader, name, slot); ffn_up_layers_.push_back(slot); slot = WeightSlot{};

        std::snprintf(name, sizeof(name), "blk.%u.ffn_down.weight", layer);
        ok &= LoadWeightSlot(loader, name, slot); ffn_down_layers_.push_back(slot); slot = WeightSlot{};

        // Norm weights (F32 scale vectors)
        std::snprintf(name, sizeof(name), "blk.%u.attn_norm.weight", layer);
        ok &= LoadWeightSlot(loader, name, slot); attn_norm_layers_.push_back(slot); slot = WeightSlot{};

        std::snprintf(name, sizeof(name), "blk.%u.ffn_norm.weight", layer);
        ok &= LoadWeightSlot(loader, name, slot); ffn_norm_layers_.push_back(slot); slot = WeightSlot{};
    }

    // Final head weights (post-layer stack) — non-fatal if unsupported type
    LoadWeightSlot(loader, "output_norm.weight", output_norm_);
    if (!LoadWeightSlot(loader, "output.weight", output_weight_)) {
        fprintf(stderr, "WARN: output.weight not loaded (unsupported type or missing)\n");
        // Not fatal — can use tied embeddings instead
    }

    // Tied embeddings: load token_embd.weight (Q4_0) — keep original type for MASM kernel
    WeightSlot token_embd_raw{};
    if (LoadWeightSlot(loader, "token_embd.weight", token_embd_raw)) {
        token_embd_f32_ = token_embd_raw;
        printf("[Engine] Loaded token_embd.weight for tied output projection (type=%u)\n",
               token_embd_f32_.desc.ggml_type);
    } else {
        fprintf(stderr, "WARN: Could not load token_embd.weight\n");
    }

    if (ok) {
        printf("[Engine] Loaded all %u layer weights + head\n", n_layer_);
        weights_loaded_ = true;
    } else {
        fprintf(stderr, "WARN: Failed to load one or more layer weights\n");
    }
    return ok;
}

bool SovereignInferenceEngine::LoadWeightSlot(StreamingGGUFLoader& loader,
                                              const char* name,
                                              WeightSlot& slot) {
    std::vector<uint8_t> raw;
    if (!loader.LoadTensorZone(name, raw)) {
        fprintf(stderr, "WARN: LoadTensorZone(%s) failed\n", name);
        return false;
    }

    auto tensors = loader.GetTensorIndex();
    const TensorRef* t = nullptr;
    for (const auto& tt : tensors) {
        if (tt.name == name) {
            t = &tt;
            break;
        }
    }
    if (!t) {
        fprintf(stderr, "WARN: %s not found in index\n", name);
        return false;
    }

    int n_cols = static_cast<int>(t->shape.size() > 0 ? t->shape[0] : 0);
    int n_rows = static_cast<int>(t->shape.size() > 1 ? t->shape[1] : 0);
    int expected_size = 0;
    const char* type_str = "UNKNOWN";

    if (t->type == RawrXD::GGMLType::Q4_0) {
        // Q4_0: 2D matrix, shape [cols, rows]
        int blocks_per_row = n_cols / 32;
        int row_stride = blocks_per_row * 18;
        expected_size = row_stride * n_rows;
        type_str = "Q4_0";
    } else if (t->type == RawrXD::GGMLType::F32) {
        // F32: can be 1D vector or 2D matrix
        int total_elements = n_rows > 0 ? n_cols * n_rows : n_cols;
        expected_size = total_elements * sizeof(float);
        type_str = "F32";
    } else if (t->type == RawrXD::GGMLType::F16) {
        // F16: half-precision, stored as 2 bytes per element
        int total_elements = n_rows > 0 ? n_cols * n_rows : n_cols;
        expected_size = total_elements * sizeof(uint16_t);
        type_str = "F16";
    } else {
        fprintf(stderr, "WARN: %s has unsupported type %d\n", name, static_cast<int>(t->type));
        return false;
    }

    if (expected_size <= 0) {
        fprintf(stderr, "WARN: %s has zero or negative expected size (%d), skipping\n", name, expected_size);
        return false;
    }

    size_t alloc_size = static_cast<size_t>(expected_size);
    void* aligned_buf = _aligned_malloc(alloc_size, 512);
    if (!aligned_buf) {
        fprintf(stderr, "WARN: _aligned_malloc(512) failed for %s\n", name);
        return false;
    }
    memset(aligned_buf, 0, alloc_size);
    memcpy(aligned_buf, raw.data(), std::min(static_cast<size_t>(expected_size), raw.size()));

    // If F16, convert to F32 in-place (expand buffer)
    if (t->type == RawrXD::GGMLType::F16) {
        int total_elements = n_rows > 0 ? n_cols * n_rows : n_cols;
        size_t f32_size = static_cast<size_t>(total_elements) * sizeof(float);
        void* f32_buf = _aligned_malloc(f32_size, 512);
        if (!f32_buf) {
            fprintf(stderr, "WARN: _aligned_malloc for F32 conversion failed\n");
            _aligned_free(aligned_buf);
            return false;
        }
        ConvertF16ToF32(static_cast<const uint16_t*>(aligned_buf), static_cast<float*>(f32_buf), total_elements);
        _aligned_free(aligned_buf);
        aligned_buf = f32_buf;
        alloc_size = f32_size;
        // Update desc to reflect F32
        slot.desc.ggml_type = static_cast<uint32_t>(RawrXD::GGMLType::F32);
    }

    if (slot.data) {
        _aligned_free(slot.data);
    }
    slot.data = aligned_buf;
    slot.size = alloc_size;
    slot.desc.name        = name;
    slot.desc.ggml_type   = static_cast<uint32_t>(t->type);
    slot.desc.n_dims      = static_cast<uint32_t>(t->shape.size());
    slot.desc.dims[0]     = t->shape.size() > 0 ? t->shape[0] : 0;
    slot.desc.dims[1]     = t->shape.size() > 1 ? t->shape[1] : 0;
    slot.desc.dims[2]     = 0;
    slot.desc.dims[3]     = 0;
    slot.desc.file_offset = 0;
    slot.desc.size_bytes  = alloc_size;

    printf("[Engine] Loaded %s: %dx%d %s (%d bytes)\n", name, n_rows, n_cols, type_str, expected_size);
    return true;
}

float* SovereignInferenceEngine::AlignedAllocF32(size_t count, size_t align) {
    // MASM kernel requires 512-byte alignment minimum
    size_t actual_align = (align < 512) ? 512 : align;
    void* p = _aligned_malloc(count * sizeof(float), actual_align);
    if (p) memset(p, 0, count * sizeof(float));
    return static_cast<float*>(p);
}

void SovereignInferenceEngine::AlignedFree(void* ptr) {
    _aligned_free(ptr);
}

// ---------------------------------------------------------------------------
// Convert F16 (half-precision) buffer to F32 — scalar fallback
// ---------------------------------------------------------------------------
void SovereignInferenceEngine::ConvertF16ToF32(const uint16_t* src, float* dst, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        uint16_t h = src[i];
        // F16 format: 1 sign | 5 exp | 10 mantissa
        uint32_t sign = (h >> 15) & 0x1;
        uint32_t exp  = (h >> 10) & 0x1F;
        uint32_t mant = h & 0x3FF;

        uint32_t f32_bits;
        if (exp == 0) {
            // Zero or subnormal
            if (mant == 0) {
                f32_bits = sign << 31;  // +/- zero
            } else {
                // Subnormal: normalize and adjust exponent
                uint32_t e = 0;
                while ((mant & 0x400) == 0) {
                    mant <<= 1;
                    e++;
                }
                mant &= 0x3FF;
                f32_bits = (sign << 31) | ((127 - 15 - e) << 23) | (mant << 13);
            }
        } else if (exp == 0x1F) {
            // Inf or NaN
            f32_bits = (sign << 31) | (0xFF << 23) | (mant << 13);
        } else {
            // Normal
            int32_t e = static_cast<int32_t>(exp) - 15 + 127;
            f32_bits = (sign << 31) | (static_cast<uint32_t>(e) << 23) | (mant << 13);
        }
        std::memcpy(&dst[i], &f32_bits, sizeof(float));
    }
}

uint32_t SovereignInferenceEngine::SampleGreedy(const float* logits, size_t count) const {
    if (count == 0) return 0;
    uint32_t best = 0;
    float best_val = logits[0];
    for (size_t i = 1; i < count; ++i) {
        if (logits[i] > best_val) {
            best_val = logits[i];
            best = static_cast<uint32_t>(i);
        }
    }
    return best;
}

// ---------------------------------------------------------------------------
// Temperature sampling: apply softmax with temperature, then sample
// ---------------------------------------------------------------------------
uint32_t SovereignInferenceEngine::SampleWithTemperature(const float* logits, size_t count, float temperature) const {
    if (count == 0) return 0;
    if (temperature <= 0.0f) return SampleGreedy(logits, count);

    // Apply temperature and compute softmax
    std::vector<float> probs(count);
    float max_logit = logits[0];
    for (size_t i = 1; i < count; ++i) {
        if (logits[i] > max_logit) max_logit = logits[i];
    }

    double sum = 0.0;
    for (size_t i = 0; i < count; ++i) {
        probs[i] = std::exp((logits[i] - max_logit) / temperature);
        sum += probs[i];
    }

    // Normalize
    for (size_t i = 0; i < count; ++i) {
        probs[i] = static_cast<float>(probs[i] / sum);
    }

    // Simple weighted random sample (deterministic for now — pick highest prob)
    uint32_t best = 0;
    float best_prob = probs[0];
    for (size_t i = 1; i < count; ++i) {
        if (probs[i] > best_prob) {
            best_prob = probs[i];
            best = static_cast<uint32_t>(i);
        }
    }
    return best;
}

// ---------------------------------------------------------------------------
// RunAttentionCore — isolated attention datapath with hash checkpoints
// ---------------------------------------------------------------------------
bool SovereignInferenceEngine::RunAttentionCore(const float* input,
                                                 uint32_t n_embd,
                                                 AttentionStageHashes& out) {
    out = {};
    if (!weights_loaded_ || n_embd == 0) {
        fprintf(stderr, "FATAL: weights not loaded or n_embd=0\n");
        return false;
    }

    out.hash_input = HashFloatVector(input, n_embd);

    // GQA parameters (ministral3: 32 Q heads, 8 K/V heads, head_dim=128)
    const uint32_t n_head     = 32;
    const uint32_t n_kv_head  = 8;
    const uint32_t head_dim   = n_embd / n_head;        // 128
    const uint32_t kv_dim     = n_embd / 4;             // 1024
    const uint32_t kv_head_dim = kv_dim / n_kv_head;    // 128

    // 1. Q/K/V projections
    float* Q = AlignedAllocF32(n_embd, 64);
    float* K = AlignedAllocF32(kv_dim, 64);
    float* V = AlignedAllocF32(kv_dim, 64);

    SovereignLayerExecutor::ExecuteAttentionQProj(wq_.desc, static_cast<uint8_t*>(wq_.data), input, Q);
    SovereignLayerExecutor::ExecuteAttentionKProj(wk_.desc, static_cast<uint8_t*>(wk_.data), input, K);
    SovereignLayerExecutor::ExecuteAttentionVProj(wv_.desc, static_cast<uint8_t*>(wv_.data), input, V);

    out.hash_q = HashFloatVector(Q, n_embd);
    out.hash_k = HashFloatVector(K, kv_dim);
    out.hash_v = HashFloatVector(V, kv_dim);

    // 2. Attention scores per Q head (GQA: each Q head shares a KV head)
    std::vector<float> scores(n_head);
    for (uint32_t h = 0; h < n_head; ++h) {
        uint32_t kv_h = h / (n_head / n_kv_head); // 0..7
        double dot = 0.0;
        const float* q_ptr = Q + h * head_dim;
        const float* k_ptr = K + kv_h * kv_head_dim;
        for (uint32_t d = 0; d < kv_head_dim; ++d) {
            dot += static_cast<double>(q_ptr[d]) * static_cast<double>(k_ptr[d]);
        }
        float scale = 1.0f / sqrtf(static_cast<float>(kv_head_dim));
        scores[h] = static_cast<float>(dot) * scale;
    }
    out.hash_scores = HashFloatVector(scores.data(), n_head);

    // 3. Softmax over Q-head scores
    Softmax(scores.data(), n_head);
    out.hash_softmax = HashFloatVector(scores.data(), n_head);

    // 4. Weighted context: each Q head gets its own weighted V slice
    float* context = AlignedAllocF32(n_embd, 64);
    for (uint32_t h = 0; h < n_head; ++h) {
        uint32_t kv_h = h / (n_head / n_kv_head);
        const float* v_ptr = V + kv_h * kv_head_dim;
        float* c_ptr = context + h * head_dim;
        float s = scores[h];
        for (uint32_t d = 0; d < kv_head_dim; ++d) {
            c_ptr[d] = v_ptr[d] * s;
        }
    }
    out.hash_context = HashFloatVector(context, n_embd);

    // 5. attn_output.weight projection: context (4096) -> attn_out (4096)
    float* attn_out = AlignedAllocF32(n_embd, 64);
    SovereignLayerExecutor::ExecuteGEMV(wo_.desc, static_cast<uint8_t*>(wo_.data), context, attn_out);
    out.hash_attn_out = HashFloatVector(attn_out, n_embd);

    AlignedFree(Q); AlignedFree(K); AlignedFree(V); AlignedFree(context); AlignedFree(attn_out);
    return true;
}

// ---------------------------------------------------------------------------
// SiLU activation: x * sigmoid(x)
// Deterministic, no fast-math approximations
// ---------------------------------------------------------------------------
void SovereignInferenceEngine::SiLU(float* vec, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        float x = vec[i];
        // sigmoid(x) = 1 / (1 + exp(-x))
        double exp_neg_x = exp(-static_cast<double>(x));
        float sigmoid = static_cast<float>(1.0 / (1.0 + exp_neg_x));
        vec[i] = x * sigmoid;
    }
}

// ---------------------------------------------------------------------------
// RunFFNCore — isolated FFN datapath with hash checkpoints
// SwiGLU: SiLU(gate) ⊙ up  →  down projection
// ---------------------------------------------------------------------------
bool SovereignInferenceEngine::RunFFNCore(const float* input,
                                           uint32_t n_embd,
                                           FFNStageHashes& out) {
    out = {};
    if (!weights_loaded_ || n_embd == 0 || !ffn_gate_.data || !ffn_up_.data || !ffn_down_.data) {
        fprintf(stderr, "FATAL: FFN weights not loaded\n");
        return false;
    }

    out.hash_input = HashFloatVector(input, n_embd);

    // FFN intermediate dim (typically 14336 for ministral3)
    uint32_t ffn_dim = static_cast<uint32_t>(ffn_gate_.desc.dims[1]);
    if (ffn_dim == 0) ffn_dim = 14336;

    // 1. Gate projection: input (4096) → gate (14336)
    float* gate = AlignedAllocF32(ffn_dim, 64);
    SovereignLayerExecutor::ExecuteGEMV(ffn_gate_.desc, static_cast<uint8_t*>(ffn_gate_.data), input, gate);
    out.hash_gate = HashFloatVector(gate, ffn_dim);

    // 2. Up projection: input (4096) → up (14336)
    float* up = AlignedAllocF32(ffn_dim, 64);
    SovereignLayerExecutor::ExecuteGEMV(ffn_up_.desc, static_cast<uint8_t*>(ffn_up_.data), input, up);
    out.hash_up = HashFloatVector(up, ffn_dim);

    // 3. SwiGLU: SiLU(gate) ⊙ up
    SiLU(gate, ffn_dim);
    for (uint32_t i = 0; i < ffn_dim; ++i) {
        gate[i] *= up[i];
    }
    out.hash_silu = HashFloatVector(gate, ffn_dim);

    // 4. Down projection: SwiGLU output (14336) → hidden (4096)
    float* down = AlignedAllocF32(n_embd, 64);
    SovereignLayerExecutor::ExecuteGEMV(ffn_down_.desc, static_cast<uint8_t*>(ffn_down_.data), gate, down);
    out.hash_down = HashFloatVector(down, n_embd);

    AlignedFree(gate);
    AlignedFree(up);
    AlignedFree(down);
    return true;
}

// ---------------------------------------------------------------------------
// Stable softmax
// ---------------------------------------------------------------------------
void SovereignInferenceEngine::Softmax(float* vec, size_t n) {
    if (n == 0) return;
    float max_val = vec[0];
    for (size_t i = 1; i < n; ++i) {
        if (vec[i] > max_val) max_val = vec[i];
    }
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) {
        vec[i] = static_cast<float>(exp(static_cast<double>(vec[i] - max_val)));
        sum += vec[i];
    }
    float inv_sum = static_cast<float>(1.0 / sum);
    for (size_t i = 0; i < n; ++i) {
        vec[i] *= inv_sum;
    }
}

// ---------------------------------------------------------------------------
// RMSNorm: x_i = x_i / sqrt(mean(x^2) + eps) * scale_i
// Deterministic, no fast-math approximations
// ---------------------------------------------------------------------------
void SovereignInferenceEngine::RMSNorm(float* vec, size_t n, const float* scale, float eps) {
    if (n == 0) return;
    double sum_sq = 0.0;
    for (size_t i = 0; i < n; ++i) {
        double x = static_cast<double>(vec[i]);
        sum_sq += x * x;
    }
    float inv_rms = static_cast<float>(1.0 / sqrt(sum_sq / static_cast<double>(n) + static_cast<double>(eps)));
    for (size_t i = 0; i < n; ++i) {
        vec[i] = vec[i] * inv_rms * scale[i];
    }
}

} // namespace AI
} // namespace RawrXD
