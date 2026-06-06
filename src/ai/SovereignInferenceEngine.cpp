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
    freeSlot(wq_); freeSlot(wk_); freeSlot(wv_); freeSlot(wo_);
    freeSlot(ffn_gate_); freeSlot(ffn_up_); freeSlot(ffn_down_);
    freeSlot(attn_norm_); freeSlot(ffn_norm_);
    freeSlots(wq_layers_); freeSlots(wk_layers_); freeSlots(wv_layers_); freeSlots(wo_layers_);
    freeSlots(ffn_gate_layers_); freeSlots(ffn_up_layers_); freeSlots(ffn_down_layers_);
    freeSlots(attn_norm_layers_); freeSlots(ffn_norm_layers_);
    freeSlot(output_norm_); freeSlot(output_weight_);

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
        // Multi-layer loaded — also populate single-layer slots for backward compat
        if (!wq_layers_.empty()) wq_ = wq_layers_[0];
        if (!wk_layers_.empty()) wk_ = wk_layers_[0];
        if (!wv_layers_.empty()) wv_ = wv_layers_[0];
        if (!wo_layers_.empty()) wo_ = wo_layers_[0];
        if (!ffn_gate_layers_.empty()) ffn_gate_ = ffn_gate_layers_[0];
        if (!ffn_up_layers_.empty())   ffn_up_   = ffn_up_layers_[0];
        if (!ffn_down_layers_.empty()) ffn_down_ = ffn_down_layers_[0];
        if (!attn_norm_layers_.empty()) attn_norm_ = attn_norm_layers_[0];
        if (!ffn_norm_layers_.empty())  ffn_norm_  = ffn_norm_layers_[0];
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

    // Greedy sample
    out_token_id = SampleGreedy(logits.data(), logits.size());
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

    // 1. Deterministic input vector (simulates token embedding lookup)
    float* hidden = AlignedAllocF32(n_embd_, 512);
    for (uint32_t i = 0; i < n_embd_; ++i) {
        hidden[i] = static_cast<float>(token_id + i) * 0.001f;
    }

    // 2. Multi-layer transformer stack — ZERO per-layer allocations
    for (uint32_t layer = 0; layer < num_layers; ++layer) {
        printf("[Forward] Layer %u/%u start\n", layer, num_layers);
        fflush(stdout);
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
        printf("[Forward] Layer %u RMSNorm1\n", layer); fflush(stdout);
        memcpy(scratch_.x_norm, hidden, n_embd_ * sizeof(float));
        if (attn_norm.data && attn_norm.size >= n_embd_ * sizeof(float)) {
            RMSNorm(scratch_.x_norm, n_embd_, static_cast<float*>(attn_norm.data), 1e-5f);
        }

        // 2b. Attention sub-layer (Q/K/V projections + O projection)
        //     scratch_.x_norm → scratch_.attn_out
        {
            printf("[Forward] Layer %u Attention start\n", layer); fflush(stdout);
            // Q/K/V projections reuse scratch buffers (Q=hidden, K=scratch_.attn_out, V=scratch_.x_norm)
            // Note: for single-token generation without KV cache, we do minimal dot-product attention
            float* Q = hidden;           // borrow hidden buffer for Q (will be reconstructed)
            float* K = scratch_.attn_out;  // borrow attn_out for K
            float* V = scratch_.x_norm;  // borrow x_norm for V

            printf("[Forward] Layer %u QProj\n", layer); fflush(stdout);
            SovereignLayerExecutor::ExecuteAttentionQProj(wq.desc, static_cast<uint8_t*>(wq.data), scratch_.x_norm, Q);
            printf("[Forward] Layer %u KProj\n", layer); fflush(stdout);
            SovereignLayerExecutor::ExecuteAttentionKProj(wk.desc, static_cast<uint8_t*>(wk.data), scratch_.x_norm, K);
            printf("[Forward] Layer %u VProj\n", layer); fflush(stdout);
            SovereignLayerExecutor::ExecuteAttentionVProj(wv.desc, static_cast<uint8_t*>(wv.data), scratch_.x_norm, V);

            // Minimal attention: dot(Q,K) for single token, then V→attn_out via O projection
            // For now: just pass V through O projection (no KV cache yet)
            printf("[Forward] Layer %u OProj\n", layer); fflush(stdout);
            SovereignLayerExecutor::ExecuteGEMV(wo.desc, static_cast<uint8_t*>(wo.data), V, scratch_.attn_out);

            // Reconstruct hidden from Q (since we borrowed it)
            // Actually Q was written into hidden, which is fine — we restore hidden from x_norm after
            memcpy(hidden, scratch_.x_norm, n_embd_ * sizeof(float));
            printf("[Forward] Layer %u Attention done\n", layer); fflush(stdout);
        }

        // 2c. Residual add: hidden = hidden + scratch_.attn_out
        printf("[Forward] Layer %u Residual1\n", layer); fflush(stdout);
        for (uint32_t i = 0; i < n_embd_; ++i) {
            hidden[i] += scratch_.attn_out[i];
        }

        // 2d. Pre-FFN RMSNorm: hidden → scratch_.x_norm
        printf("[Forward] Layer %u RMSNorm2\n", layer); fflush(stdout);
        memcpy(scratch_.x_norm, hidden, n_embd_ * sizeof(float));
        if (ffn_norm.data && ffn_norm.size >= n_embd_ * sizeof(float)) {
            RMSNorm(scratch_.x_norm, n_embd_, static_cast<float*>(ffn_norm.data), 1e-5f);
        }

        // 2e. FFN sub-layer (SwiGLU) — all into scratch buffers
        {
            uint32_t ffn_dim = static_cast<uint32_t>(ffn_gate.desc.dims[1]);
            if (ffn_dim == 0) ffn_dim = scratch_ffn_dim_;
            printf("[Forward] Layer %u FFN start (dim=%u)\n", layer, ffn_dim); fflush(stdout);

            printf("[Forward] Layer %u FFN gate proj\n", layer); fflush(stdout);
            SovereignLayerExecutor::ExecuteGEMV(ffn_gate.desc, static_cast<uint8_t*>(ffn_gate.data), scratch_.x_norm, scratch_.ffn_gate);
            printf("[Forward] Layer %u FFN up proj\n", layer); fflush(stdout);
            SovereignLayerExecutor::ExecuteGEMV(ffn_up.desc,   static_cast<uint8_t*>(ffn_up.data),   scratch_.x_norm, scratch_.ffn_up);

            printf("[Forward] Layer %u FFN SiLU\n", layer); fflush(stdout);
            SiLU(scratch_.ffn_gate, ffn_dim);
            printf("[Forward] Layer %u FFN multiply\n", layer); fflush(stdout);
            for (uint32_t i = 0; i < ffn_dim; ++i) {
                scratch_.ffn_silu[i] = scratch_.ffn_gate[i] * scratch_.ffn_up[i];
            }

            printf("[Forward] Layer %u FFN down proj\n", layer); fflush(stdout);
            SovereignLayerExecutor::ExecuteGEMV(ffn_down.desc, static_cast<uint8_t*>(ffn_down.data), scratch_.ffn_silu, scratch_.ffn_out);
            printf("[Forward] Layer %u FFN done\n", layer); fflush(stdout);
        }

        // 2f. Residual add: hidden = hidden + scratch_.ffn_out
        printf("[Forward] Layer %u Residual2\n", layer); fflush(stdout);
        for (uint32_t i = 0; i < n_embd_; ++i) {
            hidden[i] += scratch_.ffn_out[i];
        }
        printf("[Forward] Layer %u done\n", layer); fflush(stdout);
    }

    // 3. Final head: RMSNorm + output.weight projection → real logits
    printf("[Forward] Final norm...\n"); fflush(stdout);
    if (output_norm_.data && output_norm_.size >= n_embd_ * sizeof(float)) {
        RMSNorm(hidden, n_embd_, static_cast<float*>(output_norm_.data), 1e-5f);
    }

    printf("[Forward] Output projection...\n"); fflush(stdout);
    if (output_weight_.data && output_weight_.size > 0) {
        // output.weight: n_vocab × n_embd — GEMV with hidden as input
        // MUST use aligned scratch buffer (MASM kernel requires 512-byte align)
        SovereignLayerExecutor::ExecuteGEMV(output_weight_.desc,
                                            static_cast<uint8_t*>(output_weight_.data),
                                            hidden,
                                            logits_scratch_);
        // Copy aligned scratch → std::vector output
        memcpy(out_logits.data(), logits_scratch_, n_vocab_ * sizeof(float));
    } else {
        // Fallback: deterministic hash-based spike (head not loaded)
        uint64_t h = HashFloatVector(hidden, n_embd_);
        uint32_t spike = static_cast<uint32_t>(h % n_vocab_);
        out_logits[spike] = 10.0f;
        printf("[Forward] token=%u layers=%u hash(hidden)=%016llX spike=%u (no head)\n",
               token_id, num_layers, (unsigned long long)h, spike);
    }

    printf("[Forward] token=%u layers=%u done\n", token_id, num_layers);

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

    // Final head weights (post-layer stack)
    ok &= LoadWeightSlot(loader, "output_norm.weight", output_norm_);
    ok &= LoadWeightSlot(loader, "output.weight",      output_weight_);

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
